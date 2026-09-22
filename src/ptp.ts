/**
 * Sender-side PTP: the clock an AirPlay 2 receiver slaves to.
 *
 * Ported from cliairplay's `ap2_ptp.c`. Three things in here are not optional
 * and each one fails silently when wrong — the receiver keeps answering RTSP
 * and simply never renders:
 *
 *  - **majorSdoId = 1** in the first header byte. Receivers run the gPTP
 *    (802.1AS) profile and discard plain-1588 framing outright, so `0x10 | type`
 *    rather than the type alone.
 *  - **The announce dataset must out-rank the receiver's own clock.** iOS
 *    announces priority1 128 / clockClass 6 / accuracy 0x21 / variance 0x436A
 *    with timeSource GPS; a HomePod announces 248/248, so those values are what
 *    win the election and make our timeline the session's.
 *  - **Timing is unicast to the peers**, not multicast: that is what iOS does,
 *    and a receiver only follows a master it was handed in `timingPeerList`.
 *
 * Timestamps come from `CLOCK_REALTIME` (the same base the reference uses) with
 * userspace software timestamping, so accuracy is tens of microseconds — which
 * is the same class the C implementation achieves, since it timestamps in
 * userspace too.
 */

import { createSocket, type Socket } from 'node:dgram';

const EVENT_PORT = 319; // Sync, Delay_Req
const GENERAL_PORT = 320; // Announce, Follow_Up, Delay_Resp
const HDR_LEN = 34;
const VERSION = 2;
const DOMAIN = 0;

const MSG_SYNC = 0x0;
const MSG_DELAY_REQ = 0x1;
const MSG_PDELAY_REQ = 0x2;
const MSG_PDELAY_RESP = 0x3;
const MSG_FOLLOW_UP = 0x8;
const MSG_DELAY_RESP = 0x9;
const MSG_PDELAY_RESP_FUP = 0xa;
const MSG_ANNOUNCE = 0xb;
const MSG_SIGNALING = 0xc;

const FLAG_TWO_STEP = 0x0200;
const FLAG_UNICAST = 0x0400;
const FLAG_PTP_TIMESCALE = 0x0008;

// The grandmaster dataset iOS announces; it must out-rank the receiver's own.
const PRIORITY1 = 128;
const PRIORITY2 = 128;
const CLOCK_CLASS = 6; // GPS-locked
const CLOCK_ACCURACY = 0x21; // 100 ns
const LOG_VARIANCE = 0x436a;
const TIME_SOURCE = 0x20; // GPS

const ANNOUNCE_INTERVAL_MS = 1000;
const LOG_ANNOUNCE_INTERVAL = 0;
const SYNC_INTERVAL_MS = 125;
const LOG_SYNC_INTERVAL = -3;

/** Nanosecond-resolution realtime clock: Date.now() stepped by hrtime. */
class RealtimeClock {
  private readonly baseNs: bigint;
  private readonly baseHr: bigint;

  constructor() {
    this.baseNs = BigInt(Date.now()) * 1_000_000n;
    this.baseHr = process.hrtime.bigint();
  }

  public now(): bigint {
    return this.baseNs + (process.hrtime.bigint() - this.baseHr);
  }
}

function writeTimestamp(buf: Buffer, offset: number, ns: bigint): void {
  const seconds = ns / 1_000_000_000n;
  const nanos = Number(ns % 1_000_000_000n);
  buf.writeUIntBE(Number(seconds & 0xffff_ffff_ffffn), offset, 6);
  buf.writeUInt32BE(nanos, offset + 6);
}

export interface PtpEngineOptions {
  /** Our 64-bit clock identity — the same value the session SETUP advertises. */
  clockId: bigint;
  /** Receivers to unicast timing to; add and remove them as sessions come and go. */
  peers: string[];
  /** Local address to bind; empty binds all interfaces. */
  bindAddress?: string;
  onLog?: (message: string) => void;
}

/**
 * A PTP grandmaster serving one or more AirPlay receivers.
 *
 * Binding 319/320 needs privilege (or `CAP_NET_BIND_SERVICE`); {@link start}
 * rejects when it cannot, and the caller must then fall back to NTP timing —
 * on an Apple receiver that means silence, so the failure has to surface.
 */
export class PtpEngine {
  private eventSocket: Socket | null = null;
  private generalSocket: Socket | null = null;
  private announceTimer: NodeJS.Timeout | null = null;
  private syncTimer: NodeJS.Timeout | null = null;
  private signalingTimer: NodeJS.Timeout | null = null;
  /**
   * sequenceId is 16 bits wide, so these wrap rather than grow: a sync every
   * 125 ms runs out of room after a little over two hours of playing.
   */
  private announceSeq = 0;
  private syncSeq = 0;
  private signalingSeq = 0;
  private readonly clock = new RealtimeClock();
  /** Delay_Req exchanges answered — the receiver probing us is the sign of life. */
  public exchanges = 0;

  private readonly peers = new Set<string>();

  constructor(private readonly options: PtpEngineOptions) {
    for (const peer of options.peers) {
      this.peers.add(peer);
    }
  }

  public get clockId(): bigint {
    return this.options.clockId;
  }

  /**
   * Serve timing to one more receiver. Only one process on a host can bind
   * 319/320, so a single engine carries every session — sessions add and drop
   * themselves here rather than each running an engine of their own.
   */
  public addPeer(address: string): void {
    this.peers.add(address);
  }

  public removePeer(address: string): void {
    this.peers.delete(address);
  }

  public get peerCount(): number {
    return this.peers.size;
  }

  /** Time on the session timeline, in nanoseconds. */
  public now(): bigint {
    return this.clock.now();
  }

  public async start(): Promise<void> {
    this.eventSocket = await this.bind(EVENT_PORT, (msg, rinfo) => this.onEvent(msg, rinfo));
    this.generalSocket = await this.bind(GENERAL_PORT, (msg, rinfo) => this.onGeneral(msg, rinfo));

    this.sendAnnounce();
    this.sendSync();
    this.sendSignaling();
    this.announceTimer = setInterval(() => this.tick(() => this.sendAnnounce()), ANNOUNCE_INTERVAL_MS);
    this.syncTimer = setInterval(() => this.tick(() => this.sendSync()), SYNC_INTERVAL_MS);
    this.signalingTimer = setInterval(() => this.tick(() => this.sendSignaling()), ANNOUNCE_INTERVAL_MS);
  }

  public stop(): void {
    for (const timer of [this.announceTimer, this.syncTimer, this.signalingTimer]) {
      if (timer) {
        clearInterval(timer);
      }
    }
    this.announceTimer = this.syncTimer = this.signalingTimer = null;
    this.eventSocket?.close();
    this.generalSocket?.close();
    this.eventSocket = this.generalSocket = null;
  }

  private async bind(port: number, handler: (msg: Buffer, rinfo: { address: string; port: number }) => void): Promise<Socket> {
    const socket = createSocket({ type: 'udp4', reuseAddr: true });
    socket.on('message', handler);
    socket.on('error', (err) => this.log(`socket error on ${port}: ${err.message}`));
    await new Promise<void>((resolve, reject) => {
      socket.once('error', reject);
      socket.bind(port, this.options.bindAddress, () => {
        socket.removeListener('error', reject);
        resolve();
      });
    });
    return socket;
  }

  /**
   * A timer callback throws into nobody's hands: without this the process takes
   * the exception. A missed timing packet costs a beat, not the server.
   */
  private tick(send: () => void): void {
    try {
      send();
    } catch (err) {
      this.log(`ptp send failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  private log(message: string): void {
    this.options.onLog?.(message);
  }

  /** The common 34-byte PTPv2 header, in the gPTP dialect receivers require. */
  private header(type: number, length: number, flags: number, seq: number, control: number, logInterval: number): Buffer {
    const buf = Buffer.alloc(length);
    buf[0] = 0x10 | (type & 0x0f); // majorSdoId 1 — without this we are invisible
    buf[1] = VERSION & 0x0f;
    buf.writeUInt16BE(length, 2);
    buf[4] = DOMAIN;
    buf.writeUInt16BE(flags, 6);
    buf.writeBigUInt64BE(this.options.clockId, 20); // sourcePortIdentity.clockIdentity
    buf[28] = 0x80;
    buf[29] = 0x05; // portNumber, as iOS
    buf.writeUInt16BE(seq, 30);
    buf[32] = control;
    buf.writeInt8(logInterval, 33);
    return buf;
  }

  private send(socket: Socket | null, port: number, buf: Buffer, only?: string): void {
    if (!socket) {
      return;
    }
    const targets = only ? [only] : [...this.peers];
    for (const target of targets) {
      socket.send(buf, port, target, (err) => {
        if (err) {
          this.log(`send to ${target}:${port} failed: ${err.message}`);
        }
      });
    }
  }

  private sendAnnounce(): void {
    const length = HDR_LEN + 30 + 12;
    const buf = this.header(MSG_ANNOUNCE, length, FLAG_UNICAST | FLAG_PTP_TIMESCALE, this.announceSeq, 0x00, LOG_ANNOUNCE_INTERVAL);
    this.announceSeq = (this.announceSeq + 1) & 0xffff;
    const body = HDR_LEN;
    // originTimestamp (10) and currentUtcOffset (2) stay zero, as iOS sends them.
    buf[body + 13] = PRIORITY1;
    buf[body + 14] = CLOCK_CLASS;
    buf[body + 15] = CLOCK_ACCURACY;
    buf.writeUInt16BE(LOG_VARIANCE, body + 16);
    buf[body + 18] = PRIORITY2;
    buf.writeBigUInt64BE(this.options.clockId, body + 19); // grandmasterIdentity
    buf.writeUInt16BE(0, body + 27); // stepsRemoved
    buf[body + 29] = TIME_SOURCE;
    // PATH_TRACE TLV: type 0x0008, length 8, value = the grandmaster clock id.
    buf.writeUInt16BE(0x0008, body + 30);
    buf.writeUInt16BE(0x0008, body + 32);
    buf.writeBigUInt64BE(this.options.clockId, body + 34);

    this.send(this.generalSocket, GENERAL_PORT, buf);
  }

  /** Two-step master: Sync with an empty timestamp, then Follow_Up with the real one. */
  private sendSync(): void {
    const seq = this.syncSeq;
    this.syncSeq = (this.syncSeq + 1) & 0xffff;
    const sync = this.header(MSG_SYNC, HDR_LEN + 10, FLAG_UNICAST | FLAG_PTP_TIMESCALE | FLAG_TWO_STEP, seq, 0x00, LOG_SYNC_INTERVAL);
    this.send(this.eventSocket, EVENT_PORT, sync);
    const egress = this.clock.now(); // best-effort software egress time

    const length = HDR_LEN + 10 + 32 + 20;
    const followUp = this.header(MSG_FOLLOW_UP, length, FLAG_UNICAST | FLAG_PTP_TIMESCALE, seq, 0x00, LOG_SYNC_INTERVAL);
    writeTimestamp(followUp, HDR_LEN, egress); // preciseOriginTimestamp

    // 802.1AS Follow_Up information TLV: ORG_EXT, len 28, OUI 00:80:C2 subtype 1.
    let tlv = HDR_LEN + 10;
    followUp.writeUInt16BE(0x0003, tlv);
    followUp.writeUInt16BE(0x001c, tlv + 2);
    followUp[tlv + 4] = 0x00;
    followUp[tlv + 5] = 0x80;
    followUp[tlv + 6] = 0xc2;
    followUp[tlv + 9] = 0x01;
    // Apple clock-id TLV: ORG_EXT, len 16, OUI 00:0D:93 subtype 4.
    tlv += 32;
    followUp.writeUInt16BE(0x0003, tlv);
    followUp.writeUInt16BE(0x0010, tlv + 2);
    followUp[tlv + 4] = 0x00;
    followUp[tlv + 5] = 0x0d;
    followUp[tlv + 6] = 0x93;
    followUp[tlv + 9] = 0x04;
    followUp.writeBigUInt64BE(this.options.clockId, tlv + 10);

    this.send(this.generalSocket, GENERAL_PORT, followUp);
  }

  /** The once-a-second Signaling iOS sends its timing peers: two Apple TLVs. */
  private sendSignaling(): void {
    const length = HDR_LEN + 10 + 26 + 36;
    const buf = this.header(MSG_SIGNALING, length, FLAG_UNICAST | FLAG_PTP_TIMESCALE, this.signalingSeq, 0x05, -128);
    this.signalingSeq = (this.signalingSeq + 1) & 0xffff;
    // targetPortIdentity (10 bytes) stays the zero wildcard.
    let tlv = HDR_LEN + 10;
    buf.writeUInt16BE(0x0003, tlv);
    buf.writeUInt16BE(0x0016, tlv + 2); // len 22
    buf[tlv + 4] = 0x00;
    buf[tlv + 5] = 0x0d;
    buf[tlv + 6] = 0x93;
    buf[tlv + 9] = 0x01;
    buf[tlv + 12] = 0x03;
    buf[tlv + 13] = 0x01;
    tlv += 26;
    buf.writeUInt16BE(0x0003, tlv);
    buf.writeUInt16BE(0x0020, tlv + 2); // len 32
    buf[tlv + 4] = 0x00;
    buf[tlv + 5] = 0x0d;
    buf[tlv + 6] = 0x93;
    buf[tlv + 9] = 0x05;
    buf[tlv + 12] = 0x03;
    buf[tlv + 13] = 0x01;

    this.send(this.generalSocket, GENERAL_PORT, buf);
  }

  private onEvent(msg: Buffer, rinfo: { address: string; port: number }): void {
    const rx = this.clock.now();
    if (msg.length < HDR_LEN) {
      return;
    }
    const type = (msg[0] as number) & 0x0f;
    if (type === MSG_DELAY_REQ) {
      this.sendDelayResp(msg, rx, rinfo.address);
      this.exchanges++;
    } else if (type === MSG_PDELAY_REQ) {
      this.sendPdelayResp(msg, rx, rinfo.address);
    }
  }

  private onGeneral(msg: Buffer, rinfo: { address: string; port: number }): void {
    if (msg.length < HDR_LEN) {
      return;
    }
    const type = (msg[0] as number) & 0x0f;
    if (type === MSG_ANNOUNCE) {
      // A competing grandmaster. We announce the iOS dataset, which out-ranks
      // what receivers advertise, so this is recorded rather than acted on.
      this.log(`RX Announce from ${rinfo.address} (peer clock, we hold grandmaster)`);
    }
  }

  /** Echo the requester's port identity and sequence with our receive time. */
  private sendDelayResp(req: Buffer, rxNs: bigint, requester: string): void {
    const seq = req.readUInt16BE(30);
    const buf = this.header(
      MSG_DELAY_RESP,
      HDR_LEN + 10 + 10,
      FLAG_UNICAST | FLAG_PTP_TIMESCALE | FLAG_TWO_STEP,
      seq,
      0x00,
      LOG_SYNC_INTERVAL,
    );
    writeTimestamp(buf, HDR_LEN, rxNs); // receiveTimestamp
    req.copy(buf, HDR_LEN + 10, 20, 30); // requestingPortIdentity
    // Unicast to the requester only: on a shared clock a broadcast reply hands
    // every receiver the others' responses as well.
    this.send(this.generalSocket, GENERAL_PORT, buf, requester);
  }

  /**
   * Answer the gPTP peer-delay probe. An 802.1AS receiver may mark a neighbour
   * that ignores this not-asCapable and then distrust its timeline, so it is
   * answered in any role — peer delay measures the link, not the timeline.
   */
  private sendPdelayResp(req: Buffer, rxNs: bigint, requester: string): void {
    const seq = req.readUInt16BE(30);

    const resp = this.header(
      MSG_PDELAY_RESP,
      HDR_LEN + 10 + 10,
      FLAG_UNICAST | FLAG_PTP_TIMESCALE | FLAG_TWO_STEP,
      seq,
      0x00,
      LOG_SYNC_INTERVAL,
    );
    writeTimestamp(resp, HDR_LEN, rxNs); // requestReceiptTimestamp
    req.copy(resp, HDR_LEN + 10, 20, 30);
    this.send(this.eventSocket, EVENT_PORT, resp, requester);

    const followUp = this.header(MSG_PDELAY_RESP_FUP, HDR_LEN + 10 + 10, FLAG_UNICAST | FLAG_PTP_TIMESCALE, seq, 0x00, LOG_SYNC_INTERVAL);
    writeTimestamp(followUp, HDR_LEN, this.clock.now()); // responseOriginTimestamp
    req.copy(followUp, HDR_LEN + 10, 20, 30);
    this.send(this.generalSocket, GENERAL_PORT, followUp, requester);
  }
}
