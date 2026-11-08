/**
 * The realtime (type 96) audio stream: RECORD, the stream SETUP, and the RTP
 * send path with its PTP anchor.
 *
 * Ported from cliairplay's `ap2_client.c`. Two orderings in here are load-bearing:
 * RECORD goes out BEFORE the stream SETUP (a Samsung receiver 200-ACKs the other
 * order and then renders silence), and the anchor line is frozen once at stream
 * start so every periodic sync packet extrapolates along the same line rather
 * than re-deriving one.
 */

import { createSocket, type Socket } from 'node:dgram';
import { createCipheriv } from 'node:crypto';
import { parseBinaryPlist, type PlistValue } from './bplist.js';
import { buildBinaryPlist } from './bplistWriter.js';
import { encodeAlacPacket } from './alac.js';
import type { PtpEngine } from './ptp.js';
import { buildNtpSyncPacket } from './ntpTiming.js';
import type { RtspConnection } from './rtsp.js';

const PLIST_CONTENT_TYPE = 'application/x-apple-binary-plist';
/** ALAC 44100/16/2 — bit 18 of the audioFormat space. */
export const AUDIO_FORMAT_ALAC_44100_16_2 = 1 << 18;
/** Frames per packet the AirPlay session negotiates. */
export const FRAMES_PER_PACKET = 352;
const SAMPLE_RATE = 44_100;
const CHANNELS = 2;
const TAG_SIZE = 16;
/** The receiver's buffering window for a live RTP feed. */
const LATENCY_MIN = 11_025;
const LATENCY_MAX = 88_200;
/**
 * Retransmit history. Receivers report lost audio on the control port and wait
 * for it to come back; left unanswered the request simply repeats and the
 * receiver keeps a permanent hole in its stream. A request is only worth
 * answering while the packet is still ahead of the receiver's play point, so
 * the ring only has to outlast the send window — 512 packets is 4.1 s.
 */
const RTX_RING_SLOTS = 512;
/** Control-port message types (marker bit set): request in, resend out. */
const RTX_REQUEST_TYPE = 0x55;
const RTX_RESEND_TYPE = 0xd6;

/** Offsets shairport-sync's receiver math expects in the anchor packet. */
const ANCHOR_FRAME_1_OFFSET = 11_035;
const ANCHOR_FRAME_2_OFFSET = 77_175;

export interface StreamSetupResult {
  /** UDP port on the receiver that RTP audio goes to. */
  dataPort: number;
  /** UDP port on the receiver that anchor/sync packets go to. */
  controlPort: number;
}

/**
 * RECORD, then the stream SETUP. Returns the receiver's ports.
 *
 * :param audioKey: the 32-byte `shk` — the pairing shared secret, which is what
 *   the receiver decrypts RTP payloads with.
 * :param localDataPort/localControlPort: our own bound UDP ports.
 */
export async function setupRealtimeStream(
  rtsp: RtspConnection,
  sessionUrl: string,
  options: {
    audioKey: Buffer;
    localDataPort: number;
    localControlPort: number;
    streamConnectionId: number;
  },
): Promise<StreamSetupResult> {
  // RECORD first — see the note at the top of this file.
  const record = await rtsp.request('RECORD', { uri: sessionUrl });
  if (record.status !== 200) {
    throw new Error(`RECORD failed with status ${record.status}`);
  }

  const body = buildBinaryPlist({
    streams: [
      {
        audioFormat: AUDIO_FORMAT_ALAC_44100_16_2,
        audioMode: 'default',
        controlPort: options.localControlPort,
        ct: 2, // ALAC
        dataPort: options.localDataPort,
        isMedia: true,
        latencyMax: LATENCY_MAX,
        latencyMin: LATENCY_MIN,
        shk: options.audioKey,
        spf: FRAMES_PER_PACKET,
        sr: SAMPLE_RATE,
        streamConnectionID: options.streamConnectionId,
        supportsDynamicStreamID: false,
        type: 96,
      },
    ],
  });

  const response = await rtsp.request('SETUP', {
    uri: sessionUrl,
    contentType: PLIST_CONTENT_TYPE,
    body,
  });
  if (response.status !== 200) {
    throw new Error(`stream SETUP failed with status ${response.status}`);
  }

  const parsed = parseBinaryPlist(response.body);
  const streams = (parsed as { streams?: PlistValue[] }).streams;
  const first = Array.isArray(streams) ? streams[0] : undefined;
  if (!first || typeof first !== 'object' || Array.isArray(first)) {
    throw new Error('stream SETUP reply carried no stream');
  }
  const stream = first as { [key: string]: PlistValue };
  const dataPort = Number(stream['dataPort'] ?? 0);
  const controlPort = Number(stream['controlPort'] ?? 0);
  if (!dataPort || !controlPort) {
    throw new Error(`stream SETUP reply lacked ports (data=${dataPort}, control=${controlPort})`);
  }
  return { dataPort, controlPort };
}

/**
 * How long a metadata or artwork push may wait for its answer. Some receivers
 * never answer one; where requests go one at a time, a volume change must not
 * sit behind that for the full RTSP timeout.
 */
const METADATA_TIMEOUT_MS = 4_000;

/** Map a 0-100 level onto the AirPlay dB scale; 0 is mute. */
export function volumeToDb(volume: number): number {
  const clamped = Math.min(100, Math.max(0, volume));
  return clamped === 0 ? -144 : -30 + (30 * clamped) / 100;
}

export async function setVolume(
  rtsp: RtspConnection,
  sessionUrl: string,
  volume: number,
): Promise<void> {
  await rtsp.request('SET_PARAMETER', {
    uri: sessionUrl,
    contentType: 'text/parameters',
    body: Buffer.from(`volume: ${volumeToDb(volume).toFixed(6)}\r\n`, 'utf8'),
    // Where requests go one at a time, the newest level is the only one worth
    // sending, and it goes before metadata still waiting: a knob should not lag
    // behind a cover upload.
    replaces: 'volume',
    urgent: true,
  });
}

/**
 * Push track metadata over the encrypted control channel as a DMAP `mlit` blob.
 *
 * There are two metadata paths on AirPlay 2 and only this one is open to us:
 * Apple's now-playing screen rides the type-130 MediaRemote channel, whose keys
 * derive from a pair-VERIFY shared secret, so it needs stored credentials from a
 * PIN pairing. A transiently paired session cannot reach it. This DMAP push over
 * SET_PARAMETER needs no credentials, and some receivers (Sonos) withhold audio
 * entirely until they have had it.
 *
 * :param rtpTimestamp: the current RTP position — the blob is anchored to it,
 *   and a receiver may reject a metadata request that arrives without one.
 */
export async function setMetadata(
  rtsp: RtspConnection,
  sessionUrl: string,
  metadata: { title?: string; artist?: string; album?: string },
  rtpTimestamp: number,
): Promise<void> {
  const field = (tag: string, value: string): Buffer => {
    const payload = Buffer.from(value, 'utf8');
    const head = Buffer.alloc(8);
    head.write(tag, 0, 'latin1');
    head.writeUInt32BE(payload.length, 4);
    return Buffer.concat([head, payload]);
  };

  const body = Buffer.concat([
    Buffer.from([0x00, 0x00, 0x00, 0x01, 0x02]), // mikd: length 1, value 2
    field('minm', metadata.title ?? ''),
    field('asar', metadata.artist ?? ''),
    field('asal', metadata.album ?? ''),
    Buffer.from([0x00, 0x00, 0x00, 0x02, 0x00, 0x01]), // astn: track number 1
  ]);
  const mikd = Buffer.alloc(4);
  mikd.write('mikd', 0, 'latin1');
  const payload = Buffer.concat([mikd, body]);

  const container = Buffer.alloc(8);
  container.write('mlit', 0, 'latin1');
  container.writeUInt32BE(payload.length, 4);

  await rtsp.request('SET_PARAMETER', {
    uri: sessionUrl,
    contentType: 'application/x-dmap-tagged',
    headers: { 'RTP-Info': `rtptime=${rtpTimestamp >>> 0}` },
    body: Buffer.concat([container, payload]),
    replaces: 'metadata',
    timeoutMs: METADATA_TIMEOUT_MS,
  });
}

/** Push cover art on the same DMAP/SET_PARAMETER path as {@link setMetadata}. */
export async function setArtwork(
  rtsp: RtspConnection,
  sessionUrl: string,
  contentType: string,
  data: Buffer,
  rtpTimestamp: number,
): Promise<void> {
  await rtsp.request('SET_PARAMETER', {
    uri: sessionUrl,
    contentType,
    headers: { 'RTP-Info': `rtptime=${rtpTimestamp >>> 0}` },
    body: data,
    replaces: 'artwork',
    timeoutMs: METADATA_TIMEOUT_MS,
  });
}

export interface RealtimeSenderOptions {
  host: string;
  dataPort: number;
  controlPort: number;
  /** The `shk` the stream SETUP announced. */
  audioKey: Buffer;
  ptp: PtpEngine;
  /**
   * Timing lane. `ntp` swaps the anchor packet for the 20-byte NTP form and
   * leaves the PTP engine out of the timeline; the receiver polls our responder
   * instead. Apple receivers must stay on `ptp` — they render silence on an
   * NTP-timed realtime stream.
   */
  timing?: 'ptp' | 'ntp';
  /**
   * How far ahead of the render point audio is handed over, in milliseconds:
   * the receiver plays a sample this long after we send it.
   */
  leadMs?: number;
  onLog?: (message: string) => void;
}

/**
 * Feeds one receiver: ALAC-encodes PCM, encrypts each packet, and keeps the
 * anchor announcements flowing so the receiver knows where on the PTP timeline
 * the audio belongs.
 */
export class RealtimeSender {
  private readonly dataSocket: Socket;
  private readonly controlSocket: Socket;
  private sequence = Math.floor(Math.random() * 0xffff);
  private rtpTimestamp = 0;
  private firstPacket = true;
  private anchorWall0 = 0n;
  private anchorPos0 = 0;
  private anchored = false;
  private syncTimer: NodeJS.Timeout | null = null;
  private readonly leadMs: number;
  public packetsSent = 0;
  /** Current RTP position; metadata is anchored to it. */
  public get rtpPosition(): number {
    return this.rtpTimestamp >>> 0;
  }
  /** Packets kept on the wire exactly as sent, so a resend is a byte copy —
   * re-encrypting would need the original nonce anyway. */
  private readonly rtxRing: (Buffer | null)[] = new Array(RTX_RING_SLOTS).fill(null);
  private readonly rtxSeq: number[] = new Array(RTX_RING_SLOTS).fill(-1);
  public rtxRequested = 0;
  public rtxAnswered = 0;
  public rtxExpired = 0;

  constructor(
    private readonly options: RealtimeSenderOptions,
    dataSocket: Socket,
    controlSocket: Socket,
  ) {
    this.dataSocket = dataSocket;
    this.controlSocket = controlSocket;
    this.leadMs = options.leadMs ?? 2000;
    this.controlSocket.on('message', (msg, rinfo) => this.onControl(msg, rinfo));
  }

  /**
   * Answer a receiver's request for audio it lost.
   *
   * Request (type 0x55): [2:4] the request's own sequence, [4:6] the first
   * missing RTP sequence, [6:8] how many. The reply wraps the original packet
   * verbatim behind a 4-byte header echoing that request sequence, and goes
   * back to where the request came from rather than the configured control
   * address — the same endpoint for a well-behaved receiver, and it keeps
   * working for one that asks from a different source port.
   */
  private onControl(msg: Buffer, rinfo: { address: string; port: number }): void {
    if (msg.length < 8 || ((msg[1] as number) & 0x7f) !== RTX_REQUEST_TYPE) {
      return;
    }
    const requestSeq = msg.readUInt16BE(2);
    const first = msg.readUInt16BE(4);
    let count = msg.readUInt16BE(6);
    if (count === 0 || count > RTX_RING_SLOTS) {
      count = count === 0 ? 1 : RTX_RING_SLOTS;
    }
    this.rtxRequested += count;

    for (let i = 0; i < count; i++) {
      const seq = (first + i) & 0xffff;
      const slot = seq % RTX_RING_SLOTS;
      const stored = this.rtxSeq[slot] === seq ? this.rtxRing[slot] : null;
      if (!stored) {
        this.rtxExpired++;
        continue;
      }
      const header = Buffer.alloc(4);
      header[0] = 0x80;
      header[1] = RTX_RESEND_TYPE;
      header.writeUInt16BE(requestSeq, 2);
      this.controlSocket.send(Buffer.concat([header, stored]), rinfo.port, rinfo.address, (err) => {
        if (err) {
          this.options.onLog?.(`retransmit send failed: ${err.message}`);
        }
      });
      this.rtxAnswered++;
    }
  }

  /** Bind the two local UDP sockets the stream SETUP has to advertise. */
  public static async bindSockets(): Promise<{ data: Socket; control: Socket; dataPort: number; controlPort: number }> {
    const bind = async (): Promise<{ socket: Socket; port: number }> => {
      const socket = createSocket({ type: 'udp4', reuseAddr: true });
      await new Promise<void>((resolve, reject) => {
        socket.once('error', reject);
        socket.bind(0, () => {
          socket.removeListener('error', reject);
          resolve();
        });
      });
      return { socket, port: socket.address().port };
    };
    const data = await bind();
    const control = await bind();
    return { data: data.socket, control: control.socket, dataPort: data.port, controlPort: control.port };
  }

  /**
   * Freeze the anchor line and start announcing it.
   *
   * :param startAtUnixMs: for a synchronised group, the wall-clock instant the
   *   first sample must be AUDIBLE on every member. All members are handed the
   *   same value, so they map the same sample to the same moment however far
   *   ahead each one runs. Anchoring one lead early is what makes the line's
   *   audible point land exactly on that instant. Omitted = start now, which is
   *   the solo case.
   *
   * This works because our timeline is the host's realtime clock — the same
   * base the caller's shared instant comes from — and because every member of
   * the group is served by the one grandmaster this process runs.
   */
  public start(startAtUnixMs?: number): void {
    const now = this.options.ptp.now();
    if (startAtUnixMs !== undefined) {
      this.anchorWall0 = BigInt(Math.round(startAtUnixMs)) * 1_000_000n - BigInt(this.leadMs) * 1_000_000n;
    } else {
      this.anchorWall0 = now;
    }
    this.anchorPos0 = this.rtpTimestamp;
    this.anchored = true;
    this.sendSyncPacket(true);
    this.syncTimer = setInterval(() => this.sendSyncPacket(false), 1000);
  }

  public stop(): void {
    if (this.syncTimer) {
      clearInterval(this.syncTimer);
      this.syncTimer = null;
    }
    this.dataSocket.close();
    this.controlSocket.close();
  }

  /**
   * Send one packet of interleaved s16le PCM — exactly
   * {@link FRAMES_PER_PACKET} frames unless it is the last one.
   */
  public sendPacket(pcm: Buffer): void {
    const encoded = encodeAlacPacket(pcm, {
      framesPerPacket: FRAMES_PER_PACKET,
      bitDepth: 16,
      channels: CHANNELS,
    });

    const header = Buffer.alloc(12);
    header[0] = 0x80;
    header[1] = this.firstPacket ? 0xe0 : 0x60; // payload type 96, marker on the first
    header.writeUInt16BE(this.sequence & 0xffff, 2);
    header.writeUInt32BE(this.rtpTimestamp >>> 0, 4);
    header.writeUInt32BE(0, 8); // SSRC is 0 on a PTP session

    // Nonce: 12 bytes, zero but for the 2-byte sequence at offset 4 in native
    // byte order. The same 8 bytes trail the packet so the receiver can rebuild
    // it — without that suffix every packet fails its tag and is dropped.
    const nonce = Buffer.alloc(12);
    nonce.writeUInt16LE(this.sequence & 0xffff, 4);

    const cipher = createCipheriv('chacha20-poly1305', this.options.audioKey, nonce, {
      authTagLength: TAG_SIZE,
    });
    cipher.setAAD(header.subarray(4, 12), { plaintextLength: encoded.length }); // timestamp + SSRC
    const ciphertext = Buffer.concat([cipher.update(encoded), cipher.final()]);

    const packet = Buffer.concat([header, ciphertext, cipher.getAuthTag(), nonce.subarray(4, 12)]);
    // Keep the wire bytes: the receiver can ask for this packet back at any
    // point inside its buffer window.
    const slot = (this.sequence & 0xffff) % RTX_RING_SLOTS;
    this.rtxRing[slot] = packet;
    this.rtxSeq[slot] = this.sequence & 0xffff;
    this.dataSocket.send(packet, this.options.dataPort, this.options.host, (err) => {
      if (err) {
        this.options.onLog?.(`RTP send failed: ${err.message}`);
      }
    });

    this.firstPacket = false;
    this.sequence = (this.sequence + 1) & 0xffff;
    this.rtpTimestamp = (this.rtpTimestamp + pcm.length / (CHANNELS * 2)) >>> 0;
    this.packetsSent++;
  }

  /**
   * The 28-byte anchor packet: where the media timeline sits on the PTP clock.
   * Every one extrapolates along the line frozen in {@link start}, so all of
   * them agree.
   */
  private sendSyncPacket(first: boolean): void {
    if (!this.anchored) {
      return;
    }
    if (this.options.timing === 'ntp') {
      const leadFrames = Math.round((this.leadMs / 1000) * SAMPLE_RATE);
      const packet = buildNtpSyncPacket(this.rtpTimestamp, leadFrames, first);
      this.controlSocket.send(packet, this.options.controlPort, this.options.host, (err) => {
        if (err) {
          this.options.onLog?.(`ntp sync send failed: ${err.message}`);
        }
      });
      return;
    }
    const wall = this.options.ptp.now();
    const elapsedNs = wall - this.anchorWall0 - BigInt(this.leadMs) * 1_000_000n;
    const playPos =
      (this.anchorPos0 + Number((elapsedNs * BigInt(SAMPLE_RATE)) / 1_000_000_000n)) >>> 0;
    const frame1 = (playPos + ANCHOR_FRAME_1_OFFSET) >>> 0;
    const frame2 = (frame1 + ANCHOR_FRAME_2_OFFSET) >>> 0;

    const packet = Buffer.alloc(28);
    packet[0] = first ? 0x90 : 0x80;
    packet[1] = 0xd7;
    packet.writeUInt16BE(0x0006, 2);
    packet.writeUInt32BE(frame1, 4);
    packet.writeBigUInt64BE(wall, 8); // the PTP master's wall clock, in ns
    packet.writeUInt32BE(frame2, 16);
    packet.writeBigUInt64BE(this.options.ptp.clockId, 20);

    this.controlSocket.send(packet, this.options.controlPort, this.options.host, (err) => {
      if (err) {
        this.options.onLog?.(`sync send failed: ${err.message}`);
      }
    });
  }
}
