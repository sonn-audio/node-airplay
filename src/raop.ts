/**
 * AirPlay 1 (RAOP) — the legacy lane, for receivers that never learned AirPlay 2.
 *
 * Ported from libraop's `raop_client.c` / `rtsp_client.c`, the same C the rest
 * of this project replaces. It shares almost everything with the AirPlay 2 NTP
 * lane already here: the timing responder is the same 0xD2/0xD3 exchange, the
 * anchor is the same 20-byte 0xD4 packet, retransmits are the same 0x55/0x56,
 * and the ALAC encoder and DMAP metadata are shared outright. What is genuinely
 * different is only the handshake — an SDP-bodied ANNOUNCE instead of a plist,
 * a Transport header instead of a stream dictionary, and no encryption.
 *
 * Apple receivers on OS 27 and later no longer render this at all: they accept
 * the whole session and stay silent. Use AirPlay 2 for those; this is for the
 * gear that has nothing else — AirPort Express, older AVRs, third-party
 * speakers whose firmware stopped in the AirPlay 1 era.
 */

import { createSocket, type Socket } from 'node:dgram';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { encodeAlacPacket } from './alac.js';
import { buildNtpSyncPacket, ntpNow, NtpTimingResponder } from './ntpTiming.js';
import { RtspConnection } from './rtsp.js';

const SAMPLE_RATE = 44_100;
const CHANNELS = 2;
const SAMPLE_SIZE = 16;
/** Frames per packet. libraop's encoder sizes its output buffer for exactly this. */
export const RAOP_FRAMES_PER_PACKET = 352;
/**
 * Receivers ask for this much read-ahead on top of whatever the sender wants —
 * libraop's comment on it is "why do AirPlay devices use required latency +
 * 11025 ???", and the answer is still unknown, but the arithmetic depends on it.
 */
const RAOP_LATENCY_MIN = 11_025;
const RTX_RING_SLOTS = 512;

/** Seconds between the NTP and Unix epochs, for frame-to-NTP conversion. */
const NTP_EPOCH_DELTA = 2_208_988_800n;

/** RTP frame count to an absolute NTP time. */
function framesToNtp(frames: bigint): bigint {
  const seconds = frames / BigInt(SAMPLE_RATE);
  const rest = frames % BigInt(SAMPLE_RATE);
  return ((seconds + NTP_EPOCH_DELTA) << 32n) | ((rest << 32n) / BigInt(SAMPLE_RATE));
}

/** Absolute NTP time to an RTP frame count. */
function ntpToFrames(ntp: bigint): bigint {
  const seconds = (ntp >> 32n) - NTP_EPOCH_DELTA;
  const fraction = ntp & 0xffff_ffffn;
  return seconds * BigInt(SAMPLE_RATE) + ((fraction * BigInt(SAMPLE_RATE)) >> 32n);
}

export interface RaopConnectOptions {
  host: string;
  /** RAOP is usually on 5000; Apple-era devices answer on 7000. */
  port?: number;
  /**
   * The device's advertised encryption types (mDNS TXT `et`). A `4` in there
   * means MFi, and the device wants the `/auth-setup` exchange before SETUP —
   * without it those receivers answer the SETUP with a 403. Nothing secret is
   * needed for it; the exchange is a plain X25519 public key.
   */
  et?: string;
  /** Read-ahead requested from the device, in frames. */
  latencyFrames?: number;
  timeoutMs?: number;
  onLog?: (message: string) => void;
}

export interface RaopSession {
  rtsp: RtspConnection;
  /** Answers the device's timing polls; the device has no clock of its own here. */
  timing: NtpTimingResponder;
  /** Our sockets: sync and retransmits on one, audio on the other. */
  control: Socket;
  audio: Socket;
  /** UDP port on the device that audio goes to. */
  serverPort: number;
  /** UDP port on the device that sync packets go to. */
  controlPort: number;
  /** Total read-ahead the device holds, in frames. */
  latencyFrames: number;
  sessionUrl: string;
}

/**
 * The MFi handshake an `et` containing `4` asks for: post our X25519 public key
 * behind a `0x01` marker byte. The response is not used — performing the
 * exchange at all is what the receiver checks for.
 */
async function authSetup(rtsp: RtspConnection): Promise<void> {
  const { publicKey } = generateKeyPairSync('x25519');
  const raw = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  await rtsp.request('POST', {
    uri: '/auth-setup',
    contentType: 'application/octet-stream',
    body: Buffer.concat([Buffer.from([0x01]), raw]),
  });
}

/**
 * Open a RAOP session: OPTIONS, the MFi exchange when asked for, ANNOUNCE with
 * an SDP body, SETUP, and RECORD.
 */
export async function connectRaop(options: RaopConnectOptions): Promise<RaopSession> {
  const sessionId = randomBytes(4).readUInt32BE(0).toString().padStart(10, '0');
  const rtsp = new RtspConnection(options.host, options.port ?? 5000, sessionId);
  await rtsp.connect(options.timeoutMs);

  const clientInstance = randomBytes(8).toString('hex');
  const common = {
    'Client-Instance': clientInstance,
    'DACP-ID': clientInstance.toUpperCase(),
    'Active-Remote': String(randomBytes(4).readUInt32BE(0)),
  };
  const sessionUrl = `rtsp://${rtsp.localAddress()}/${sessionId}`;

  try {
    await rtsp.request('OPTIONS', { uri: '*', headers: common });

    if (options.et?.includes('4')) {
      await authSetup(rtsp);
    }

    // The SDP names the codec and its frame geometry. The fmtp line is ALAC's
    // magic cookie in text form: frame length, then the encoder's fixed
    // parameters, then channels and sample rate.
    const sdp =
      `v=0\r\n` +
      `o=iTunes ${sessionId} 0 IN IP4 ${rtsp.localAddress()}\r\n` +
      `s=iTunes\r\n` +
      `c=IN IP4 ${options.host}\r\n` +
      `t=0 0\r\n` +
      `m=audio 0 RTP/AVP 96\r\n` +
      `a=rtpmap:96 AppleLossless\r\n` +
      `a=fmtp:96 ${RAOP_FRAMES_PER_PACKET} 0 ${SAMPLE_SIZE} 40 10 14 ${CHANNELS} 255 0 0 ${SAMPLE_RATE}\r\n`;

    const announce = await rtsp.request('ANNOUNCE', {
      uri: sessionUrl,
      contentType: 'application/sdp',
      headers: common,
      body: Buffer.from(sdp, 'utf8'),
    });
    if (announce.status !== 200) {
      throw new Error(`RAOP ANNOUNCE failed with status ${announce.status}`);
    }

    // Our timing port has to exist before SETUP: Apple receivers expect to be
    // able to poll it as soon as the transport is agreed.
    const timing = new NtpTimingResponder();
    const timingPort = await timing.start();
    const control = createSocket({ type: 'udp4', reuseAddr: true });
    const audio = createSocket({ type: 'udp4', reuseAddr: true });
    await Promise.all([bindEphemeral(control), bindEphemeral(audio)]);

    const setup = await rtsp.request('SETUP', {
      uri: sessionUrl,
      headers: {
        ...common,
        Transport:
          `RTP/AVP/UDP;unicast;interleaved=0-1;mode=record;` +
          `control_port=${control.address().port};timing_port=${timingPort}`,
      },
    });
    if (setup.status !== 200) {
      throw new Error(`RAOP SETUP failed with status ${setup.status}`);
    }

    const transport = setup.headers.get('transport') ?? '';
    const field = (name: string): number => {
      const match = new RegExp(`${name}=(\\d+)`).exec(transport);
      return match ? Number(match[1]) : 0;
    };
    const serverPort = field('server_port');
    const controlPort = field('control_port');
    if (!serverPort || !controlPort) {
      throw new Error(`RAOP SETUP gave no ports (transport: ${transport})`);
    }

    const record = await rtsp.request('RECORD', {
      uri: sessionUrl,
      headers: { ...common, Range: 'npt=0-', 'RTP-Info': 'seq=0;rtptime=0' },
    });
    if (record.status !== 200) {
      throw new Error(`RAOP RECORD failed with status ${record.status}`);
    }

    // The device may raise the read-ahead it wants; it wins.
    const announced = Number(record.headers.get('audio-latency') ?? '0') || 0;
    const latencyFrames =
      Math.max(announced, options.latencyFrames ?? 22_050) + RAOP_LATENCY_MIN;

    return { rtsp, timing, control, audio, serverPort, controlPort, latencyFrames, sessionUrl };
  } catch (err) {
    rtsp.close();
    throw err;
  }
}

async function bindEphemeral(socket: Socket): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    socket.once('error', reject);
    socket.bind(0, () => {
      socket.removeListener('error', reject);
      resolve();
    });
  });
}

export interface RaopStreamOptions {
  host: string;
  session: RaopSession;
  onLog?: (message: string) => void;
}

/**
 * Streams ALAC over RAOP: audio on one socket, the anchor and retransmit
 * answers on the other.
 *
 * The timeline here is the frame counter itself — `headFrames` is an absolute
 * position derived from the NTP instant playback was anchored at, and every
 * sync packet reports it. That is the whole of RAOP's clock model: no PTP, no
 * grandmaster, just a sender that keeps saying where it is.
 */
export class RaopStreamer {
  private sequence = Math.floor(Math.random() * 0xffff);
  private readonly ssrc = randomBytes(4).readUInt32BE(0);
  private headFrames = 0n;
  private firstPacket = true;
  private syncTimer: NodeJS.Timeout | null = null;
  private readonly rtxRing: (Buffer | null)[] = new Array(RTX_RING_SLOTS).fill(null);
  private readonly rtxSeq: number[] = new Array(RTX_RING_SLOTS).fill(-1);
  public packetsSent = 0;
  public rtxAnswered = 0;

  constructor(private readonly options: RaopStreamOptions) {
    options.session.control.on('message', (msg, rinfo) => this.onControl(msg, rinfo));
  }

  /** Total read-ahead the device holds, in milliseconds. */
  public get latencyMs(): number {
    return Math.round((this.options.session.latencyFrames / SAMPLE_RATE) * 1000);
  }

  /**
   * Anchor playback.
   *
   * :param startNtp: absolute NTP instant the first frame belongs to. Every
   *   member of a sync group is handed the same one, which is what lines a RAOP
   *   zone up with an AirPlay 2 zone: both express the same moment.
   */
  public start(startNtp?: bigint): void {
    this.headFrames = ntpToFrames(startNtp ?? ntpNow());
    this.sendSync(true);
    this.syncTimer = setInterval(() => this.sendSync(false), 1000);
  }

  public stop(): void {
    if (this.syncTimer) {
      clearInterval(this.syncTimer);
      this.syncTimer = null;
    }
    this.options.session.timing.stop();
    this.options.session.control.close();
    this.options.session.audio.close();
  }

  /** Send one packet of interleaved s16le PCM. */
  public sendPacket(pcm: Buffer): void {
    const encoded = encodeAlacPacket(pcm, {
      framesPerPacket: RAOP_FRAMES_PER_PACKET,
      bitDepth: 16,
      channels: CHANNELS,
    });

    this.sequence = (this.sequence + 1) & 0xffff;
    const packet = Buffer.alloc(12 + encoded.length);
    packet[0] = 0x80;
    packet[1] = 0x60 | (this.firstPacket ? 0x80 : 0);
    packet.writeUInt16BE(this.sequence, 2);
    packet.writeUInt32BE(Number(this.headFrames & 0xffff_ffffn), 4);
    packet.writeUInt32BE(this.ssrc, 8);
    encoded.copy(packet, 12);
    this.firstPacket = false;

    const slot = this.sequence % RTX_RING_SLOTS;
    this.rtxRing[slot] = packet;
    this.rtxSeq[slot] = this.sequence;

    this.options.session.audio.send(
      packet,
      this.options.session.serverPort,
      this.options.host,
      (err) => {
        if (err) {
          this.options.onLog?.(`RAOP audio send failed: ${err.message}`);
        }
      },
    );
    this.headFrames += BigInt(pcm.length / (CHANNELS * 2));
    this.packetsSent++;
  }

  /** Where the timeline is now — reported once a second so the device can follow. */
  private sendSync(first: boolean): void {
    const packet = buildNtpSyncPacket(
      Number(this.headFrames & 0xffff_ffffn),
      this.options.session.latencyFrames,
      first,
    );
    // RAOP reports the time the frame counter says it is, not the wall clock:
    // the frame counter IS the timeline.
    const ntp = framesToNtp(this.headFrames);
    packet.writeUInt32BE(Number(ntp >> 32n), 8);
    packet.writeUInt32BE(Number(ntp & 0xffff_ffffn), 12);

    this.options.session.control.send(
      packet,
      this.options.session.controlPort,
      this.options.host,
      (err) => {
        if (err) {
          this.options.onLog?.(`RAOP sync send failed: ${err.message}`);
        }
      },
    );
  }

  /** Same retransmit contract as the AirPlay 2 lane: 0x55 asks, 0x56 answers. */
  private onControl(msg: Buffer, rinfo: { address: string; port: number }): void {
    if (msg.length < 8 || ((msg[1] as number) & 0x7f) !== 0x55) {
      return;
    }
    const requestSeq = msg.readUInt16BE(2);
    const first = msg.readUInt16BE(4);
    const count = Math.min(msg.readUInt16BE(6) || 1, RTX_RING_SLOTS);

    for (let i = 0; i < count; i++) {
      const seq = (first + i) & 0xffff;
      const slot = seq % RTX_RING_SLOTS;
      const stored = this.rtxSeq[slot] === seq ? this.rtxRing[slot] : null;
      if (!stored) {
        continue;
      }
      const header = Buffer.alloc(4);
      header[0] = 0x80;
      header[1] = 0xd6;
      header.writeUInt16BE(requestSeq, 2);
      this.options.session.control.send(
        Buffer.concat([header, stored]),
        rinfo.port,
        rinfo.address,
      );
      this.rtxAnswered++;
    }
  }
}
