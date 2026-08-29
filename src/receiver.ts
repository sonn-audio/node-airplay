/**
 * The receiving half: an AirPlay 1 (RAOP) target other devices can stream to.
 *
 * Ported from libraop's `raop_server.c`. This is the mirror of everything else
 * in the package — an RTSP *server* instead of a client, ALAC decoding instead
 * of encoding, polling someone else's clock instead of serving our own.
 *
 * **Encryption is the caller's decision, not this package's.** A sender may
 * encrypt the audio with an AES key it wraps in the receiver's RSA public key,
 * and may demand an `Apple-Challenge` response signed with the matching private
 * key. That key is Apple's, and shipping it is not something a library should
 * decide for the person publishing it — so both operations are optional hooks
 * ({@link ReceiverOptions.rsa}). With no hook the service advertises `et=0`,
 * which is the honest statement that it takes cleartext only.
 *
 * mDNS advertising is likewise left to the caller: the port and the TXT record
 * are handed out, and the application publishes them with whatever responder it
 * already runs.
 */

import { connect as connectTcp, createServer, type Server, type Socket } from 'node:net';
import { createSocket, type Socket as UdpSocket } from 'node:dgram';
import { createDecipheriv, randomBytes } from 'node:crypto';
import { AlacDecoder, parseAlacFmtp, type AlacConfig } from './alacDecoder.js';
import { ntpNow } from './ntpTiming.js';

/** Events a session raises, mirroring what the native receiver reported. */
export type ReceiverEvent =
  | { type: 'stream'; port: number }
  /** The sender named its remote-control service; resolve it to send commands back. */
  | { type: 'remote'; dacpId: string; activeRemote: string }
  | { type: 'play' }
  | { type: 'pause' }
  | { type: 'flush' }
  | { type: 'stop' }
  | { type: 'volume'; value: number }
  | { type: 'metadata'; title?: string; artist?: string; album?: string }
  | { type: 'artwork'; contentType: string; data: Buffer }
  | { type: 'pcm'; sampleRate: number; channels: number; data: Buffer };

export interface ReceiverOptions {
  /** Name shown to senders; goes in the mDNS instance name. */
  name: string;
  /** Model string for the TXT record's `am` field. */
  model?: string;
  /** Six bytes identifying this receiver — the mDNS instance name's prefix. */
  mac?: Buffer;
  /** TCP port for RTSP; 0 picks a free one. */
  port?: number;
  /**
   * Hooks for the two operations that need Apple's AirPort private key. Supply
   * them to accept encrypted senders; leave them out and the service advertises
   * cleartext only.
   */
  /** Called for every request, so a caller can see how far a sender got. */
  onRequest?: (info: {
    method: string;
    appleChallenge: boolean;
    encryptedKey: boolean;
    headers: string[];
  }) => void;
  rsa?: {
    /** Decrypt an `rsaaeskey` from the SDP into the 16-byte AES key. */
    decryptAesKey(wrapped: Buffer): Buffer;
    /** Sign an `Apple-Challenge` into the `Apple-Response` header value. */
    answerChallenge(challenge: Buffer, localAddress: string, mac: Buffer): string;
  };
}

/** What the caller needs to advertise the service over mDNS. */
export interface ReceiverAdvertisement {
  /** `<mac hex>@<name>`, the instance name senders expect. */
  instanceName: string;
  port: number;
  /** TXT record as key/value pairs. */
  txt: Record<string, string>;
}

interface SessionState {
  alac: AlacConfig | null;
  aesKey: Buffer | null;
  aesIv: Buffer | null;
  decoder: AlacDecoder | null;
  audio: UdpSocket | null;
  control: UdpSocket | null;
  timing: UdpSocket | null;
  /** Where the sender listens for our timing polls and retransmit requests. */
  senderTimingPort: number;
  senderControlPort: number;
  senderAddress: string;
  /**
   * The sender's remote-control identity, from its RTSP headers. `DACP-ID`
   * names an `_dacp._tcp` service the sender publishes; `Active-Remote` is the
   * token that service accepts. Together they are how a receiver sends play,
   * pause and skip BACK to whatever is streaming to it.
   */
  dacpId: string | null;
  activeRemote: string | null;
}

/**
 * A running RAOP receiver. One instance serves one sender at a time, which is
 * what the protocol assumes: a second ANNOUNCE replaces the first.
 */
export class AirPlayReceiver {
  private server: Server | null = null;
  private readonly sessions = new Map<Socket, SessionState>();
  private readonly mac: Buffer;
  private volume = 0;

  constructor(
    private readonly options: ReceiverOptions,
    private readonly onEvent: (event: ReceiverEvent) => void,
  ) {
    this.mac = options.mac ?? randomBytes(6);
  }

  /** Start listening. Returns what the caller needs to advertise. */
  public async start(): Promise<ReceiverAdvertisement> {
    const server = createServer((socket) => this.onConnection(socket));
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(this.options.port ?? 0, () => {
        server.removeListener('error', reject);
        resolve();
      });
    });
    this.server = server;
    const address = server.address();
    const port = typeof address === 'object' && address ? address.port : 0;

    return {
      instanceName: `${this.mac.toString('hex').toUpperCase()}@${this.options.name}`,
      port,
      txt: {
        tp: 'UDP',
        sm: 'false',
        sv: 'false',
        // `ek=1` and an `et` with a 1 in it are claims about encryption we can
        // only make when the caller supplied the key to back them up.
        ek: this.options.rsa ? '1' : '0',
        et: this.options.rsa ? '0,1' : '0',
        md: '0,1,2',
        cn: '0,1',
        ch: '2',
        ss: '16',
        sr: '44100',
        // The RAOP protocol version. 65537 is the AirPlay 2 value and tells a
        // sender it is looking at something it should talk to differently.
        vn: '3',
        txtvers: '1',
        am: this.options.model ?? 'sonn',
      },
    };
  }

  public stop(): void {
    for (const [socket, session] of this.sessions) {
      this.teardown(session);
      socket.destroy();
    }
    this.sessions.clear();
    this.server?.close();
    this.server = null;
  }

  private onConnection(socket: Socket): void {
    socket.setNoDelay(true);
    const session: SessionState = {
      alac: null,
      aesKey: null,
      aesIv: null,
      decoder: null,
      audio: null,
      control: null,
      timing: null,
      senderTimingPort: 0,
      senderControlPort: 0,
      senderAddress: socket.remoteAddress?.replace(/^::ffff:/, '') ?? '',
      dacpId: null,
      activeRemote: null,
    };
    this.sessions.set(socket, session);

    let buffer = Buffer.alloc(0);
    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      for (;;) {
        const headerEnd = buffer.indexOf('\r\n\r\n');
        if (headerEnd < 0) {
          return;
        }
        const head = buffer.subarray(0, headerEnd).toString('utf8');
        const lines = head.split('\r\n');
        const headers = new Map<string, string>();
        for (const line of lines.slice(1)) {
          const sep = line.indexOf(':');
          if (sep > 0) {
            headers.set(line.slice(0, sep).trim().toLowerCase(), line.slice(sep + 1).trim());
          }
        }
        const length = Number(headers.get('content-length') ?? '0') || 0;
        if (buffer.length < headerEnd + 4 + length) {
          return;
        }
        const body = buffer.subarray(headerEnd + 4, headerEnd + 4 + length);
        buffer = buffer.subarray(headerEnd + 4 + length);
        this.handleRequest(socket, session, lines[0] ?? '', headers, Buffer.from(body));
      }
    });

    socket.on('close', () => {
      const state = this.sessions.get(socket);
      if (state) {
        this.teardown(state);
        this.sessions.delete(socket);
        this.onEvent({ type: 'stop' });
      }
    });
    socket.on('error', () => {
      /* the close handler does the cleanup */
    });
  }

  private reply(
    socket: Socket,
    cseq: string,
    extra: Record<string, string> = {},
    body?: Buffer,
  ): void {
    const headers: Record<string, string> = {
      Server: 'AirTunes/105.1',
      // Senders check this to know the receiver actually has an output; without
      // it an iPhone retries OPTIONS a few times and gives up before it ever
      // gets as far as ANNOUNCE.
      'Audio-Jack-Status': 'connected; type=analog',
      CSeq: cseq,
      ...extra,
    };
    if (body) {
      headers['Content-Length'] = String(body.length);
    }
    const text = Object.entries(headers)
      .map(([key, value]) => `${key}: ${value}`)
      .join('\r\n');
    socket.write(`RTSP/1.0 200 OK\r\n${text}\r\n\r\n`);
    if (body) {
      socket.write(body);
    }
  }

  private handleRequest(
    socket: Socket,
    session: SessionState,
    requestLine: string,
    headers: Map<string, string>,
    body: Buffer,
  ): void {
    const [method = ''] = requestLine.split(' ');
    const cseq = headers.get('cseq') ?? '0';
    this.options.onRequest?.({
      method,
      appleChallenge: headers.has('apple-challenge'),
      encryptedKey: body.toString('latin1').includes('rsaaeskey'),
      headers: [...headers.keys()],
    });

    // Every request carries these; keep the latest so a remote command can be
    // sent at any point in the session.
    const dacpId = headers.get('dacp-id');
    const activeRemote = headers.get('active-remote');
    if (dacpId && dacpId !== session.dacpId) {
      session.dacpId = dacpId;
      session.activeRemote = activeRemote ?? session.activeRemote;
      this.onEvent({ type: 'remote', dacpId, activeRemote: session.activeRemote ?? '' });
    } else if (activeRemote) {
      session.activeRemote = activeRemote;
    }

    // A sender may demand proof we hold the AirPort key before it will stream.
    const extra: Record<string, string> = {};
    const challenge = headers.get('apple-challenge');
    if (challenge && this.options.rsa) {
      extra['Apple-Response'] = this.options.rsa.answerChallenge(
        Buffer.from(challenge, 'base64'),
        socket.localAddress?.replace(/^::ffff:/, '') ?? '',
        this.mac,
      );
    }

    switch (method) {
      case 'OPTIONS':
        this.reply(socket, cseq, {
          ...extra,
          Public: 'ANNOUNCE, SETUP, RECORD, PAUSE, FLUSH, TEARDOWN, OPTIONS, GET_PARAMETER, SET_PARAMETER',
        });
        return;

      case 'ANNOUNCE':
        this.handleAnnounce(session, body.toString('utf8'));
        this.reply(socket, cseq, extra);
        return;

      case 'SETUP':
        void this.handleSetup(socket, session, headers, cseq, extra);
        return;

      case 'RECORD':
        this.onEvent({ type: 'play' });
        this.reply(socket, cseq, { ...extra, 'Audio-Latency': '11025' });
        return;

      case 'FLUSH':
        this.onEvent({ type: 'flush' });
        this.reply(socket, cseq, extra);
        return;

      case 'TEARDOWN':
        this.teardown(session);
        this.onEvent({ type: 'stop' });
        this.reply(socket, cseq, extra);
        return;

      case 'SET_PARAMETER':
        this.handleSetParameter(headers, body);
        this.reply(socket, cseq, extra);
        return;

      case 'GET_PARAMETER':
        this.reply(
          socket,
          cseq,
          { ...extra, 'Content-Type': 'text/parameters' },
          Buffer.from(`volume: ${this.volume.toFixed(6)}\r\n`, 'utf8'),
        );
        return;

      default:
        this.reply(socket, cseq, extra);
    }
  }

  /** Read the codec parameters, and the AES key when the sender encrypted one. */
  private handleAnnounce(session: SessionState, sdp: string): void {
    for (const line of sdp.split(/\r?\n/)) {
      if (line.startsWith('a=fmtp:')) {
        session.alac = parseAlacFmtp(line.slice(line.indexOf(' ') + 1));
      } else if (line.startsWith('a=rsaaeskey:')) {
        const wrapped = Buffer.from(base64Pad(line.slice('a=rsaaeskey:'.length)), 'base64');
        session.aesKey = this.options.rsa ? this.options.rsa.decryptAesKey(wrapped) : null;
      } else if (line.startsWith('a=aesiv:')) {
        session.aesIv = Buffer.from(base64Pad(line.slice('a=aesiv:'.length)), 'base64');
      }
    }
    if (session.alac) {
      session.decoder = new AlacDecoder(session.alac);
    }
  }

  private async handleSetup(
    socket: Socket,
    session: SessionState,
    headers: Map<string, string>,
    cseq: string,
    extra: Record<string, string>,
  ): Promise<void> {
    const transport = headers.get('transport') ?? '';
    const field = (name: string): number => {
      const match = new RegExp(`${name}=(\\d+)`).exec(transport);
      return match ? Number(match[1]) : 0;
    };
    session.senderControlPort = field('control_port');
    session.senderTimingPort = field('timing_port');

    const audio = createSocket({ type: 'udp4', reuseAddr: true });
    const control = createSocket({ type: 'udp4', reuseAddr: true });
    const timing = createSocket({ type: 'udp4', reuseAddr: true });
    audio.on('message', (msg) => this.onAudio(session, msg));
    control.on('message', (msg) => this.onControl(session, msg));
    await Promise.all([bind(audio), bind(control), bind(timing)]);
    session.audio = audio;
    session.control = control;
    session.timing = timing;

    // Poll the sender's clock: on RAOP the sender owns the timeline and we
    // follow it, the exact inverse of this package's sending side.
    if (session.senderTimingPort) {
      this.startTimingClient(session);
    }

    this.onEvent({ type: 'stream', port: audio.address().port });
    this.reply(socket, cseq, {
      ...extra,
      Transport:
        `RTP/AVP/UDP;unicast;mode=record;server_port=${audio.address().port};` +
        `control_port=${control.address().port};timing_port=${timing.address().port}`,
      Session: '1',
    });
  }

  /**
   * The control port carries two different things and they must not be
   * confused: a retransmit reply (type 0xD6) wraps a real audio packet behind a
   * four-byte header, while a sync packet (0xD4) is the sender telling us where
   * its timeline is. Feeding the latter to the decoder produces exactly what it
   * sounds like.
   */
  private onControl(session: SessionState, msg: Buffer): void {
    if (msg.length < 4) {
      return;
    }
    const type = (msg[1] as number) & 0x7f;
    if (type === 0x56) {
      this.onAudio(session, msg.subarray(4));
    }
    // 0x54 is the sync packet; the timeline it announces is not used yet.
  }

  /** Ask the sender for the time, the same 0xD2/0xD3 exchange we answer as a sender. */
  private startTimingClient(session: SessionState): void {
    const poll = (): void => {
      if (!session.timing) {
        return;
      }
      const request = Buffer.alloc(32);
      request[0] = 0x80;
      request[1] = 0xd2;
      request.writeUInt16BE(0x0007, 2);
      const now = ntpNow();
      request.writeUInt32BE(Number(now >> 32n), 24);
      request.writeUInt32BE(Number(now & 0xffff_ffffn), 28);
      session.timing.send(request, session.senderTimingPort, session.senderAddress);
    };
    poll();
    const timer = setInterval(poll, 3000);
    session.timing?.on('close', () => clearInterval(timer));
  }

  /**
   * One audio packet: strip the RTP header, decrypt when the sender encrypted,
   * decode, and hand the PCM up.
   *
   * AES here is CBC over whole 16-byte blocks only — the tail of the payload is
   * left in the clear, which is what the format specifies and what a decoder
   * that assumes otherwise gets wrong.
   */
  private onAudio(session: SessionState, packet: Buffer): void {
    if (packet.length <= 12 || !session.decoder || !session.alac) {
      return;
    }
    let payload = packet.subarray(12);

    if (session.aesKey && session.aesIv) {
      const whole = payload.length - (payload.length % 16);
      if (whole > 0) {
        const decipher = createDecipheriv('aes-128-cbc', session.aesKey, session.aesIv);
        decipher.setAutoPadding(false);
        const clear = Buffer.concat([decipher.update(payload.subarray(0, whole)), decipher.final()]);
        payload = Buffer.concat([clear, payload.subarray(whole)]);
      }
    }

    const pcm = session.decoder.decode(payload);
    if (pcm) {
      this.onEvent({
        type: 'pcm',
        sampleRate: session.alac.sampleRate,
        channels: session.alac.channels,
        data: pcm,
      });
    }
  }

  /** Volume, track metadata and cover art all arrive on SET_PARAMETER. */
  private handleSetParameter(headers: Map<string, string>, body: Buffer): void {
    const contentType = headers.get('content-type') ?? '';

    if (contentType.startsWith('text/parameters')) {
      const match = /volume:\s*(-?[\d.]+)/.exec(body.toString('utf8'));
      if (match) {
        this.volume = Number(match[1]);
        // The wire scale is dB from -30 to 0, with -144 for mute.
        const value = this.volume <= -144 ? 0 : Math.round(((this.volume + 30) / 30) * 100);
        this.onEvent({ type: 'volume', value: Math.min(100, Math.max(0, value)) });
      }
      return;
    }

    if (contentType.startsWith('image/')) {
      this.onEvent({ type: 'artwork', contentType, data: body });
      return;
    }

    if (contentType.includes('dmap')) {
      this.onEvent({ type: 'metadata', ...parseDmap(body) });
    }
  }

  private teardown(session: SessionState): void {
    session.audio?.close();
    session.control?.close();
    session.timing?.close();
    session.audio = session.control = session.timing = null;
    session.decoder = null;
  }
}

/**
 * Send a transport command back to the device that is streaming to us.
 *
 * The sender publishes an `_dacp._tcp` service named `iTunes_Ctrl_<DACP-ID>`;
 * resolving that is the caller's job (this package carries no mDNS), and the
 * address it finds goes in here. The request itself is a bare HTTP GET carrying
 * the `Active-Remote` token as its only credential.
 */
export async function sendRemoteCommand(
  host: string,
  port: number,
  activeRemote: string,
  command: 'play' | 'pause' | 'playpause' | 'stop' | 'nextitem' | 'previtem' | 'mutetoggle',
  timeoutMs = 3000,
): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    const socket = connectTcp({ host, port });
    let settled = false;
    const finish = (ok: boolean): void => {
      if (!settled) {
        settled = true;
        socket.destroy();
        resolve(ok);
      }
    };
    const timer = setTimeout(() => finish(false), timeoutMs);
    socket.once('connect', () => {
      socket.write(
        `GET /ctrl-int/1/${command} HTTP/1.0\r\n` +
          `Active-Remote: ${activeRemote}\r\n` +
          `Connection: close\r\n\r\n`,
      );
    });
    socket.once('data', (chunk) => {
      clearTimeout(timer);
      finish(/^HTTP\/1\.[01] 2\d\d/.test(chunk.toString('latin1')));
    });
    socket.once('error', () => {
      clearTimeout(timer);
      finish(false);
    });
    socket.once('close', () => {
      clearTimeout(timer);
      finish(false);
    });
  });
}

async function bind(socket: UdpSocket): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    socket.once('error', reject);
    socket.bind(0, () => {
      socket.removeListener('error', reject);
      resolve();
    });
  });
}

/** SDP strips base64 padding; Node's decoder wants it back. */
function base64Pad(value: string): string {
  const trimmed = value.trim();
  return trimmed + '='.repeat((4 - (trimmed.length % 4)) % 4);
}

/**
 * Pull the track fields out of a DMAP blob. The container is a tag, a 32-bit
 * length and a payload, nested — only the three fields a now-playing display
 * needs are read.
 */
function parseDmap(body: Buffer): { title?: string; artist?: string; album?: string } {
  const out: { title?: string; artist?: string; album?: string } = {};
  const walk = (buffer: Buffer): void => {
    let offset = 0;
    while (offset + 8 <= buffer.length) {
      const tag = buffer.subarray(offset, offset + 4).toString('latin1');
      const length = buffer.readUInt32BE(offset + 4);
      const value = buffer.subarray(offset + 8, offset + 8 + length);
      if (tag === 'mlit') {
        walk(value);
      } else if (tag === 'minm') {
        out.title = value.toString('utf8');
      } else if (tag === 'asar') {
        out.artist = value.toString('utf8');
      } else if (tag === 'asal') {
        out.album = value.toString('utf8');
      }
      offset += 8 + length;
    }
  };
  walk(body);
  return out;
}
