/**
 * The receiver's control connection: RTSP/1.0 request-response over one TCP
 * socket, optionally wrapped in HAP's encrypted framing once pairing has run.
 *
 * AirPlay speaks RTSP over the same socket for the whole session and keeps it
 * open — it is also the channel the receiver uses to report teardown — so this
 * is a long-lived connection with a request queue, not a request factory.
 */

import { connect, type Socket } from 'node:net';
import type { HapSession } from './hap.js';

export const USER_AGENT = 'AirPlay/670.6.2';

export interface RtspResponse {
  status: number;
  reason: string;
  headers: Map<string, string>;
  body: Buffer;
}

export interface RtspRequestOptions {
  /** Extra headers, e.g. `X-Apple-HKP`. Content-Length is always set here. */
  headers?: Record<string, string>;
  body?: Buffer;
  contentType?: string;
  /** Request line target; defaults to the `rtsp://<host>/<sessionId>` form. */
  uri?: string;
  timeoutMs?: number;
  /**
   * On a one-at-a-time connection: a request of the same kind still waiting to
   * go out is dropped for this one — only the newest volume, say, is worth
   * sending. Ignored where requests go out at once.
   */
  replaces?: string;
  /**
   * On a one-at-a-time connection: go out before waiting requests that are not
   * urgent themselves. Ignored where requests go out at once.
   */
  urgent?: boolean;
}

export interface RtspConnectionOptions {
  /**
   * Send the next request only once the previous one is answered or has timed
   * out. See {@link RtspConnection}.
   */
  oneAtATime?: boolean;
}

interface Pending {
  cseq: number;
  resolve: (value: RtspResponse) => void;
  reject: (err: Error) => void;
  timer: NodeJS.Timeout;
}

/** A request on a one-at-a-time connection that has not gone out yet. */
interface Waiting {
  method: string;
  options: RtspRequestOptions;
  resolve: (value: RtspResponse) => void;
  reject: (err: Error) => void;
}

const DEFAULT_TIMEOUT_MS = 10_000;

export class RtspConnection {
  private socket: Socket | null = null;
  private buffer: Buffer = Buffer.alloc(0);
  private readonly queue: Pending[] = [];
  private cseq = 0;
  /** Set once pairing completes; from then on every byte is HAP-framed. */
  private hap: HapSession | null = null;
  private closed = false;
  private readonly waiting: Waiting[] = [];

  /**
   * :param options.oneAtATime: what an AirPlay 1 receiver needs. RTSP lets a
   *   client send its next request before the last one is answered, and Apple
   *   receivers take that in their stride; the embedded RTSP servers in a lot of
   *   AirPlay 1 gear do not. Handed a volume change and a metadata push in the
   *   same instant, a B&O speaker stopped answering anything on the connection,
   *   and stayed silent (sonn-audio/core#429). libraop, which drove these
   *   receivers for years, never had two requests out at once, so this lane
   *   does not either. It stays off for AirPlay 2: its `/feedback` keepalive
   *   must not wait behind a slow artwork upload, or the receiver ends the
   *   session.
   */
  constructor(
    private readonly host: string,
    private readonly port: number,
    /** Random per-session id used in the default request URI. */
    private readonly sessionId: string,
    /** Called when the receiver drops the control channel — the session is over. */
    private readonly onClose?: (reason: string) => void,
    private readonly options: RtspConnectionOptions = {},
  ) {}

  public async connect(timeoutMs = DEFAULT_TIMEOUT_MS): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      const socket = connect({ host: this.host, port: this.port });
      const timer = setTimeout(() => {
        socket.destroy();
        reject(new Error(`RTSP connect to ${this.host}:${this.port} timed out`));
      }, timeoutMs);
      socket.once('connect', () => {
        clearTimeout(timer);
        socket.setNoDelay(true);
        this.socket = socket;
        socket.on('data', (chunk) => this.onData(chunk));
        socket.on('error', (err) => this.failAll(err));
        socket.on('close', () => {
          this.failAll(new Error('RTSP connection closed'));
          if (!this.closed) {
            this.onClose?.('receiver closed the control channel');
          }
        });
        resolve();
      });
      socket.once('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });
    });
  }

  /** Local address the socket ended up on — goes into the SDP/SETUP bodies. */
  public localAddress(): string {
    return this.socket?.localAddress?.replace(/^::ffff:/, '') ?? '0.0.0.0';
  }

  /** Switch the connection to HAP-encrypted framing. */
  public enableEncryption(hap: HapSession): void {
    this.hap = hap;
  }

  public isEncrypted(): boolean {
    return this.hap !== null;
  }

  public async request(method: string, options: RtspRequestOptions = {}): Promise<RtspResponse> {
    if (!this.socket || this.closed) {
      throw new Error('RTSP connection is not open');
    }
    if (!this.options.oneAtATime) {
      return new Promise<RtspResponse>((resolve, reject) => this.send({ method, options, resolve, reject }));
    }
    return new Promise<RtspResponse>((resolve, reject) => {
      const entry: Waiting = { method, options, resolve, reject };
      if (options.replaces !== undefined) {
        const index = this.waiting.findIndex((w) => w.options.replaces === options.replaces);
        if (index >= 0) {
          const [dropped] = this.waiting.splice(index, 1);
          dropped?.reject(new Error(`RTSP ${dropped.method} superseded before it was sent`));
        }
      }
      if (options.urgent) {
        const firstOrdinary = this.waiting.findIndex((w) => !w.options.urgent);
        this.waiting.splice(firstOrdinary < 0 ? this.waiting.length : firstOrdinary, 0, entry);
      } else {
        this.waiting.push(entry);
      }
      this.pump();
    });
  }

  /** On a one-at-a-time connection: send the next waiting request if none is out. */
  private pump(): void {
    if (this.queue.length > 0 || this.closed || !this.socket) {
      return;
    }
    const next = this.waiting.shift();
    if (next) {
      this.send(next);
    }
  }

  private send(entry: Waiting): void {
    const socket = this.socket;
    if (!socket || this.closed) {
      entry.reject(new Error('RTSP connection is not open'));
      return;
    }
    const { method, options } = entry;
    const body = options.body ?? Buffer.alloc(0);
    const uri = options.uri ?? `rtsp://${this.host}/${this.sessionId}`;
    const cseq = ++this.cseq;

    const headers: Record<string, string> = {
      'User-Agent': USER_AGENT,
      CSeq: String(cseq),
      ...(options.headers ?? {}),
    };
    if (options.contentType) {
      headers['Content-Type'] = options.contentType;
    }
    headers['Content-Length'] = String(body.length);

    const headerText = Object.entries(headers)
      .map(([key, value]) => `${key}: ${value}`)
      .join('\r\n');
    const head = Buffer.from(`${method} ${uri} RTSP/1.0\r\n${headerText}\r\n\r\n`, 'utf8');
    const raw = Buffer.concat([head, body]);

    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const timer = setTimeout(() => {
      const index = this.queue.findIndex((pending) => pending.timer === timer);
      if (index >= 0) {
        this.queue.splice(index, 1);
      }
      entry.reject(new Error(`RTSP ${method} timed out after ${timeoutMs}ms`));
      this.pump();
    }, timeoutMs);
    this.queue.push({ cseq, resolve: entry.resolve, reject: entry.reject, timer });

    socket.write(this.hap ? this.hap.encrypt(raw) : raw);
  }

  public close(): void {
    this.closed = true;
    this.socket?.destroy();
    this.socket = null;
  }

  private onData(chunk: Buffer): void {
    let plain = chunk;
    if (this.hap) {
      plain = this.hap.decrypt(chunk);
      if (plain.length === 0) {
        return; // a partial HAP frame; the session buffers the remainder
      }
    }
    this.buffer = Buffer.concat([this.buffer, plain]);
    this.drain();
  }

  /** Pull every complete response out of the read buffer. */
  private drain(): void {
    for (;;) {
      const headerEnd = this.buffer.indexOf('\r\n\r\n');
      if (headerEnd < 0) {
        return;
      }
      const headerText = this.buffer.subarray(0, headerEnd).toString('utf8');
      const lines = headerText.split('\r\n');
      const statusLine = lines[0] ?? '';
      const match = /^\S+\s+(\d+)\s*(.*)$/.exec(statusLine);
      if (!match) {
        // Not a response — an event the receiver pushed at us. Drop the frame
        // rather than desyncing the parser.
        this.buffer = this.buffer.subarray(headerEnd + 4);
        continue;
      }

      const headers = new Map<string, string>();
      for (const line of lines.slice(1)) {
        const sep = line.indexOf(':');
        if (sep > 0) {
          headers.set(line.slice(0, sep).trim().toLowerCase(), line.slice(sep + 1).trim());
        }
      }
      const contentLength = Number(headers.get('content-length') ?? '0') || 0;
      const bodyStart = headerEnd + 4;
      if (this.buffer.length < bodyStart + contentLength) {
        return; // body still arriving
      }

      const body = Buffer.from(this.buffer.subarray(bodyStart, bodyStart + contentLength));
      this.buffer = this.buffer.subarray(bodyStart + contentLength);

      const pending = this.takePending(headers.get('cseq'));
      if (pending) {
        clearTimeout(pending.timer);
        pending.resolve({
          status: Number(match[1]),
          reason: match[2] ?? '',
          headers,
          body,
        });
      }
      if (this.options.oneAtATime) {
        this.pump();
      }
    }
  }

  /**
   * The request a response answers.
   *
   * By its CSeq, not by its place in line. A response that arrives after its
   * request already timed out would otherwise be handed to the next request
   * waiting — a volume change resolved with the answer to a metadata push — and
   * every reply after it would be one off for the rest of the session. A late
   * answer to a request nobody waits for any more is dropped. A receiver that
   * leaves CSeq out of its replies is answered in order, as before.
   */
  private takePending(cseqHeader: string | undefined): Pending | undefined {
    const cseq = cseqHeader === undefined ? Number.NaN : Number(cseqHeader);
    if (!Number.isInteger(cseq)) {
      return this.queue.shift();
    }
    const index = this.queue.findIndex((entry) => entry.cseq === cseq);
    if (index < 0) {
      return undefined;
    }
    return this.queue.splice(index, 1)[0];
  }

  private failAll(err: Error): void {
    while (this.queue.length > 0) {
      const pending = this.queue.shift() as Pending;
      clearTimeout(pending.timer);
      pending.reject(err);
    }
    while (this.waiting.length > 0) {
      (this.waiting.shift() as Waiting).reject(err);
    }
  }
}
