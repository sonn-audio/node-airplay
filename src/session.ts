/**
 * The AirPlay 2 session SETUP — the first encrypted exchange, which tells the
 * receiver who we are and, crucially, which clock its playback timeline will
 * follow.
 *
 * A receiver only slaves to a clock it finds in `timingPeerList`, and it cannot
 * anchor to its own, so the sender has to hold grandmaster and advertise its own
 * ClockID here. The same identity is used for the PTP engine's
 * `grandmasterIdentity`, so the two must be generated together — a session that
 * announces one ClockID and serves PTP under another looks healthy and renders
 * silence.
 */

import { randomUUID } from 'node:crypto';
import { connect, type Socket } from 'node:net';
import { parseBinaryPlist, type PlistValue } from './bplist.js';
import { buildBinaryPlist, PlistInt64 } from './bplistWriter.js';
import type { RtspConnection } from './rtsp.js';

const PLIST_CONTENT_TYPE = 'application/x-apple-binary-plist';

/** The 8-byte identity behind deviceID, macAddress and the PTP ClockID. */
export interface SenderIdentity {
  /** The raw 8 bytes. */
  bytes: Buffer;
  /** All 8 bytes, colon-separated — the `deviceID`. */
  deviceId: string;
  /** The first 6 bytes, colon-separated — the `macAddress`. */
  macAddress: string;
  /** The same 8 bytes as a 64-bit integer — the PTP clock identity. */
  clockId: bigint;
}

/** Build the sender identity from 8 bytes (random when not supplied). */
export function createIdentity(bytes: Buffer): SenderIdentity {
  if (bytes.length !== 8) {
    throw new Error('sender identity must be exactly 8 bytes');
  }
  const hex = (from: number, to: number): string =>
    [...bytes.subarray(from, to)].map((byte) => byte.toString(16).padStart(2, '0')).join(':');
  return {
    bytes: Buffer.from(bytes),
    deviceId: hex(0, 8),
    macAddress: hex(0, 6),
    clockId: bytes.readBigUInt64BE(0),
  };
}

export interface SessionSetupOptions {
  identity: SenderIdentity;
  /** Our address as the receiver must reach it — goes into the timing peer list. */
  localAddress: string;
  /** Name the receiver shows for this session. */
  name: string;
  /**
   * The clock the session timeline follows. Ours when we hold grandmaster,
   * which is the normal case; BMCA may hand it to the receiver instead.
   */
  timelineClockId: bigint;
  sessionUuid?: string;
  groupUuid?: string;
}

export interface SessionSetupResult {
  sessionUuid: string;
  groupUuid: string;
  /** TCP port the receiver opens for session events; 0 when it reports none. */
  eventPort: number;
  /** The parsed SETUP reply, for callers that want the rest of it. */
  response: { [key: string]: PlistValue };
}

function timingPeer(peerId: string, clockId: bigint, address: string): { [key: string]: PlistValue } {
  return {
    ID: peerId,
    DeviceType: 0,
    ClockID: new PlistInt64(clockId) as unknown as PlistValue,
    SupportsClockPortMatchingOverride: false,
    Addresses: [address],
  };
}

/**
 * Run the PTP-flavoured session SETUP over the encrypted control channel.
 *
 * :param rtsp: an encrypted connection (pairing already done).
 * :param sessionUrl: `rtsp://<our address>/<session id>` — note it names OUR
 *   address, not the device's, and stays the request target for the rest of the
 *   session including TEARDOWN.
 */
export async function setupSession(
  rtsp: RtspConnection,
  sessionUrl: string,
  options: SessionSetupOptions,
): Promise<SessionSetupResult> {
  const sessionUuid = options.sessionUuid ?? randomUUID().toUpperCase();
  const groupUuid = options.groupUuid ?? randomUUID().toUpperCase();
  const peerId = randomUUID().toUpperCase();
  const peer = timingPeer(peerId, options.timelineClockId, options.localAddress);

  const body = buildBinaryPlist({
    timingProtocol: 'PTP',
    deviceID: options.identity.deviceId,
    sessionUUID: sessionUuid,
    name: options.name,
    macAddress: options.identity.macAddress,
    groupUUID: groupUuid,
    groupContainsGroupLeader: false,
    timingPeerInfo: peer,
    timingPeerList: [peer],
  });

  const response = await rtsp.request('SETUP', {
    uri: sessionUrl,
    contentType: PLIST_CONTENT_TYPE,
    body,
  });
  if (response.status !== 200) {
    throw new Error(`session SETUP failed with status ${response.status}`);
  }

  let parsed: { [key: string]: PlistValue } = {};
  if (response.body.length > 0) {
    const value = parseBinaryPlist(response.body);
    if (value !== null && typeof value === 'object' && !Array.isArray(value) && !Buffer.isBuffer(value)) {
      parsed = value as { [key: string]: PlistValue };
    }
  }
  const eventPort = typeof parsed['eventPort'] === 'number' ? (parsed['eventPort'] as number) : 0;

  return { sessionUuid, groupUuid, eventPort, response: parsed };
}

/**
 * The reverse TCP connection to the receiver's event port. Nothing is written
 * on it — the receiver pushes session events — but it must exist and stay open:
 * the reference sender opens it right after the session SETUP and holds it for
 * the life of the session.
 */
export async function connectEvents(host: string, port: number, timeoutMs = 3000): Promise<Socket> {
  return new Promise<Socket>((resolve, reject) => {
    const socket = connect({ host, port });
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error(`events connect to ${host}:${port} timed out`));
    }, timeoutMs);
    socket.once('connect', () => {
      clearTimeout(timer);
      socket.setNoDelay(true);
      socket.on('error', () => {
        /* session health is judged on the control channel, not here */
      });
      resolve(socket);
    });
    socket.once('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

/** How often the keepalive POST goes out. */
export const FEEDBACK_INTERVAL_MS = 2000;

/**
 * Start the `POST /feedback` keepalive. **This is what resets the receiver's
 * idle timer.** Without it an Apple receiver drops the timeline after about
 * half a minute and goes quiet while the sender keeps streaming happily, with
 * nothing in any log to show for it — measured: PTP Delay_Req probes stop at
 * ~30 s and the audio dies with them.
 *
 * :returns: a stop function.
 */
export function startFeedback(
  rtsp: RtspConnection,
  onResult?: (status: number | null, err?: Error) => void,
): () => void {
  const timer = setInterval(() => {
    void rtsp
      .request('POST', { uri: '/feedback', timeoutMs: FEEDBACK_INTERVAL_MS })
      .then((res) => onResult?.(res.status))
      .catch((err) => onResult?.(null, err instanceof Error ? err : new Error(String(err))));
  }, FEEDBACK_INTERVAL_MS);
  return () => clearInterval(timer);
}
