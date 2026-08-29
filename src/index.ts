/**
 * @sonn-audio/node-airplay — an AirPlay sender for Node.js, in TypeScript.
 *
 * The protocol logic follows Music Assistant's `cliairplay` (Apache-2.0), which
 * encodes years of measurements against real receivers; this is a port of that
 * behaviour, not a fresh reading of the protocol.
 *
 * Status: connect, device capability read and transient HAP pairing are in
 * place. Session SETUP, PTP timing and the audio stream follow.
 */

import { randomBytes } from 'node:crypto';
import { connectEvents, createIdentity, setupSession, startFeedback, type SenderIdentity, type SessionSetupResult } from './session.js';
import { parseBinaryPlist, type PlistValue } from './bplist.js';
import { pairSetupTransient, type HapSession } from './hap.js';
import { RtspConnection } from './rtsp.js';

export { parseBinaryPlist, type PlistValue } from './bplist.js';
export { buildBinaryPlist, PlistInt64, type PlistInput } from './bplistWriter.js';
export { HapError, HapSession } from './hap.js';
export { RtspConnection } from './rtsp.js';
export { TRANSIENT_PIN } from './srp.js';
export { PtpEngine, type PtpEngineOptions } from './ptp.js';
export { encodeAlacPacket, type AlacEncoderOptions } from './alac.js';
export {
  setupRealtimeStream, RealtimeSender, setVolume, volumeToDb, setMetadata, setArtwork,
  FRAMES_PER_PACKET, AUDIO_FORMAT_ALAC_44100_16_2,
  type StreamSetupResult, type RealtimeSenderOptions,
} from './stream.js';
export { connectEvents, startFeedback, FEEDBACK_INTERVAL_MS, createIdentity, setupSession, type SenderIdentity, type SessionSetupResult } from './session.js';

/** Feature bits that decide the route (see the mDNS `features`/`ft` TXT field). */
export const FEATURE = {
  /** SupportsUnifiedMediaControl → the device speaks AirPlay 2. */
  UNIFIED_MEDIA_CONTROL: 38n,
  /** SupportsBufferedAudio → the type-103 stream is available. */
  BUFFERED_AUDIO: 40n,
  /** SupportsPTP → PTP timing rather than the NTP responder. */
  PTP: 41n,
  /** SupportsHKPairingAndAccessControl. */
  HK_PAIRING: 46n,
  /** SupportsCoreUtilsPairingAndEncryption → AirPlay 2, pairing-capable. */
  COREUTILS_PAIRING: 48n,
} as const;

/** Status flags (`flags`/`sf` TXT field) that force a user-visible pairing. */
export const STATUS_FLAG = {
  PIN_REQUIRED: 0x8,
  LEGACY_PAIRING: 0x200,
} as const;

export interface DeviceTxt {
  /** `features=0xLOW,0xHIGH` (or `ft=`), as advertised. */
  features?: string;
  /** `flags=` (or `sf=`), as advertised. */
  flags?: string;
  /** `model=` (or `am=`), e.g. `AudioAccessory5,1`. */
  model?: string;
}

export interface DeviceCapabilities {
  features: bigint;
  flags: number;
  model: string;
  supportsAirPlay2: boolean;
  supportsPtp: boolean;
  supportsBufferedAudio: boolean;
  /**
   * True when the device forces a PIN/legacy pairing flow, i.e. transient
   * pairing will not do and stored credentials are required. Current HomePods
   * are false here: they take transient pairing with no user interaction.
   */
  requiresUserPairing: boolean;
  /** Apple receivers get the realtime lane; buffered is denied on measurement. */
  isAppleReceiver: boolean;
}

const APPLE_MODEL_PREFIXES = ['AppleTV', 'AudioAccessory', 'iPhone', 'iPad', 'iPod', 'Mac'];

/** Parse the two-word `0xLOW,0xHIGH` feature form into one 64-bit value. */
export function parseFeatures(value: string | undefined): bigint {
  if (!value) {
    return 0n;
  }
  const [low, high] = value.split(',');
  const lowBits = BigInt(low?.trim() ?? '0');
  const highBits = high ? BigInt(high.trim()) : 0n;
  return (highBits << 32n) | lowBits;
}

/** Read a device's capabilities out of its mDNS TXT record. */
export function readCapabilities(txt: DeviceTxt): DeviceCapabilities {
  const features = parseFeatures(txt.features);
  const flags = txt.flags ? Number(txt.flags) : 0;
  const model = txt.model ?? '';
  const has = (bit: bigint): boolean => ((features >> bit) & 1n) === 1n;

  return {
    features,
    flags,
    model,
    supportsAirPlay2: has(FEATURE.UNIFIED_MEDIA_CONTROL) || has(FEATURE.COREUTILS_PAIRING),
    supportsPtp: has(FEATURE.PTP),
    supportsBufferedAudio: has(FEATURE.BUFFERED_AUDIO),
    requiresUserPairing: (flags & (STATUS_FLAG.PIN_REQUIRED | STATUS_FLAG.LEGACY_PAIRING)) !== 0,
    isAppleReceiver: APPLE_MODEL_PREFIXES.some((prefix) => model.startsWith(prefix)),
  };
}

export interface ConnectOptions {
  host: string;
  /** AirPlay 2 receivers listen on 7000. */
  port?: number;
  /** Device password, when it has one; otherwise transient pairing is used. */
  password?: string;
  timeoutMs?: number;
  /**
   * Stable 8-byte sender identity (deviceID / macAddress / PTP ClockID). Pass a
   * value derived from the host so a receiver recognises us across restarts;
   * a random one is generated otherwise.
   */
  identity?: Buffer;
  /** Name the receiver shows for the session. */
  name?: string;
  /**
   * Session-level diagnostics: the keepalive's result and the moment the
   * receiver drops the control channel. Without this a dead session looks
   * exactly like a healthy one from the sending side.
   */
  onEvent?: (event: string) => void;
}

/**
 * A control connection to an AirPlay 2 receiver: paired, encrypted, and ready
 * for the stream setup that follows.
 */
export class AirPlayConnection {
  private constructor(
    public readonly rtsp: RtspConnection,
    public readonly hap: HapSession,
    /** The plaintext `GET /info` reply read before pairing. */
    public readonly info: { [key: string]: PlistValue },
    public readonly identity: SenderIdentity,
    /** `rtsp://<our address>/<session id>` — the target for every later request. */
    public readonly sessionUrl: string,
    private readonly host: string,
    private readonly onEvent?: (event: string) => void,
  ) {}

  private events: import('node:net').Socket | null = null;
  private stopFeedback: (() => void) | null = null;

  /**
   * Run the session SETUP. The timeline follows our own clock, so the PTP
   * engine must be serving under {@link identity}'s clockId by the time the
   * receiver starts probing it.
   */
  public async setupSession(name = 'sonn'): Promise<SessionSetupResult> {
    const result = await setupSession(this.rtsp, this.sessionUrl, {
      identity: this.identity,
      localAddress: this.rtsp.localAddress(),
      name,
      timelineClockId: this.identity.clockId,
    });
    // Both of these keep the session alive, and neither announces itself when
    // missing: the receiver just stops following the timeline after ~30 s.
    if (result.eventPort > 0) {
      try {
        this.events = await connectEvents(this.host, result.eventPort);
      } catch {
        /* best effort — the reference sender warns and carries on as well */
      }
    }
    this.stopFeedback = startFeedback(this.rtsp, (status, err) => {
      if (err) {
        this.onEvent?.(`feedback failed: ${err.message}`);
      } else if (status !== 200) {
        this.onEvent?.(`feedback returned ${status}`);
      }
    });
    return result;
  }

  /**
   * Open the control channel: read the device's `/info`, run transient HAP
   * pair-setup, and switch the connection to encrypted framing.
   */
  public static async open(options: ConnectOptions): Promise<AirPlayConnection> {
    const sessionId = randomBytes(4).readUInt32BE(0).toString();
    const rtsp = new RtspConnection(options.host, options.port ?? 7000, sessionId, (reason) =>
      options.onEvent?.(reason),
    );
    await rtsp.connect(options.timeoutMs);
    try {
      const identity = createIdentity(options.identity ?? randomBytes(8));
      const info = await AirPlayConnection.readInfo(rtsp);
      const hap = await pairSetupTransient(rtsp, options.password);
      rtsp.enableEncryption(hap);
      // The session URL names OUR address, not the device's.
      const sessionUrl = `rtsp://${rtsp.localAddress()}/${sessionId}`;
      return new AirPlayConnection(rtsp, hap, info, identity, sessionUrl, options.host, options.onEvent);
    } catch (err) {
      rtsp.close();
      throw err;
    }
  }

  /**
   * Read `GET /info`. Works both before pairing (plaintext) and after, where a
   * successful reply is the proof that the encrypted channel is in step.
   */
  public static async readInfo(rtsp: RtspConnection): Promise<{ [key: string]: PlistValue }> {
    const response = await rtsp.request('GET', { uri: '/info' });
    if (response.status !== 200) {
      throw new Error(`GET /info failed with status ${response.status}`);
    }
    const value = parseBinaryPlist(response.body);
    if (typeof value !== 'object' || value === null || Array.isArray(value) || Buffer.isBuffer(value)) {
      throw new Error('GET /info did not return a plist dictionary');
    }
    return value as { [key: string]: PlistValue };
  }

  /** Re-read `/info` over the (now encrypted) channel. */
  public async refreshInfo(): Promise<{ [key: string]: PlistValue }> {
    return AirPlayConnection.readInfo(this.rtsp);
  }

  public close(): void {
    this.stopFeedback?.();
    this.stopFeedback = null;
    this.events?.destroy();
    this.events = null;
    this.rtsp.close();
  }
}
