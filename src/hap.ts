/**
 * HomeKit Accessory Protocol as an AirPlay 2 sender needs it: transient
 * pair-setup (no credentials, no PIN prompt) and the ChaCha20-Poly1305 framing
 * that every RTSP byte rides in afterwards.
 *
 * Ported from cliairplay's `ap2_hap.c`. Transient pairing is the route for a
 * receiver that advertises pairing without the PIN (0x8) or legacy (0x200)
 * status flag — measured to include current HomePods, which complete it
 * without any user interaction.
 */

import { createCipheriv, createDecipheriv, hkdfSync, timingSafeEqual } from 'node:crypto';
import { parseTlv, TLV, TlvWriter, tlvErrorText } from './tlv8.js';
import { srpClientCompute, TRANSIENT_PIN } from './srp.js';
import type { RtspConnection } from './rtsp.js';

/** kTLVFlag transient, sent in the M1 Flags TLV. */
const TRANSIENT_FLAG = 0x10;
const MAX_FRAME_SIZE = 1024;
const TAG_SIZE = 16;
const NONCE_SIZE = 12;

/** 4 zero bytes followed by an 8-byte little-endian counter. */
function makeNonce(counter: bigint): Buffer {
  const nonce = Buffer.alloc(NONCE_SIZE);
  nonce.writeBigUInt64LE(counter, 4);
  return nonce;
}

function hkdfSha512(secret: Buffer, salt: string, info: string, length: number): Buffer {
  return Buffer.from(hkdfSync('sha512', secret, Buffer.from(salt, 'utf8'), Buffer.from(info, 'utf8'), length));
}

/**
 * An established HAP session: the two directional channel keys plus their nonce
 * counters, and the shared secret the audio cipher is later derived from.
 */
export class HapSession {
  private writeCounter = 0n;
  private readCounter = 0n;
  /** Bytes of an incomplete inbound frame, carried to the next read. */
  private readBuffer: Buffer = Buffer.alloc(0);

  constructor(
    private readonly writeKey: Buffer,
    private readonly readKey: Buffer,
    /**
     * For transient pairing this is the SRP session key; after pair-verify it is
     * the X25519 shared secret. Either way it is what the audio keys derive from.
     */
    public readonly sharedSecret: Buffer,
  ) {}

  /**
   * Wrap plaintext in HAP frames: `[2-byte LE length][ciphertext][16-byte tag]`,
   * at most 1024 plaintext bytes per frame, with the length field as AAD.
   */
  public encrypt(plain: Buffer): Buffer {
    const frames: Buffer[] = [];
    for (let offset = 0; offset < plain.length; offset += MAX_FRAME_SIZE) {
      const chunk = plain.subarray(offset, offset + MAX_FRAME_SIZE);
      const lengthField = Buffer.alloc(2);
      lengthField.writeUInt16LE(chunk.length, 0);

      const cipher = createCipheriv('chacha20-poly1305', this.writeKey, makeNonce(this.writeCounter++), {
        authTagLength: TAG_SIZE,
      });
      cipher.setAAD(lengthField, { plaintextLength: chunk.length });
      const body = Buffer.concat([cipher.update(chunk), cipher.final()]);
      frames.push(lengthField, body, Buffer.from(cipher.getAuthTag()));
    }
    return Buffer.concat(frames);
  }

  /**
   * Unwrap as many complete frames as the input holds. A partial trailing frame
   * is kept for the next call, so this is safe to feed raw socket chunks.
   */
  public decrypt(data: Buffer): Buffer {
    this.readBuffer = this.readBuffer.length === 0 ? data : Buffer.concat([this.readBuffer, data]);
    const out: Buffer[] = [];

    for (;;) {
      if (this.readBuffer.length < 2) {
        break;
      }
      const length = this.readBuffer.readUInt16LE(0);
      const total = 2 + length + TAG_SIZE;
      if (this.readBuffer.length < total) {
        break;
      }
      const lengthField = this.readBuffer.subarray(0, 2);
      const body = this.readBuffer.subarray(2, 2 + length);
      const tag = this.readBuffer.subarray(2 + length, total);

      const decipher = createDecipheriv('chacha20-poly1305', this.readKey, makeNonce(this.readCounter++), {
        authTagLength: TAG_SIZE,
      });
      decipher.setAAD(lengthField, { plaintextLength: length });
      decipher.setAuthTag(tag);
      out.push(decipher.update(body));
      decipher.final(); // throws on a bad tag — a desynced channel must not pass silently

      this.readBuffer = this.readBuffer.subarray(total);
    }
    return out.length === 0 ? Buffer.alloc(0) : Buffer.concat(out);
  }
}

export class HapError extends Error {
  constructor(
    message: string,
    public readonly httpStatus = 0,
    public readonly tlvError = 0,
  ) {
    super(message);
    this.name = 'HapError';
  }
}

async function postPairSetup(rtsp: RtspConnection, body: Buffer, label: string): Promise<Buffer> {
  const response = await rtsp.request('POST', {
    uri: '/pair-setup',
    headers: { 'X-Apple-HKP': '4' },
    contentType: 'application/octet-stream',
    body,
  });
  if (response.status !== 200) {
    const hint = response.status === 470 ? ' — device requires full HomeKit pairing' : '';
    throw new HapError(`${label} rejected (status ${response.status})${hint}`, response.status);
  }
  return response.body;
}

function assertNoTlvError(tlv: Map<number, Buffer>, label: string): void {
  const error = tlv.get(TLV.ERROR);
  if (error && error.length > 0) {
    const code = error[0] as number;
    throw new HapError(`${label}: ${tlvErrorText(code)}`, 0, code);
  }
}

/**
 * Run transient pair-setup over an open (still plaintext) RTSP connection and
 * return the session that encrypts everything from here on.
 *
 * :param secret: device password when it has one; otherwise the fixed transient
 *   PIN every credential-less receiver expects.
 */
export async function pairSetupTransient(
  rtsp: RtspConnection,
  secret = TRANSIENT_PIN,
): Promise<HapSession> {
  // M1: state=1, method=pair-setup, transient flag.
  const m1 = new TlvWriter()
    .addByte(TLV.STATE, 0x01)
    .addByte(TLV.METHOD, 0x00)
    .addByte(TLV.FLAGS, TRANSIENT_FLAG)
    .build();
  const m2 = parseTlv(await postPairSetup(rtsp, m1, 'pair-setup M1'));
  assertNoTlvError(m2, 'pair-setup M2');

  const state = m2.get(TLV.STATE);
  const salt = m2.get(TLV.SALT);
  const serverPublicKey = m2.get(TLV.PUBLIC_KEY);
  if (state?.[0] !== 0x02 || !salt || salt.length !== 16 || !serverPublicKey || serverPublicKey.length === 0) {
    throw new HapError(
      `invalid pair-setup M2 (state=${state?.[0] ?? -1}, salt=${salt?.length ?? -1}, B=${serverPublicKey?.length ?? -1})`,
    );
  }

  const srp = srpClientCompute(salt, serverPublicKey, secret);

  // M3: state=3, our public key A, our proof M1.
  const m3 = new TlvWriter()
    .addByte(TLV.STATE, 0x03)
    .add(TLV.PUBLIC_KEY, srp.publicKey)
    .add(TLV.PROOF, srp.proof)
    .build();
  const m4 = parseTlv(await postPairSetup(rtsp, m3, 'pair-setup M3'));
  assertNoTlvError(m4, 'pair-setup M4');

  const m4State = m4.get(TLV.STATE);
  const serverProof = m4.get(TLV.PROOF);
  if (m4State?.[0] !== 0x04 || !serverProof || serverProof.length !== srp.expectedServerProof.length) {
    throw new HapError(
      `invalid pair-setup M4 (state=${m4State?.[0] ?? -1}, proof=${serverProof?.length ?? -1})`,
    );
  }
  // A mismatch means both sides ran SRP with different secrets — i.e. the PIN
  // or password is not what this receiver expects.
  if (!timingSafeEqual(serverProof, srp.expectedServerProof)) {
    throw new HapError('server SRP proof mismatch in M4 (wrong PIN or password)');
  }

  // Channel keys derive from the FULL 64-byte SRP session key.
  const writeKey = hkdfSha512(srp.sessionKey, 'Control-Salt', 'Control-Write-Encryption-Key', 32);
  const readKey = hkdfSha512(srp.sessionKey, 'Control-Salt', 'Control-Read-Encryption-Key', 32);
  // The audio key takes the first 32 bytes, the same role the X25519 shared
  // secret plays after pair-verify.
  const sharedSecret = srp.sessionKey.subarray(0, 32);

  return new HapSession(writeKey, readKey, sharedSecret);
}
