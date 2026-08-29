/**
 * Client side of SRP-6a (SHA-512, RFC 5054 3072-bit group) as HAP pair-setup
 * uses it. Ported from cliairplay's `srp_client_compute` (ap2_hap.c), whose
 * byte conventions were verified against real receivers:
 *
 *   k = SHA512(PAD(N) || PAD(g)) and u = SHA512(PAD(A) || PAD(B)), both padded
 *   to the 384-byte modulus size; the values hashed into x, K, M1 and HAMK use
 *   MINIMAL-length big-endian encoding, and the salt goes in as its raw TLV
 *   bytes. Getting either convention wrong still produces a valid-looking
 *   exchange that fails only at the server-proof compare, so they matter.
 *
 * BigInt is used rather than a bignum addon: pair-setup runs two modular
 * exponentiations per session, once at connect, so the cost is irrelevant.
 */

import { createHash, randomBytes } from 'node:crypto';

const N_HEX =
  'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437' +
  '4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05' +
  '98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' +
  'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33' +
  'A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864' +
  'D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF';

const N = BigInt(`0x${N_HEX}`);
const G = 5n;
const N_BYTES = 384;
const HASH_LEN = 64; // SHA-512
const USERNAME = 'Pair-Setup';

/** The fixed secret every credential-less receiver expects for transient pairing. */
export const TRANSIENT_PIN = '3939';

export interface SrpClientResult {
  /** Our public key A, minimal-length big-endian (goes in the M3 TLV). */
  publicKey: Buffer;
  /** Client proof M1 (goes in the M3 TLV). */
  proof: Buffer;
  /** The server proof we expect back in M4; a mismatch means a wrong secret. */
  expectedServerProof: Buffer;
  /** Session key K = SHA512(S) — the input to the channel key derivation. */
  sessionKey: Buffer;
}

function sha512(...parts: Buffer[]): Buffer {
  const hash = createHash('sha512');
  for (const part of parts) {
    hash.update(part);
  }
  return hash.digest();
}

/** Big-endian encoding, minimal length (no leading zero byte). */
function toBuffer(value: bigint): Buffer {
  let hex = value.toString(16);
  if (hex.length % 2 === 1) {
    hex = `0${hex}`;
  }
  return Buffer.from(hex, 'hex');
}

/** Big-endian encoding, left-padded to the modulus size. */
function toPadded(value: bigint, length: number): Buffer {
  const raw = toBuffer(value);
  if (raw.length > length) {
    throw new Error(`SRP value wider than ${length} bytes`);
  }
  return Buffer.concat([Buffer.alloc(length - raw.length), raw]);
}

function toBigInt(buf: Buffer): bigint {
  return buf.length === 0 ? 0n : BigInt(`0x${buf.toString('hex')}`);
}

/** modular exponentiation (square-and-multiply). */
function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  let result = 1n;
  let b = base % modulus;
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) {
      result = (result * b) % modulus;
    }
    b = (b * b) % modulus;
    e >>= 1n;
  }
  return result;
}

/**
 * Run the client half of SRP-6a against the device's salt and public key B.
 *
 * :param salt: the 16-byte salt from the M2 TLV, raw.
 * :param serverPublicKey: the device's public key B from the M2 TLV.
 * :param secret: the shared secret — {@link TRANSIENT_PIN} unless the device
 *   has a password, which replaces it.
 */
export function srpClientCompute(
  salt: Buffer,
  serverPublicKey: Buffer,
  secret: string,
): SrpClientResult {
  const B = toBigInt(serverPublicKey);
  if (B % N === 0n) {
    throw new Error('SRP: server public key B is invalid (0 mod N)');
  }

  // A = g^a mod N, with a 256-bit random private value.
  const a = toBigInt(randomBytes(32));
  const A = modPow(G, a, N);
  const aPub = toBuffer(A);

  // k and u are hashed over MODULUS-PADDED values.
  const k = toBigInt(sha512(toPadded(N, N_BYTES), toPadded(G, N_BYTES)));
  const u = toBigInt(sha512(toPadded(A, N_BYTES), toPadded(B, N_BYTES)));
  if (u === 0n) {
    throw new Error('SRP: scrambling parameter u is zero');
  }

  // x = SHA512(salt || SHA512("Pair-Setup:<secret>"))
  const x = toBigInt(sha512(salt, sha512(Buffer.from(`${USERNAME}:${secret}`, 'utf8'))));

  // S = (B - k * g^x) ^ (a + u*x) mod N, with the base normalised into [0, N).
  let base = (B - ((k * modPow(G, x, N)) % N)) % N;
  if (base < 0n) {
    base += N;
  }
  const S = modPow(base, a + u * x, N);
  const sessionKey = sha512(toBuffer(S));

  // M1 = SHA512((SHA512(N) xor SHA512(g)) || SHA512(username) || salt || A || B || K)
  const hashN = sha512(toBuffer(N));
  const hashG = sha512(toBuffer(G));
  const xored = Buffer.alloc(HASH_LEN);
  for (let i = 0; i < HASH_LEN; i++) {
    xored[i] = (hashN[i] as number) ^ (hashG[i] as number);
  }
  const proof = sha512(
    xored,
    sha512(Buffer.from(USERNAME, 'utf8')),
    salt,
    aPub,
    toBuffer(B),
    sessionKey,
  );

  // HAMK = SHA512(A || M1 || K)
  const expectedServerProof = sha512(aPub, proof, sessionKey);

  return { publicKey: aPub, proof, expectedServerProof, sessionKey };
}
