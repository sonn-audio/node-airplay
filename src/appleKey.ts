import { constants, privateDecrypt, privateEncrypt } from 'node:crypto';

/**
 * The RSA key every AirPlay 1 sender assumes a receiver holds.
 *
 * A sender wraps its AES audio key in the AirPort Express public key and the
 * protocol has no way to negotiate a different one, so a receiver either holds
 * this exact private key or cannot read a single audio packet. That is why a
 * receiver advertising `et=0` gets abandoned right after OPTIONS: an iPhone
 * will not send audio it cannot encrypt.
 *
 * Every third-party RAOP receiver ships it for the same reason -- shairport-sync
 * and libraop among them -- and it has been public for well over a decade.
 */
const PRIVATE_KEY =
  '-----BEGIN RSA PRIVATE KEY-----\n' +
  'MIIEpQIBAAKCAQEA59dE8qLieItsH1WgjrcFRKj6eUWqi+bGLOX1HL3U3GhC/j0Qg90u3sG/1CUt\n' +
  'wC5vOYvfDmFI6oSFXi5ELabWJmT2dKHzBJKa3k9ok+8t9ucRqMd6DZHJ2YCCLlDRKSKv6kDqnw4U\n' +
  'wPdpOMXziC/AMj3Z/lUVX1G7WSHCAWKf1zNS1eLvqr+boEjXuBOitnZ/bDzPHrTOZz0Dew0uowxf\n' +
  '/+sG+NCK3eQJVxqcaJ/vEHKIVd2M+5qL71yJQ+87X6oV3eaYvt3zWZYD6z5vYTcrtij2VZ9Zmni/\n' +
  'UAaHqn9JdsBWLUEpVviYnhimNVvYFZeCXg/IdTQ+x4IRdiXNv5hEewIDAQABAoIBAQDl8Axy9XfW\n' +
  'BLmkzkEiqoSwF0PsmVrPzH9KsnwLGH+QZlvjWd8SWYGN7u1507HvhF5N3drJoVU3O14nDY4TFQAa\n' +
  'LlJ9VM35AApXaLyY1ERrN7u9ALKd2LUwYhM7Km539O4yUFYikE2nIPscEsA5ltpxOgUGCY7b7ez5\n' +
  'NtD6nL1ZKauw7aNXmVAvmJTcuPxWmoktF3gDJKK2wxZuNGcJE0uFQEG4Z3BrWP7yoNuSK3dii2jm\n' +
  'lpPHr0O/KnPQtzI3eguhe0TwUem/eYSdyzMyVx/YpwkzwtYL3sR5k0o9rKQLtvLzfAqdBxBurciz\n' +
  'aaA/L0HIgAmOit1GJA2saMxTVPNhAoGBAPfgv1oeZxgxmotiCcMXFEQEWflzhWYTsXrhUIuz5jFu\n' +
  'a39GLS99ZEErhLdrwj8rDDViRVJ5skOp9zFvlYAHs0xh92ji1E7V/ysnKBfsMrPkk5KSKPrnjndM\n' +
  'oPdevWnVkgJ5jxFuNgxkOLMuG9i53B4yMvDTCRiIPMQ++N2iLDaRAoGBAO9v//mU8eVkQaoANf0Z\n' +
  'oMjW8CN4xwWA2cSEIHkd9AfFkftuv8oyLDCG3ZAf0vrhrrtkrfa7ef+AUb69DNggq4mHQAYBp7L+\n' +
  'k5DKzJrKuO0r+R0YbY9pZD1+/g9dVt91d6LQNepUE/yY2PP5CNoFmjedpLHMOPFdVgqDzDFxU8hL\n' +
  'AoGBANDrr7xAJbqBjHVwIzQ4To9pb4BNeqDndk5Qe7fT3+/H1njGaC0/rXE0Qb7q5ySgnsCb3DvA\n' +
  'cJyRM9SJ7OKlGt0FMSdJD5KG0XPIpAVNwgpXXH5MDJg09KHeh0kXo+QA6viFBi21y340NonnEfdf\n' +
  '54PX4ZGS/Xac1UK+pLkBB+zRAoGAf0AY3H3qKS2lMEI4bzEFoHeK3G895pDaK3TFBVmD7fV0Zhov\n' +
  '17fegFPMwOII8MisYm9ZfT2Z0s5Ro3s5rkt+nvLAdfC/PYPKzTLalpGSwomSNYJcB9HNMlmhkGzc\n' +
  '1JnLYT4iyUyx6pcZBmCd8bD0iwY/FzcgNDaUmbX9+XDvRA0CgYEAkE7pIPlE71qvfJQgoA9em0gI\n' +
  'LAuE4Pu13aKiJnfft7hIjbK+5kyb3TysZvoyDnb3HOKvInK7vXbKuU4ISgxB2bB3HcYzQMGsz1qJ\n' +
  '2gG0N5hvJpzwwhbhXqFKA4zaaSrw622wDniAK5MlIE0tIAKKP4yxNGjoD2QYjhBGuhvkWKY=\n' +
  '-----END RSA PRIVATE KEY-----\n';

/** Unwrap an `rsaaeskey` from the SDP into the 16-byte AES key. */
export function decryptAesKey(wrapped: Buffer): Buffer {
  return privateDecrypt({ key: PRIVATE_KEY, padding: constants.RSA_PKCS1_OAEP_PADDING }, wrapped);
}

/**
 * Sign an `Apple-Challenge` into the `Apple-Response` header value.
 *
 * The signed blob is the challenge followed by our address and MAC, zero-filled
 * to 32 bytes. The sender rebuilds it from what it knows about us, so both
 * halves have to agree byte for byte.
 */
export function answerChallenge(challenge: Buffer, localAddress: string, mac: Buffer): string {
  const data = Buffer.alloc(32);
  const used = challenge.copy(data, 0, 0, Math.min(challenge.length, 32 - 10));
  const octets = localAddress.split('.');
  if (octets.length === 4) {
    Buffer.from(octets.map((o) => Number(o) & 0xff)).copy(data, used);
    mac.copy(data, used + 4, 0, 6);
  } else {
    mac.copy(data, used, 0, 6);
  }
  const signed = privateEncrypt({ key: PRIVATE_KEY, padding: constants.RSA_PKCS1_PADDING }, data);
  return signed.toString('base64').replace(/=+$/, '');
}
