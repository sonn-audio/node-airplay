import { deepStrictEqual, ok, strictEqual, throws } from 'node:assert/strict';
import { test } from 'node:test';
import { parseTlv, TLV, TlvWriter } from './tlv8.js';
import { parseBinaryPlist } from './bplist.js';
import { buildBinaryPlist, PlistInt64 } from './bplistWriter.js';
import { srpClientCompute, TRANSIENT_PIN } from './srp.js';
import { encodeAlacPacket } from './alac.js';
import { volumeToDb } from './stream.js';

// --- TLV8 -------------------------------------------------------------------

test('TLV8 splits a value over 255 bytes and reads it back whole', () => {
  // The SRP public keys are 384 bytes, so fragmentation is the normal case here,
  // not an edge case: a reader that takes only the first fragment gets a key
  // that is silently 255 bytes long.
  const key = Buffer.alloc(384, 0xab);
  const encoded = new TlvWriter().addByte(TLV.STATE, 3).add(TLV.PUBLIC_KEY, key).build();

  strictEqual(encoded[0], TLV.STATE);
  // state(tag + length + value) + first fragment(2 + 255) + second fragment(2 + 129)
  strictEqual(encoded.length, 3 + 257 + 131);

  const parsed = parseTlv(encoded);
  strictEqual(parsed.get(TLV.STATE)?.[0], 3);
  deepStrictEqual(parsed.get(TLV.PUBLIC_KEY), key);
});

test('TLV8 reads an empty value and a truncated tail without throwing', () => {
  const parsed = parseTlv(new TlvWriter().add(TLV.ERROR, Buffer.alloc(0)).build());
  strictEqual(parsed.get(TLV.ERROR)?.length, 0);
  // A short read must stop, not misinterpret the remainder as a new entry.
  deepStrictEqual([...parseTlv(Buffer.from([TLV.SALT, 16, 1, 2, 3])).keys()], []);
});

// --- binary plist -----------------------------------------------------------

test('a binary plist round-trips the shapes the AirPlay SETUPs use', () => {
  const source = {
    timingProtocol: 'PTP',
    groupContainsGroupLeader: false,
    isMedia: true,
    spf: 352,
    sr: 44100,
    audioFormat: 1 << 18,
    shk: Buffer.alloc(32, 7),
    timingPeerList: [
      {
        ID: 'B1E5A9C0-1111-2222-3333-444455556666',
        DeviceType: 0,
        Addresses: ['192.168.1.209'],
      },
    ],
  };
  const parsed = parseBinaryPlist(buildBinaryPlist(source)) as Record<string, unknown>;
  deepStrictEqual(parsed, source);
});

test('a 64-bit ClockID survives as the value it went in as', () => {
  // Written as a signed 64-bit int; the top bit set is the case that turns into
  // a negative number if the width is guessed from the magnitude instead.
  const clockId = 0xf4a1b2c3d4e5f607n;
  const body = { ClockID: new PlistInt64(clockId) };
  const parsed = parseBinaryPlist(buildBinaryPlist(body)) as { ClockID: bigint | number };
  strictEqual(BigInt.asUintN(64, BigInt(parsed.ClockID)), clockId);
});

test('a plist with more than fourteen entries still parses', () => {
  // Past 14 the count no longer fits the marker nibble and moves to a trailing
  // integer, which is a different code path in both directions.
  const wide: Record<string, number> = {};
  for (let i = 0; i < 40; i++) {
    wide[`key${i}`] = i;
  }
  deepStrictEqual(parseBinaryPlist(buildBinaryPlist(wide)), wide);
});

test('a body that is not a plist is rejected rather than half-read', () => {
  throws(() => parseBinaryPlist(Buffer.alloc(64)), /bplist00/);
});

// --- SRP --------------------------------------------------------------------

test('SRP-6a produces a stable exchange for a fixed private key', () => {
  const salt = Buffer.from('0102030405060708090a0b0c0d0e0f10', 'hex');
  const serverPublicKey = Buffer.alloc(384, 0x42);
  const privateKey = Buffer.alloc(32, 0x11);

  const first = srpClientCompute(salt, serverPublicKey, TRANSIENT_PIN, privateKey);
  const second = srpClientCompute(salt, serverPublicKey, TRANSIENT_PIN, privateKey);
  deepStrictEqual(first.proof, second.proof);
  deepStrictEqual(first.sessionKey, second.sessionKey);

  strictEqual(first.sessionKey.length, 64);
  strictEqual(first.proof.length, 64);
  strictEqual(first.expectedServerProof.length, 64);
  ok(first.publicKey.length <= 384);

  // A different secret must not land on the same proof — that is exactly what a
  // wrong PIN is, and the server proof compare is what catches it.
  const other = srpClientCompute(salt, serverPublicKey, '1234', privateKey);
  ok(!other.proof.equals(first.proof));
});

test('SRP rejects a server public key that is zero mod N', () => {
  throws(
    () => srpClientCompute(Buffer.alloc(16), Buffer.alloc(384), TRANSIENT_PIN),
    /invalid/,
  );
});

// --- ALAC -------------------------------------------------------------------

/** Minimal MSB-first bit reader, mirroring what the receiver's decoder does. */
function readBits(buf: Buffer, state: { bit: number }, count: number): number {
  let value = 0;
  for (let i = 0; i < count; i++) {
    const byte = buf[state.bit >> 3] as number;
    value = (value << 1) | ((byte >> (7 - (state.bit & 7))) & 1);
    state.bit++;
  }
  return value >>> 0;
}

test('an uncompressed ALAC frame carries the samples the decoder will read back', () => {
  const frames = 352;
  const pcm = Buffer.alloc(frames * 4);
  for (let i = 0; i < frames; i++) {
    pcm.writeInt16LE(i - 176, i * 4);
    pcm.writeInt16LE(176 - i, i * 4 + 2);
  }
  const encoded = encodeAlacPacket(pcm, { framesPerPacket: frames, bitDepth: 16, channels: 2 });

  const state = { bit: 0 };
  strictEqual(readBits(encoded, state, 3), 1, 'stereo element');
  readBits(encoded, state, 4);
  readBits(encoded, state, 12);
  strictEqual(readBits(encoded, state, 1), 0, 'no explicit size on a full packet');
  strictEqual(readBits(encoded, state, 2), 0, 'no uncompressed byte shift');
  strictEqual(readBits(encoded, state, 1), 1, 'escape mode: not compressed');

  for (let i = 0; i < frames; i++) {
    const left = (readBits(encoded, state, 16) << 16) >> 16;
    const right = (readBits(encoded, state, 16) << 16) >> 16;
    strictEqual(left, i - 176, `left sample ${i}`);
    strictEqual(right, 176 - i, `right sample ${i}`);
  }
  strictEqual(readBits(encoded, state, 3), 7, 'end-of-elements marker');
});

test('a short final packet declares its own sample count', () => {
  const frames = 100;
  const encoded = encodeAlacPacket(Buffer.alloc(frames * 4), {
    framesPerPacket: 352,
    bitDepth: 16,
    channels: 2,
  });
  const state = { bit: 0 };
  readBits(encoded, state, 3 + 4 + 12);
  strictEqual(readBits(encoded, state, 1), 1, 'hasSize is set on a partial frame');
  readBits(encoded, state, 2);
  readBits(encoded, state, 1);
  strictEqual(readBits(encoded, state, 32), frames);
});

test('ALAC refuses PCM that is not a whole number of stereo frames', () => {
  throws(
    () => encodeAlacPacket(Buffer.alloc(7), { framesPerPacket: 352, bitDepth: 16, channels: 2 }),
    /whole number/,
  );
});

// --- volume -----------------------------------------------------------------

test('volume maps onto the AirPlay dB scale, with zero as mute', () => {
  strictEqual(volumeToDb(0), -144);
  strictEqual(volumeToDb(100), 0);
  strictEqual(volumeToDb(50), -15);
  strictEqual(volumeToDb(-20), -144, 'clamped below zero');
  strictEqual(volumeToDb(500), 0, 'clamped above full');
});

// --- ALAC decoder -----------------------------------------------------------

test('the decoder reads back what the encoder wrote, sample for sample', async () => {
  const { AlacDecoder, parseAlacFmtp } = await import('./alacDecoder.js');
  const config = parseAlacFmtp('352 0 16 40 10 14 2 255 0 0 44100');
  ok(config, 'the fmtp line parses');
  strictEqual(config.framesPerPacket, 352);
  strictEqual(config.bitDepth, 16);
  strictEqual(config.channels, 2);
  strictEqual(config.sampleRate, 44100);

  const frames = 352;
  const pcm = Buffer.alloc(frames * 4);
  for (let i = 0; i < frames; i++) {
    // Something with real structure, so a predictor bug would show as drift
    // rather than as a single wrong sample.
    pcm.writeInt16LE(Math.round(8000 * Math.sin((2 * Math.PI * i) / 32)), i * 4);
    pcm.writeInt16LE(Math.round(-6000 * Math.sin((2 * Math.PI * i) / 41)), i * 4 + 2);
  }

  const decoded = new AlacDecoder(config).decode(
    encodeAlacPacket(pcm, { framesPerPacket: frames, bitDepth: 16, channels: 2 }),
  );
  ok(decoded, 'the frame decodes');
  deepStrictEqual(decoded, pcm);
});

test('a partial frame survives the round trip too', async () => {
  const { AlacDecoder, parseAlacFmtp } = await import('./alacDecoder.js');
  const config = parseAlacFmtp('352 0 16 40 10 14 2 255 0 0 44100');
  ok(config);
  const frames = 91;
  const pcm = Buffer.alloc(frames * 4);
  for (let i = 0; i < frames; i++) {
    pcm.writeInt16LE(i * 37 - 1500, i * 4);
    pcm.writeInt16LE(2000 - i * 11, i * 4 + 2);
  }
  const decoded = new AlacDecoder(config).decode(
    encodeAlacPacket(pcm, { framesPerPacket: 352, bitDepth: 16, channels: 2 }),
  );
  deepStrictEqual(decoded, pcm);
});
