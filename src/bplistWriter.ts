/**
 * Writing `bplist00` bodies — the encoding the AirPlay 2 session and stream
 * SETUP go out in.
 *
 * Two passes: every object is first interned in depth-first order so it has a
 * stable index, then each is serialised against those indices. Doing it in one
 * pass means emitting a reference before its target's index is settled, which
 * is how subtly-wrong plists get written — they parse, and the receiver reads
 * the wrong values.
 */

import { APPLE_EPOCH_OFFSET_MS, BPLIST_HEADER, BPLIST_TRAILER_SIZE, type PlistValue } from './bplist.js';

/**
 * An integer to be written as a signed 64-bit value whatever its magnitude —
 * the PTP ClockID goes out that way, as the reference sender does.
 */
export class PlistInt64 {
  constructor(public readonly value: bigint) {}
}

export type PlistInput = PlistValue | PlistInt64;

/** One object in the table: its value plus the indices of the objects it refers to. */
interface Entry {
  value: PlistInput;
  /** Array: element indices. Dict: all key indices, then all value indices. */
  refs: number[];
}

function byteWidth(max: number): 1 | 2 | 4 | 8 {
  if (max < 0x100) return 1;
  if (max < 0x10000) return 2;
  if (max < 0x1_0000_0000) return 4;
  return 8;
}

function writeUInt(value: number, size: number): Buffer {
  const buf = Buffer.alloc(size);
  let rest = value;
  for (let i = size - 1; i >= 0; i--) {
    buf[i] = rest & 0xff;
    rest = Math.floor(rest / 256);
  }
  return buf;
}

/** Marker byte, plus a trailing length integer when the count exceeds a nibble. */
function marker(type: number, count: number): Buffer {
  if (count < 0x0f) {
    return Buffer.from([(type << 4) | count]);
  }
  const size = byteWidth(count);
  const power = size === 1 ? 0 : size === 2 ? 1 : size === 4 ? 2 : 3;
  return Buffer.concat([Buffer.from([(type << 4) | 0x0f, 0x10 | power]), writeUInt(count, size)]);
}

function isDict(value: PlistInput): value is { [key: string]: PlistValue } {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    !Buffer.isBuffer(value) &&
    !(value instanceof Date) &&
    !(value instanceof PlistInt64)
  );
}

function isAscii(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    if (value.charCodeAt(i) > 0x7f) {
      return false;
    }
  }
  return true;
}

/** Encode a value as a `bplist00` body. */
export function buildBinaryPlist(root: PlistInput): Buffer {
  const entries: Entry[] = [];

  const intern = (value: PlistInput): number => {
    const index = entries.length;
    const entry: Entry = { value, refs: [] };
    entries.push(entry);
    if (Array.isArray(value)) {
      entry.refs = value.map((item) => intern(item));
    } else if (isDict(value)) {
      const keys = Object.keys(value);
      const keyRefs = keys.map((key) => intern(key));
      const valueRefs = keys.map((key) => intern(value[key] as PlistValue));
      entry.refs = [...keyRefs, ...valueRefs];
    }
    return index;
  };
  intern(root);

  const refSize = byteWidth(entries.length);

  const encode = (entry: Entry): Buffer => {
    const { value, refs } = entry;

    if (value === null) return Buffer.from([0x00]);
    if (typeof value === 'boolean') return Buffer.from([value ? 0x09 : 0x08]);

    if (value instanceof PlistInt64 || typeof value === 'bigint') {
      const raw = value instanceof PlistInt64 ? value.value : value;
      const buf = Buffer.alloc(9);
      buf[0] = 0x13; // int, 2^3 bytes
      buf.writeBigInt64BE(BigInt.asIntN(64, raw), 1);
      return buf;
    }

    if (typeof value === 'number') {
      if (Number.isInteger(value) && value >= 0 && value < 0x1_0000_0000) {
        const size = byteWidth(value);
        const power = size === 1 ? 0 : size === 2 ? 1 : 2;
        return Buffer.concat([Buffer.from([0x10 | power]), writeUInt(value, size)]);
      }
      if (Number.isInteger(value)) {
        const buf = Buffer.alloc(9);
        buf[0] = 0x13;
        buf.writeBigInt64BE(BigInt(value), 1);
        return buf;
      }
      const buf = Buffer.alloc(9);
      buf[0] = 0x23; // real, 8 bytes
      buf.writeDoubleBE(value, 1);
      return buf;
    }

    if (typeof value === 'string') {
      return isAscii(value)
        ? Buffer.concat([marker(0x5, value.length), Buffer.from(value, 'latin1')])
        : Buffer.concat([marker(0x6, value.length), Buffer.from(value, 'utf16le').swap16()]);
    }

    if (Buffer.isBuffer(value)) {
      return Buffer.concat([marker(0x4, value.length), value]);
    }

    if (value instanceof Date) {
      const buf = Buffer.alloc(9);
      buf[0] = 0x33;
      buf.writeDoubleBE((value.getTime() - APPLE_EPOCH_OFFSET_MS) / 1000, 1);
      return buf;
    }

    const refBytes = refs.map((ref) => writeUInt(ref, refSize));
    if (Array.isArray(value)) {
      return Buffer.concat([marker(0xa, value.length), ...refBytes]);
    }
    return Buffer.concat([marker(0xd, refs.length / 2), ...refBytes]);
  };

  const bodies = entries.map((entry) => encode(entry));

  const offsets: number[] = [];
  let position = BPLIST_HEADER.length;
  for (const body of bodies) {
    offsets.push(position);
    position += body.length;
  }

  const offsetIntSize = byteWidth(position);
  const trailer = Buffer.alloc(BPLIST_TRAILER_SIZE);
  trailer.writeUInt8(offsetIntSize, 6);
  trailer.writeUInt8(refSize, 7);
  trailer.writeBigUInt64BE(BigInt(bodies.length), 8);
  trailer.writeBigUInt64BE(0n, 16); // the root is always object 0
  trailer.writeBigUInt64BE(BigInt(position), 24);

  return Buffer.concat([
    Buffer.from(BPLIST_HEADER, 'latin1'),
    ...bodies,
    ...offsets.map((offset) => writeUInt(offset, offsetIntSize)),
    trailer,
  ]);
}
