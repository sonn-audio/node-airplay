/**
 * Apple binary property lists (`bplist00`) — the encoding every AirPlay 2
 * message body uses, from `GET /info` to the stream SETUP.
 *
 * Only the subset Apple actually emits is handled: null/bool, int, real, date,
 * data, ASCII and UTF-16BE strings, arrays, sets and dicts. UIDs appear in
 * keyed archives, which AirPlay does not use, so they decode to a plain number.
 */

export type PlistValue =
  | null
  | boolean
  | number
  | bigint
  | string
  | Buffer
  | Date
  | PlistValue[]
  | { [key: string]: PlistValue };

export const BPLIST_HEADER = 'bplist00';
export const BPLIST_TRAILER_SIZE = 32;
/** bplist dates count seconds from 2001-01-01, not the Unix epoch. */
export const APPLE_EPOCH_OFFSET_MS = 978_307_200_000;

class Reader {
  private readonly offsets: number[] = [];
  private readonly cache = new Map<number, PlistValue>();

  constructor(
    private readonly data: Buffer,
    private readonly offsetIntSize: number,
    private readonly objectRefSize: number,
    numObjects: number,
    offsetTableOffset: number,
  ) {
    for (let i = 0; i < numObjects; i++) {
      this.offsets.push(this.readUInt(offsetTableOffset + i * offsetIntSize, offsetIntSize));
    }
  }

  public readObject(index: number): PlistValue {
    const cached = this.cache.get(index);
    if (cached !== undefined) {
      return cached;
    }
    const offset = this.offsets[index];
    if (offset === undefined || offset >= this.data.length) {
      throw new Error(`bplist: object ${index} out of range`);
    }
    const value = this.parseAt(offset);
    this.cache.set(index, value);
    return value;
  }

  private readUInt(offset: number, size: number): number {
    let value = 0;
    for (let i = 0; i < size; i++) {
      value = value * 256 + (this.data[offset + i] as number);
    }
    return value;
  }

  /** Marker low-nibble length, or the integer that follows when it is 0xF. */
  private readLength(offset: number, nibble: number): { length: number; next: number } {
    if (nibble !== 0x0f) {
      return { length: nibble, next: offset + 1 };
    }
    const sizeMarker = this.data[offset + 1] as number;
    const byteCount = 1 << (sizeMarker & 0x0f);
    return { length: this.readUInt(offset + 2, byteCount), next: offset + 2 + byteCount };
  }

  private parseAt(offset: number): PlistValue {
    const marker = this.data[offset] as number;
    const type = marker >> 4;
    const nibble = marker & 0x0f;

    switch (type) {
      case 0x0:
        if (nibble === 0x00) return null;
        if (nibble === 0x08) return false;
        if (nibble === 0x09) return true;
        return null;

      case 0x1: {
        // Integers are 2^nibble bytes; 8-byte values are signed, the rest are not.
        const byteCount = 1 << nibble;
        if (byteCount <= 4) {
          return this.readUInt(offset + 1, byteCount);
        }
        const value = this.data.readBigInt64BE(offset + 1);
        return value >= BigInt(Number.MIN_SAFE_INTEGER) && value <= BigInt(Number.MAX_SAFE_INTEGER)
          ? Number(value)
          : value;
      }

      case 0x2:
        return nibble === 2
          ? this.data.readFloatBE(offset + 1)
          : this.data.readDoubleBE(offset + 1);

      case 0x3:
        return new Date(this.data.readDoubleBE(offset + 1) * 1000 + APPLE_EPOCH_OFFSET_MS);

      case 0x4: {
        const { length, next } = this.readLength(offset, nibble);
        return Buffer.from(this.data.subarray(next, next + length));
      }

      case 0x5: {
        const { length, next } = this.readLength(offset, nibble);
        return this.data.subarray(next, next + length).toString('latin1');
      }

      case 0x6: {
        const { length, next } = this.readLength(offset, nibble);
        return this.data.subarray(next, next + length * 2).swap16().toString('utf16le');
      }

      case 0x8:
        return this.readUInt(offset + 1, nibble + 1);

      case 0xa:
      case 0xc: {
        const { length, next } = this.readLength(offset, nibble);
        const out: PlistValue[] = [];
        for (let i = 0; i < length; i++) {
          out.push(this.readObject(this.readUInt(next + i * this.objectRefSize, this.objectRefSize)));
        }
        return out;
      }

      case 0xd: {
        const { length, next } = this.readLength(offset, nibble);
        const out: { [key: string]: PlistValue } = {};
        for (let i = 0; i < length; i++) {
          const keyRef = this.readUInt(next + i * this.objectRefSize, this.objectRefSize);
          const valueRef = this.readUInt(
            next + (length + i) * this.objectRefSize,
            this.objectRefSize,
          );
          out[String(this.readObject(keyRef))] = this.readObject(valueRef);
        }
        return out;
      }

      default:
        throw new Error(`bplist: unsupported object type 0x${type.toString(16)}`);
    }
  }
}

/** Decode a `bplist00` body. Throws when the header or trailer is not a plist. */
export function parseBinaryPlist(data: Buffer): PlistValue {
  if (data.length < BPLIST_HEADER.length + BPLIST_TRAILER_SIZE) {
    throw new Error('bplist: body too short');
  }
  if (data.subarray(0, BPLIST_HEADER.length).toString('latin1') !== BPLIST_HEADER) {
    throw new Error('bplist: missing bplist00 header');
  }
  const trailer = data.subarray(data.length - BPLIST_TRAILER_SIZE);
  const offsetIntSize = trailer.readUInt8(6);
  const objectRefSize = trailer.readUInt8(7);
  const numObjects = Number(trailer.readBigUInt64BE(8));
  const topObject = Number(trailer.readBigUInt64BE(16));
  const offsetTableOffset = Number(trailer.readBigUInt64BE(24));

  const reader = new Reader(data, offsetIntSize, objectRefSize, numObjects, offsetTableOffset);
  return reader.readObject(topObject);
}

