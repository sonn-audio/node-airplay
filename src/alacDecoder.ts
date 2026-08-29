/**
 * ALAC decoding — what a receiver needs, and the mirror of `alac.ts`.
 *
 * Ported from libraop's `alac.c` (David Hammerton's decoder). A sender only
 * emits the uncompressed escape frames this project's encoder writes when
 * compression would not pay; a real sender — an iPhone, iTunes — sends the
 * compressed form nearly always, so a receiver has to implement the whole
 * thing: adaptive Rice entropy coding and the adaptive FIR predictor whose
 * coefficients are rewritten as it goes.
 *
 * The predictor is the part worth reading twice: its coefficient table is not
 * constant, it is nudged after every sample by the sign of the error, so
 * decoding is only correct if the table is updated in exactly the same order
 * the encoder did it.
 */

const RICE_THRESHOLD = 8;

/** Sign-extend the low `bits` of a value to a full 32-bit signed integer. */
function signExtend(value: number, bits: number): number {
  const shift = 32 - bits;
  return (value << shift) >> shift;
}

function countLeadingZeros(value: number): number {
  return value === 0 ? 32 : Math.clz32(value >>> 0);
}

/** MSB-first bit reader with the one-bit rewind the Rice decoder needs. */
class BitReader {
  private bit = 0;

  constructor(private readonly data: Buffer) {}

  public readBit(): number {
    const byte = this.data[this.bit >> 3] ?? 0;
    const value = (byte >> (7 - (this.bit & 7))) & 1;
    this.bit++;
    return value;
  }

  public read(count: number): number {
    let value = 0;
    for (let i = 0; i < count; i++) {
      value = ((value << 1) | this.readBit()) >>> 0;
    }
    return value >>> 0;
  }

  public rewind(count: number): void {
    this.bit -= count;
  }
}

/** The stream parameters an ALAC decoder is configured with. */
export interface AlacConfig {
  /** Samples per frame — the SDP fmtp line's first value. */
  framesPerPacket: number;
  bitDepth: number;
  channels: number;
  sampleRate: number;
  /** Entropy coder tuning; the fmtp line carries these as 40 / 10 / 14. */
  riceHistoryMult: number;
  riceInitialHistory: number;
  riceKModifier: number;
}

/**
 * Read the ALAC parameters out of an SDP `a=fmtp` line.
 *
 * The line is the ALAC magic cookie in decimal:
 * `frameLength 0 bitDepth historyMult initialHistory kModifier channels 255 0 0 sampleRate`.
 */
export function parseAlacFmtp(fmtp: string): AlacConfig | null {
  const numbers = fmtp
    .trim()
    .split(/\s+/)
    .map((part) => Number(part))
    .filter((value) => Number.isFinite(value));
  if (numbers.length < 11) {
    return null;
  }
  return {
    framesPerPacket: numbers[0] as number,
    bitDepth: numbers[2] as number,
    riceHistoryMult: numbers[3] as number,
    riceInitialHistory: numbers[4] as number,
    riceKModifier: numbers[5] as number,
    channels: numbers[6] as number,
    sampleRate: numbers[10] as number,
  };
}

function decodeValue(reader: BitReader, readSampleSize: number, k: number, mask: number): number {
  // A run of ones gives the quotient; more than the threshold means the value
  // was too large for that and follows raw.
  let x = 0;
  while (x <= RICE_THRESHOLD && reader.readBit()) {
    x++;
  }
  if (x > RICE_THRESHOLD) {
    return reader.read(readSampleSize) & (0xffffffff >>> (32 - readSampleSize));
  }
  if (k !== 1) {
    const extra = reader.read(k);
    x = x * (((1 << k) - 1) & mask);
    if (extra > 1) {
      x += extra - 1;
    } else {
      reader.rewind(1);
    }
  }
  return x;
}

/**
 * Adaptive Rice decoding: `k` is derived from a running history of how large
 * recent values were, so the code length tracks the signal instead of being
 * fixed.
 */
function riceDecode(
  reader: BitReader,
  out: Int32Array,
  count: number,
  readSampleSize: number,
  config: AlacConfig,
  historyMult: number,
): void {
  let history = config.riceInitialHistory;
  const kModifierMask = (1 << config.riceKModifier) - 1;
  let signModifier = 0;

  for (let i = 0; i < count; i++) {
    let k = 31 - config.riceKModifier - countLeadingZeros((history >> 9) + 3);
    k = k < 0 ? k + config.riceKModifier : config.riceKModifier;

    let decoded = decodeValue(reader, readSampleSize, k, 0xffffffff);
    decoded += signModifier;
    let final = (decoded + 1) >> 1;
    if (decoded & 1) {
      final = -final;
    }
    out[i] = final;
    signModifier = 0;

    history += decoded * historyMult - ((history * historyMult) >> 9);
    if (decoded > 0xffff) {
      history = 0xffff;
    }

    // A long run of zeros is coded once rather than sample by sample.
    if (history < 128 && i + 1 < count) {
      signModifier = 1;
      const runK = countLeadingZeros(history) + (((history + 16) / 64) | 0) - 24;
      const blockSize = decodeValue(reader, 16, runK, kModifierMask);
      if (blockSize > 0) {
        out.fill(0, i + 1, Math.min(count, i + 1 + blockSize));
        i += blockSize;
      }
      if (blockSize > 0xffff) {
        history = 0xffff;
      } else {
        history = 0;
      }
    }
  }
}

/**
 * Undo the adaptive FIR prediction.
 *
 * The coefficient table is rewritten as decoding proceeds — after each sample
 * every coefficient is nudged by the sign of the residual — so this has to walk
 * the samples in order and cannot be vectorised or reordered.
 */
function predictorDecompress(
  errors: Int32Array,
  out: Int32Array,
  count: number,
  readSampleSize: number,
  coefficients: Int16Array,
  coefficientCount: number,
  quantisation: number,
): void {
  if (count === 0) {
    return;
  }
  out[0] = errors[0] as number;

  if (coefficientCount === 0) {
    for (let i = 1; i < count; i++) {
      out[i] = errors[i] as number;
    }
    return;
  }

  // 0x1f means "the residual is a difference from the previous sample" — a
  // common shortcut the encoder takes.
  if (coefficientCount === 0x1f) {
    for (let i = 0; i < count - 1; i++) {
      out[i + 1] = signExtend((out[i] as number) + (errors[i + 1] as number), readSampleSize);
    }
    return;
  }

  for (let i = 0; i < coefficientCount && i + 1 < count; i++) {
    out[i + 1] = signExtend((out[i] as number) + (errors[i + 1] as number), readSampleSize);
  }

  let base = 0; // stands in for the C code's advancing buffer_out pointer
  for (let i = coefficientCount + 1; i < count; i++) {
    let sum = 0;
    for (let j = 0; j < coefficientCount; j++) {
      sum += ((out[base + coefficientCount - j] as number) - (out[base] as number)) * (coefficients[j] as number);
    }
    let value = (1 << (quantisation - 1)) + sum;
    value >>= quantisation;
    value += (out[base] as number) + (errors[i] as number);
    value = signExtend(value, readSampleSize);
    out[base + coefficientCount + 1] = value;

    let error = errors[i] as number;
    if (error > 0) {
      let index = coefficientCount - 1;
      while (index >= 0 && error > 0) {
        const difference = (out[base] as number) - (out[base + coefficientCount - index] as number);
        const sign = Math.sign(difference);
        coefficients[index] = (coefficients[index] as number) - sign;
        error -= ((difference * sign) >> quantisation) * (coefficientCount - index);
        index--;
      }
    } else if (error < 0) {
      let index = coefficientCount - 1;
      while (index >= 0 && error < 0) {
        const difference = (out[base] as number) - (out[base + coefficientCount - index] as number);
        const sign = -Math.sign(difference);
        coefficients[index] = (coefficients[index] as number) - sign;
        error -= ((difference * sign) >> quantisation) * (coefficientCount - index);
        index--;
      }
    }
    base++;
  }
}

/**
 * Decodes ALAC frames to interleaved s16le PCM.
 *
 * One instance per stream: the scratch buffers are sized from the configuration
 * and reused, which matters at 125 frames a second.
 */
export class AlacDecoder {
  private readonly errorsA: Int32Array;
  private readonly errorsB: Int32Array;
  private readonly samplesA: Int32Array;
  private readonly samplesB: Int32Array;

  constructor(private readonly config: AlacConfig) {
    const size = config.framesPerPacket;
    this.errorsA = new Int32Array(size);
    this.errorsB = new Int32Array(size);
    this.samplesA = new Int32Array(size);
    this.samplesB = new Int32Array(size);
  }

  /** Decode one frame. Returns interleaved s16le, or null when unsupported. */
  public decode(frame: Buffer): Buffer | null {
    const reader = new BitReader(frame);
    const channels = reader.read(3);
    return channels === 0
      ? this.decodeMono(reader)
      : channels === 1
        ? this.decodeStereo(reader)
        : null;
  }

  private readFrameHeader(reader: BitReader): {
    count: number;
    uncompressedBytes: number;
    notCompressed: boolean;
  } {
    reader.read(4);
    reader.read(12);
    const hasSize = reader.readBit();
    const uncompressedBytes = reader.read(2);
    const notCompressed = reader.readBit() === 1;
    const count = hasSize ? reader.read(32) : this.config.framesPerPacket;
    return { count, uncompressedBytes, notCompressed };
  }

  private decodeMono(reader: BitReader): Buffer {
    const { count, uncompressedBytes, notCompressed } = this.readFrameHeader(reader);
    const readSampleSize = this.config.bitDepth - uncompressedBytes * 8;
    const out = Buffer.alloc(count * 2);

    if (notCompressed) {
      for (let i = 0; i < count; i++) {
        out.writeInt16LE(signExtend(reader.read(readSampleSize), readSampleSize), i * 2);
      }
      return out;
    }

    reader.read(8); // interlacing fields, unused on a single channel
    reader.read(8);
    const predictor = this.readPredictorHeader(reader);
    riceDecode(reader, this.errorsA, count, readSampleSize, this.config, predictor.historyMult);
    predictorDecompress(
      this.errorsA,
      this.samplesA,
      count,
      readSampleSize,
      predictor.coefficients,
      predictor.coefficientCount,
      predictor.quantisation,
    );
    for (let i = 0; i < count; i++) {
      out.writeInt16LE(((this.samplesA[i] as number) << 16) >> 16, i * 2);
    }
    return out;
  }

  /** Read one channel's predictor description: quantisation and coefficients. */
  private readPredictorHeader(reader: BitReader): {
    quantisation: number;
    coefficients: Int16Array;
    coefficientCount: number;
    historyMult: number;
  } {
    reader.read(4); // prediction type; only 0 (adaptive FIR) occurs in practice
    const quantisation = reader.read(4);
    const riceModifier = reader.read(3);
    const coefficientCount = reader.read(5);
    const coefficients = new Int16Array(32);
    for (let i = 0; i < coefficientCount; i++) {
      coefficients[i] = signExtend(reader.read(16), 16);
    }
    return {
      quantisation,
      coefficients,
      coefficientCount,
      historyMult: (riceModifier * this.config.riceHistoryMult) / 4,
    };
  }

  private decodeStereo(reader: BitReader): Buffer {
    const { count, uncompressedBytes, notCompressed } = this.readFrameHeader(reader);
    // Stereo carries one extra bit of headroom: the mid/side transform can
    // produce a difference that needs it.
    const readSampleSize = this.config.bitDepth - uncompressedBytes * 8 + 1;
    const out = Buffer.alloc(count * 4);

    if (notCompressed) {
      const size = this.config.bitDepth;
      for (let i = 0; i < count; i++) {
        out.writeInt16LE(signExtend(reader.read(size), size), i * 4);
        out.writeInt16LE(signExtend(reader.read(size), size), i * 4 + 2);
      }
      return out;
    }

    const interlacingShift = reader.read(8);
    const interlacingLeftWeight = reader.read(8);

    const a = this.readPredictorHeader(reader);
    const b = this.readPredictorHeader(reader);

    riceDecode(reader, this.errorsA, count, readSampleSize, this.config, a.historyMult);
    predictorDecompress(
      this.errorsA,
      this.samplesA,
      count,
      readSampleSize,
      a.coefficients,
      a.coefficientCount,
      a.quantisation,
    );
    riceDecode(reader, this.errorsB, count, readSampleSize, this.config, b.historyMult);
    predictorDecompress(
      this.errorsB,
      this.samplesB,
      count,
      readSampleSize,
      b.coefficients,
      b.coefficientCount,
      b.quantisation,
    );

    // Undo the mid/side transform the encoder applied across the pair.
    for (let i = 0; i < count; i++) {
      const midRight = this.samplesA[i] as number;
      const difference = this.samplesB[i] as number;
      const right = interlacingLeftWeight
        ? midRight - ((difference * interlacingLeftWeight) >> interlacingShift)
        : difference;
      const left = interlacingLeftWeight ? right + difference : midRight;
      out.writeInt16LE(left << 16 >> 16, i * 4);
      out.writeInt16LE(right << 16 >> 16, i * 4 + 2);
    }
    return out;
  }
}
