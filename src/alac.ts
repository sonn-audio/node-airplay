/**
 * ALAC encoding for the AirPlay wire — uncompressed frames.
 *
 * ALAC's bitstream has an escape mode: a frame may carry its samples verbatim
 * instead of predictor + Rice output, and every decoder must handle it because
 * Apple's own encoder falls back to it whenever compression would not pay. That
 * is what this writes. The layout below is taken from libraop's decoder
 * (`alac.c`), which is what the receiver runs, so it is what the frame is
 * checked against.
 *
 * The cost is bandwidth: a 352-frame stereo packet is 1412 bytes instead of
 * roughly half that. On a LAN carrying one AirPlay stream that is not a
 * constraint, and it keeps the predictor and the adaptive Rice coder — the part
 * of ALAC that is genuinely intricate — out of the first working version. Real
 * compression can be added behind this same interface later; the receiver
 * cannot tell the difference beyond packet size.
 *
 * Uncompressed stereo frame:
 *   3 bits  element/channel count (1 = stereo)
 *   4 bits  unused
 *  12 bits  unused
 *   1 bit   hasSize
 *   2 bits  uncompressedBytes (0)
 *   1 bit   isNotCompressed (1)
 *  32 bits  sample count, only when hasSize
 *   then, per frame: left sample, right sample, each `bitDepth` bits
 *   3 bits  end-of-elements marker (7), then byte alignment
 */

/** Writes a big-endian bit stream, MSB first. */
class BitWriter {
  private readonly bytes: number[] = [];
  private current = 0;
  private used = 0;

  public write(value: number, bits: number): void {
    for (let i = bits - 1; i >= 0; i--) {
      this.current = (this.current << 1) | ((value >>> i) & 1);
      this.used++;
      if (this.used === 8) {
        this.bytes.push(this.current & 0xff);
        this.current = 0;
        this.used = 0;
      }
    }
  }

  public finish(): Buffer {
    if (this.used > 0) {
      this.bytes.push((this.current << (8 - this.used)) & 0xff);
      this.current = 0;
      this.used = 0;
    }
    return Buffer.from(this.bytes);
  }
}

/** Element type written after the payload to close the frame. */
const ID_END = 7;

export interface AlacEncoderOptions {
  /** Samples per frame the session negotiated (`spf`, 352 for AirPlay). */
  framesPerPacket: number;
  bitDepth: 16;
  channels: 2;
}

/**
 * Encode one packet of interleaved PCM as an uncompressed ALAC frame.
 *
 * :param pcm: interleaved signed 16-bit little-endian samples, exactly
 *   `framesPerPacket * channels` of them. A short final packet is allowed and
 *   is written with an explicit sample count.
 */
export function encodeAlacPacket(pcm: Buffer, options: AlacEncoderOptions): Buffer {
  const frameCount = pcm.length / (options.channels * 2);
  if (!Number.isInteger(frameCount)) {
    throw new Error('ALAC: PCM length is not a whole number of stereo frames');
  }

  const writer = new BitWriter();
  const partial = frameCount !== options.framesPerPacket;

  writer.write(1, 3); // stereo element
  writer.write(0, 4);
  writer.write(0, 12);
  writer.write(partial ? 1 : 0, 1); // hasSize
  writer.write(0, 2); // uncompressedBytes
  writer.write(1, 1); // isNotCompressed — the escape mode
  if (partial) {
    // 32 bits, written in two halves because the bit writer takes 32-bit ints.
    writer.write((frameCount >>> 16) & 0xffff, 16);
    writer.write(frameCount & 0xffff, 16);
  }

  for (let i = 0; i < frameCount; i++) {
    writer.write(pcm.readUInt16LE(i * 4), 16);
    writer.write(pcm.readUInt16LE(i * 4 + 2), 16);
  }

  writer.write(ID_END, 3);
  return writer.finish();
}
