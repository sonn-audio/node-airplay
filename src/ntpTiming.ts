/**
 * The legacy NTP timing lane.
 *
 * Not every AirPlay 2 receiver does PTP, and the ones that do not are not
 * honest about it: a device can advertise SupportsPTP, accept a PTP session
 * SETUP with a 200, and then never send a single clock probe — after which it
 * renders silence while the sender looks perfectly healthy. Measured on a
 * BeoLab 50: audio on the wire at the right rate, nothing coming back, no
 * sound. The tell is in the SETUP reply, which carries a `timingPort` instead
 * of just a `timingPeerInfo`.
 *
 * For those receivers the sender runs this instead: a responder the device
 * polls for the time, and a different sync packet. Apple receivers are the
 * opposite case — they render silence on an NTP-timed realtime stream — so the
 * two lanes are not interchangeable, they are per device.
 */

import { createSocket, type Socket } from 'node:dgram';

/** Seconds between 1900 (NTP) and 1970 (Unix). */
const NTP_EPOCH_DELTA = 2_208_988_800;
const REQUEST_TYPE = 0xd2;
const RESPONSE_TYPE = 0xd3;
const REQUEST_SIZE = 32;

/** Now, as an NTP fixed-point value (seconds << 32 | fraction). */
export function ntpNow(): bigint {
  const ms = Date.now();
  const seconds = BigInt(Math.floor(ms / 1000) + NTP_EPOCH_DELTA);
  const fraction = (BigInt(ms % 1000) << 32n) / 1000n;
  return (seconds << 32n) | fraction;
}

/**
 * Answers a receiver's timing requests so it can place our clock.
 *
 * The exchange is the RAOP one: a 32-byte request with type 0xD2, answered with
 * type 0xD3 carrying the request's transmit time as the reference, plus our
 * receive and transmit times. Left unanswered the receiver has no timeline and
 * plays nothing.
 */
export class NtpTimingResponder {
  private socket: Socket | null = null;
  /** Requests answered — a receiver that stops asking has dropped the session. */
  public exchanges = 0;

  public async start(): Promise<number> {
    const socket = createSocket({ type: 'udp4', reuseAddr: true });
    socket.on('message', (msg, rinfo) => this.onMessage(msg, rinfo));
    socket.on('error', () => {
      /* a timing socket error surfaces as the receiver going quiet */
    });
    await new Promise<void>((resolve, reject) => {
      socket.once('error', reject);
      socket.bind(0, () => {
        socket.removeListener('error', reject);
        resolve();
      });
    });
    this.socket = socket;
    return socket.address().port;
  }

  public stop(): void {
    this.socket?.close();
    this.socket = null;
  }

  private onMessage(msg: Buffer, rinfo: { address: string; port: number }): void {
    if (msg.length < REQUEST_SIZE || msg[1] !== REQUEST_TYPE) {
      return;
    }
    const response = Buffer.alloc(32);
    response[0] = 0x80;
    response[1] = RESPONSE_TYPE;
    // Reference time: the request's own transmit timestamp, echoed back.
    msg.copy(response, 8, 24, 32);

    const now = ntpNow();
    response.writeUInt32BE(Number(now >> 32n), 16);
    response.writeUInt32BE(Number(now & 0xffff_ffffn), 20);
    // We answer immediately, so transmit time is the receive time.
    response.copy(response, 24, 16, 24);

    this.socket?.send(response, rinfo.port, rinfo.address);
    this.exchanges++;
  }
}

/**
 * The NTP flavour of the anchor packet (20 bytes, type 0xD4) — where the media
 * timeline sits on the NTP clock. The PTP lane sends a different, longer one.
 *
 * :param rtpTimestamp: the sender's current RTP position.
 * :param leadFrames: how far ahead of the render point that position is.
 */
export function buildNtpSyncPacket(
  rtpTimestamp: number,
  leadFrames: number,
  first: boolean,
): Buffer {
  const packet = Buffer.alloc(20);
  packet[0] = first ? 0x90 : 0x80;
  packet[1] = 0xd4;
  packet.writeUInt16BE(0x0007, 2);

  const playing = rtpTimestamp >= leadFrames ? rtpTimestamp - leadFrames : 0;
  packet.writeUInt32BE(playing >>> 0, 4);

  const now = ntpNow();
  packet.writeUInt32BE(Number(now >> 32n), 8);
  packet.writeUInt32BE(Number(now & 0xffff_ffffn), 12);
  packet.writeUInt32BE(rtpTimestamp >>> 0, 16);
  return packet;
}
