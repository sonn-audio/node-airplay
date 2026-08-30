# @sonn-audio/node-airplay

AirPlay for Node.js, in TypeScript. Sender and receiver, AirPlay 1 (RAOP) and
AirPlay 2. No native addon, no bundled binary, no dependencies — `node:crypto`,
`node:net` and `node:dgram` are the whole runtime.

```bash
npm install @sonn-audio/node-airplay
```

## What it does

|                     | Sender | Receiver |
| ------------------- | ------ | -------- |
| AirPlay 2 (native)  | ✅     | —        |
| AirPlay 1 (RAOP)    | ✅     | ✅       |

Everything a working session needs is in here: HAP pairing and the encrypted
control channel, binary property lists, SRP-6a, a PTP grandmaster, NTP timing,
ALAC encode and decode, RTP with retransmits, DMAP metadata and cover art, and
DACP remote control.

## Sending to an AirPlay 2 receiver

Transient pairing — no PIN, no stored credentials, nothing for the user to do.

```ts
import {
  AirPlayConnection, PtpEngine, RealtimeSender, setupRealtimeStream,
} from '@sonn-audio/node-airplay';

const connection = await AirPlayConnection.open({ host: '192.168.1.50' });
const session = await connection.setupSession('living-room');

const ptp = new PtpEngine({ clockId: connection.identity.clockId, peers: ['192.168.1.50'] });
await ptp.start();

const sockets = await RealtimeSender.bindSockets();
const stream = await setupRealtimeStream(connection.rtsp, connection.sessionUrl, {
  audioKey: connection.hap.sharedSecret,
  localDataPort: sockets.dataPort,
  localControlPort: sockets.controlPort,
  streamConnectionId: Math.floor(Math.random() * 0x7fff_ffff),
});

const sender = new RealtimeSender(
  {
    host: '192.168.1.50',
    dataPort: stream.dataPort,
    controlPort: stream.controlPort,
    audioKey: connection.hap.sharedSecret,
    ptp,
  },
  sockets.data,
  sockets.control,
);
sender.start();
sender.sendPacket(pcm); // 352 frames of 44100/16/2, little-endian
```

`setVolume`, `setMetadata` and `setArtwork` drive what the device shows and how
loud it plays.

## Sending to an AirPlay 1 receiver

```ts
import { connectRaop, RaopStreamer } from '@sonn-audio/node-airplay';

const session = await connectRaop({ host: '192.168.1.60', et: '0,1' });
const streamer = new RaopStreamer({ host: '192.168.1.60', session });
streamer.start();
streamer.sendPacket(pcm);
```

Pass the device's advertised `et` from its mDNS TXT record. A `4` in there means
MFi, and the `/auth-setup` exchange runs automatically — those receivers answer
SETUP with a 403 without it.

## Receiving

Becomes an AirPlay speaker: an iPhone, Mac or iTunes can pick it and stream to
it. Audio arrives decoded, as PCM.

```ts
import { AirPlayReceiver } from '@sonn-audio/node-airplay';

const receiver = new AirPlayReceiver({ name: 'Kitchen', model: 'MyDevice' }, (event) => {
  switch (event.type) {
    case 'pcm':      speaker.write(event.data); break;      // 44100/16/2
    case 'metadata': show(event.title, event.artist, event.durationMs); break;
    case 'artwork':  showCover(event.data, event.contentType); break;
    case 'volume':   setVolume(event.value); break;         // 0-100
    case 'remote':   remember(event.dacpId, event.activeRemote); break;
  }
});

const ad = await receiver.start();  // { instanceName, port, txt }
```

The receiver deliberately publishes no mDNS itself — announce `ad` with whatever
service discovery you already run. `sendRemoteCommand()` sends play, pause, next
and previous back to whatever is streaming, over DACP.

## Timing

An AirPlay 2 sender picks its timing lane from what the receiver **answers**,
not from what it advertises:

- **PTP** — a grandmaster on UDP 319/320 that Apple receivers slave to.
- **NTP** — for devices that advertise `SupportsPTP`, accept the PTP session and
  then never probe the clock. They give themselves away by returning a
  `timingPort` in the SETUP reply, and the session is re-established on that lane.

Getting this wrong is silent: the wrong lane renders silence, not an error.

**PTP needs UDP 319 and 320, which are privileged.** Run as root or grant
`CAP_NET_BIND_SERVICE`. Without them an Apple receiver accepts the session and
plays nothing, so the failure is raised rather than quietly downgraded.

## Limits

- **Apple's now-playing screen** is out of reach. It rides the MediaRemote
  channel, whose keys derive from a pair-verify secret — that needs stored
  credentials from a PIN pairing, which a transient session does not have. DMAP
  metadata is the credential-free path, and it is what this uses.
- **No `FLUSH` to an Apple receiver, by choice.** Dropping their queue produces
  an audible burst of noise, so queued audio is left to play out. The send lead
  is what bounds how much of an old track a skip still plays. Non-Apple AirPlay 2
  receivers should get a real flush, per device.
- 16-bit only; the buffered (type 103) stream is not implemented.
- Measured against a HomePod (OS 27, PTP), a BeoLab 50 (NTP), and iOS senders.

Worth knowing if you are choosing a lane: Apple receivers on OS 27 no longer
render AirPlay 1. They accept the entire RTSP session, answer timing, take every
packet — and play nothing. For HomePods and Apple TVs, AirPlay 2 is not an
upgrade but the only route left.

## Notes

`src/appleKey.ts` carries the AirPort Express private key, which the receiver
needs: a sender wraps its AES key in the matching public key and the protocol
has no way to negotiate another. Every third-party RAOP receiver ships it.

The AirPlay 2 protocol logic is a port of Music Assistant's `cliairplay`
(Apache-2.0) — see [NOTICE](NOTICE). Its device-specific constants have a
traceable source, which matters because most of them fail silently when wrong.

## Licence

Apache-2.0.
