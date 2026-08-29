# @sonn-audio/node-airplay

An AirPlay 2 sender for Node.js, in TypeScript. No native addon, no bundled
binary, no dependencies beyond `node:crypto`, `node:net` and `node:dgram`.

## Why

Apple receivers running OS 27 no longer render legacy AirPlay 1 (RAOP). They
still accept the whole RTSP session, still answer timing requests, still take
every audio packet — and play nothing. Measured on a HomePod (AudioAccessory5,1,
build 24J5358a, AirTunes/980.77.2) with two independent RAOP senders; the same
speaker plays fine over AirPlay 2. So for HomePods and Apple TVs, AirPlay 2 is
not an upgrade, it is the only remaining route.

## What works

Verified end to end against a HomePod on OS 27 — audible audio, not just green
status codes:

- `GET /info` and binary property lists (read and write)
- HAP **transient** pair-setup (SRP-6a, SHA-512, 3072-bit) — no PIN, no stored
  credentials, no user interaction
- the ChaCha20-Poly1305 encrypted control channel
- session SETUP with PTP timing, plus the keepalive and events connection that
  keep it alive
- a PTP grandmaster on UDP 319/320 that Apple receivers slave to
- RECORD, stream SETUP (type 96 realtime, ALAC 44100/16/2)
- ALAC encoding and the encrypted RTP stream, anchored on the PTP timeline

- retransmits: the receiver asks for audio it lost and gets it back
- track metadata and cover art, over the DMAP/SET_PARAMETER path
- synchronised groups: members handed one shared instant anchor to it
- both timing lanes, chosen per device from what the receiver answers rather
  than what it advertises: PTP for Apple receivers, NTP for the ones that
  advertise `SupportsPTP` and then never probe the clock

## What does not exist yet

**Apple's now-playing screen.** It rides the MediaRemote channel, whose keys
derive from a pair-VERIFY secret, so it needs stored credentials from a PIN
pairing; a transiently paired session cannot reach it. The DMAP metadata above
is the path that is open without credentials.

**`FLUSH` for seek and skip — deliberately.** The reference implementation
avoids every flush verb on Apple receivers: dropping their queue produces an
audible noise burst, so the queued audio is left to play out instead. That makes
the send lead the bound on how much of the old track a skip still plays, which
is why it is kept shallow. A non-Apple AirPlay 2 receiver should get a real
FLUSH, per device.

24-bit, the buffered (type 103) stream, and any receiver beyond the two this was
measured against: a HomePod (OS 27, PTP lane) and a BeoLab 50 (NTP lane).

## Requirements

PTP needs UDP ports 319 and 320, which are privileged: run as root or grant
`CAP_NET_BIND_SERVICE`. Without PTP an Apple receiver accepts the session and
renders silence, so the failure is raised rather than quietly downgraded.

## Origin

The protocol logic is a port of Music Assistant's `cliairplay`, whose `src/`
files are Apache-2.0. See [NOTICE](NOTICE) — it matters that the device-specific
constants in here have a traceable source, because most of them fail silently
when wrong.

## Licence

Apache-2.0.

## The AirPlay 1 RSA key

`src/appleKey.ts` carries the AirPort Express private key. A sender wraps its
AES audio key in the matching public key and the protocol has no way to
negotiate a different one, so a receiver either holds this exact key or cannot
read a single audio packet -- a receiver that advertises `et=0` is abandoned by
an iPhone right after `OPTIONS`. Every third-party RAOP receiver ships it for
that reason, shairport-sync and libraop among them, and it has been public for
well over a decade. It is used only by the receiver; the sender side never
touches it.
