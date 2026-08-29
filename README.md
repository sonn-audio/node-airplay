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

## What does not exist yet

Metadata and artwork (the MediaRemote channel), `FLUSH` for a clean seek or
skip, retransmit handling, synchronised groups, 24-bit, the buffered (type 103)
stream, and non-Apple receivers beyond what the protocol implies — this has been
tested against one HomePod. There are no tests.

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
