# Sinkhole observations

`--sinkhole` observes DNS-based HTTP and TLS connection attempts inside a fresh user and network
namespace. The target has only a loopback interface. Namespace or listener setup failure stops the
observation before running the target; this mode never falls back to ordinary networking.

```sh
bonebed dig example-gem --phase all --sinkhole --quiet-target
bonebed run --sinkhole -- ruby -rnet/http -e 'Net::HTTP.get(URI("http://example.invalid/health"))'
```

Package downloads happen before observation, as with offline installs. That preparation still needs
registry access or a populated package cache. `--sinkhole` and `--offline` are mutually exclusive:
sinkhole permits communication with its synthetic services, whereas offline observations reject
target IP connections. Baselines and resume identities distinguish these modes.

## What is recorded

The observer supplies a private resolver file through seccomp ADDFD when the target opens
`/etc/resolv.conf`. Each read gets its own file offset; writes to that path are rejected. The host's
resolver file is never modified. Unix socket and socketpair creation is rejected in this mode,
including nscd requests that could otherwise bypass the synthetic resolver. Connection and datagram
decoding failures are also rejected, so unreadable target memory cannot permit a host socket request.

The DNS service answers ordinary UDP A and AAAA questions with `127.0.0.1` and `::1`. Requests to
loopback TCP ports 80 and 443 reach bounded listeners outside the target's seccomp observation tree.
Their own system calls do not become target capabilities.

- HTTP/1.x: method, Host, path, and up to 4096 bytes of the initial request are recorded. A bounded
  Content-Length body is included when available. The service returns an empty 204 response.
- TLS: the first ClientHello's plaintext SNI is recorded, including a ClientHello split across
  records. The service sends a fatal handshake alert; it does not impersonate a certificate or decrypt
  application traffic.

These events appear in `network_intent`. DNS names and socket destinations remain in `dns` and
`network`. Destination capability keys use `network:http:HOST` and `network:tls:HOST`, so existing
network policies, diffs, and capability locks apply. Fake credential tokens in request samples, hosts,
and paths are replaced by canary markers before the manifest is saved. Corresponding `canary_hits`
identify `network_intent` as their location.

## Bounds and limitations

The listeners accept at most 16 concurrent clients and retain at most 1024 distinct intent events.
Each client has a one-second deadline and at most 16 KiB of buffered protocol input. Reaching the
event limit is an observer error. Requests that are incomplete, malformed, or too large may have a
socket/DNS observation without a decoded intent event.

Only DNS-based HTTP/1.x on port 80 and TLS on port 443 are served. Literal external IP addresses,
other destination ports, DNS over TCP/HTTPS, encrypted ClientHello, and arbitrary application protocols
are not redirected or decoded. With no external interface or route, direct external IP traffic cannot
leave this network namespace. A failed TLS handshake may prevent behavior that would occur with a
real service. A sinkhole observation is therefore a distinct execution environment, not proof of all
possible behavior.

Linux must allow unprivileged user/network namespaces and seccomp ADDFD. Container profiles and host
AppArmor restrictions can prevent setup. This mode fails closed under those restrictions; it does not
change host security settings. Check `bonebed doctor` and use a disposable environment configured for
the required kernel features.

The helper drops its capabilities and protects its memory before starting target code. The target
has no effective, permitted, ambient, or bounding capabilities. A per-run authentication code protects
the returned observation against direct pipe forgery. These measures do not make the shared filesystem
or same-user host processes a complete security boundary; the [threat model](threat-model.md) still
applies. Captured HTTP samples can contain application data: review artifacts before publishing them.

Target output is bounded and replayed after the helper finishes; `--quiet-target` suppresses replay.
`--trace` is currently rejected in sinkhole mode. Ordinary observations retain their streaming output
and JSONL trace support.
