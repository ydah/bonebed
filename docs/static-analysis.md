# Source hints with Prism

`bonebed static PATH [--manifest FILE]` parses a Ruby file or recursively scans `*.rb` files in a
directory, without executing source. Symlinks leaving the selected source tree are ignored. JSON
output lists selected `system`, `exec`, `spawn`, backtick, `eval`, `Net::HTTP`, and socket call sites,
with source file, line, kind, call, literal argument where available, and an `observed` field.

Prism is optional. Ruby 3.3 and newer include it; on an older supported Ruby, install the `prism` gem
separately. An unavailable parser produces `available: false`, an explanation, and exit status 2.
Parse errors are listed explicitly and produce exit status 1. Successful scans return status 0.

With `--manifest FILE`, literal commands are matched to observed command paths or basenames. Network
calls use broad observed network capabilities. `observed: true` means an approximate capability match;
it does not establish that this particular source line executed. `false` means no matching recorded
capability, not that the code cannot execute. Without a manifest, or for dynamic arguments and eval,
the match is unknown (`null`).

This scan does not resolve aliases, perform dataflow analysis, model dynamic method dispatch, inspect
native extensions, or decide whether a gem is malicious. Review source hints together with the
observation environment, target status, and observer errors.
