# Implementation notes

Measurements below were taken on 2026-09-09 in the development container: Ruby 4.0.6, Linux 6.8.0, aarch64, and `seccomp-notify` 0.3.0. The upstream API was checked at commit `e904a3f07eb8693e3a0c86e29f0bd71d46230475`.

## Confirmed `seccomp-notify` API

- Syscall arguments: `request.args[index]`
- NUL-terminated string: `request.read_string(address, max: 4096)`
- Raw bytes: `request.read(address, length)`
- Socket address: `request.read_sockaddr(address, length)`, returning `Addrinfo`
- Continue after reading a pointer: `request.continue!(unsafe: true)`; the flag acknowledges the documented TOCTOU risk
- `request.pid` is the issuing thread ID and aliases `request.tid`

Both `sendmsg` and `sendmmsg` can be placed in a notification policy with version 0.3.0. The library keeps its listener-transfer descriptor available so `sendmsg` can be filtered safely. Bonebed v1 still observes only `open`/`openat`, `connect`, and `execve`.

An `execve` notification was continued successfully and decoded `/usr/local/bin/ruby` from its filename argument. Returning `Errno::ENETUNREACH` from a `connect` handler reached the target as expected.

## Open notification spike

`spike/open_spy.rb` observed `/etc/hostname` and 900 total `openat` calls for `ruby -e 'File.read("/etc/hostname")'`. The high count includes RubyGems and Bundler startup path searches and confirms that baseline subtraction is required.

Three wall-clock runs, in seconds:

| Run | Plain Ruby | Open notification |
| --- | ---: | ---: |
| 1 | 0.160 | 0.374 |
| 2 | 0.166 | 0.363 |
| 3 | 0.163 | 0.367 |

Median overhead was 2.25x (0.367 / 0.163). Printing all 900 paths was disabled during timing.

## Event dates

- Hokuriku RubyKaigi 02 CFP deadline: 2026-09-14
- Conference: 2026-11-14
