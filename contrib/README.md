# Docker syscall profile

`docker-seccomp.json` derives from [Moby profiles](https://github.com/moby/profiles/blob/2ceae35d351c156cb5a8efc0fdc4a08cf94569d8/seccomp/default.json), under the Apache 2.0 license in `MOBY-LICENSE`.

The only additional permissions are `unshare(CLONE_NEWUSER | CLONE_NEWNET)` for offline namespaces and `io_uring_setup` so the inner observation filter can record the attempt and return ENOSYS. Default-denied operations remain denied by the outer filter and may therefore be invisible to the inner observer. This profile requires a recent Docker/libseccomp release with the syscall names in the upstream profile.
