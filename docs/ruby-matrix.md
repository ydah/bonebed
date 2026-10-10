# Comparing Ruby runtimes

The Docker wrapper can observe the same command or gem under several Ruby versions:

```sh
bonebed --docker dig rainbow --phase all --offline --ruby 3.3,3.4,4.0
bonebed --docker run --ruby 3.3,4.0 -- ruby -e 'require "socket"'
```

`--ruby` belongs to the wrapper and is accepted before the target's `--` separator. It supports
`dig`, `survey`, `run`, and `bundle`, with one to eight distinct major.minor versions. Each version
runs sequentially with the usual read-only project mount, bounded container resources, private
temporary directory, and dedicated writable results mount. Target arguments after `--` are literal.

Every invocation creates `results/ruby-matrix-<unique>/ruby-<version>/` (or the selected `--results`
directory). Separate runs therefore cannot silently reuse observations from an earlier matrix.
The final JSON output names that directory, each container's exit status, and capability additions
and removals between adjacent requested versions. Comparisons require matching gem version,
platform, require path and phase, or the same command. Failed targets, observer errors, and missing
observations are excluded from comparison; absence does not mean a capability was absent. Repeated
observations require a complete group and compare the union of capabilities, without comparing event
counts across runtimes. A container that exits successfully without producing any observations is an
observer failure (exit 2). Request command help without `--ruby`.

The default images are `ghcr.io/ydah/bonebed:<tool-version>-ruby<major.minor>`. The release workflow
builds pinned Ruby 3.3, 3.4 and 4.0 variants for both Linux architectures; these tags become available
only after a release publishes them. Other versions require operator-built images. The manifest's
actual Ruby version is checked against the requested version, and a mismatch returns exit 2.

For local images, build each runtime from a reviewed base digest and select a template containing
exactly one `%{ruby}` placeholder:

```sh
docker build --build-arg RUBY_IMAGE=ruby:3.3@sha256:a91b6ac1b9b18d33812480856e4bc39c5c492ff9c6cc810d916cc3f0cc1d0eab -t bonebed:local-ruby3.3 .
docker build -t bonebed:local-ruby4.0 .
BONEBED_RUBY_IMAGE='bonebed:local-ruby%{ruby}' bonebed --docker run --ruby 3.3,4.0 -- ruby -e 'puts RUBY_VERSION'
```

`BONEBED_IMAGE` still selects the ordinary single-image wrapper; `BONEBED_RUBY_IMAGE` selects matrix
images. The wrapper does not mount the host Docker socket or credentials into observation containers.
Different Ruby standard libraries and resolved dependency versions can themselves produce differences;
review the saved environment and dependency metadata before attributing a change to the target gem.
