# Check approvals before Bundler installs gems

Bonebed ships an optional Bundler plugin. Once explicitly installed, its `before-install-all` hook
checks saved observations against `Gemfile.lock`, `Gemfile.capabilities.lock`, and the capability
policy. A failure raises a Bundler error and stops installation. The plugin never downloads packages,
executes observations, updates approvals, or evaluates a Gemfile itself.

Bundler has already evaluated the project's Gemfile when this hook runs. The plugin therefore cannot
sandbox an untrusted Gemfile or make installing hostile gems safe. Run Bundler only in a suitable
environment; use `bonebed bundle` for a disposable, observed installation. Other installed Bundler
plugins and RubyGems plugins remain part of the trusted Bundler process.

## Prepare observations and review approvals

Generate observations in a disposable Linux environment, then review the resulting capability lock:

```sh
bonebed lock --gemfile Gemfile.lock --phase all --offline --results results
bonebed check results --lock Gemfile.capabilities.lock --strict
```

The plugin requires full schema v2 install and require observations for every locked package compatible
with the local platform, including transitive dependencies. A declared RubyGems plugin also needs its
plugin phase. The approval version and observed version/platform must match the lockfile exactly.
Each required phase must be explicitly approved, even when its capability list is empty.

Missing or invalid files, target/observer errors, unknown target status, write-only observations, and
incomplete repeat groups stop installation. Capability keys outside the approved set also stop it,
regardless of severity. Separately, policy findings at the configured threshold stop installation unless
allowed by the policy. Listing a capability in the approval lock does not override a policy rule.

Repeated observations must agree on the requested repetition count, per-sample count, group, and
completion summary, with every sample index present. A `complete` flag alone is insufficient. Every
JSON file under the selected results directory is parsed and checked before duplicate observations
are selected. Malformed JSON or an invalid observation structure fails the check even if other files
provide a successful observation for the same gem. Keep exported datasets, monitor state, and other
JSON documents outside this plugin input directory.

Only `https://rubygems.org` lock sources are supported. Git, path, other registries, and source-plugin
sections are rejected. The plugin checks compatible platform variants conservatively; a lock containing
both `ruby` and a matching native platform needs observations for both variants. Saved observations
and policies must come from a trusted review process; their content is not cryptographically authenticated.
The approval format does not bind the installed archive's SHA-256 to the observed archive. Matching
name, version, platform, and registry therefore relies on Bundler's source/checksum verification and
the integrity of its local package cache. A replaced local archive with the same identity is outside
this check's guarantees. Review and protect those inputs separately from capability approvals.

## Install explicitly in a trusted project

The published 0.1.0 gem does not contain this plugin. For this source checkout, work inside a trusted
project containing a Gemfile so Bundler uses that project's `.bundle/plugin` directory. First make
Bonebed's runtime dependencies available there. A fully local setup can seed reviewed package archives:

```sh
gem install --local /reviewed/cache/seccomp-notify-0.3.0.gem --install-dir .bundle/plugin --no-document
env -u BUNDLE_PATH BUNDLE_IGNORE_CONFIG=true bundle plugin install bonebed --path /absolute/path/to/bonebed
bundle plugin list
```

Seed any nondefault dependency archives, such as `fiddle`, in the same directory if needed. Bundler's
path-plugin installer does not automatically resolve missing dependencies from RubyGems. The temporary
environment settings above keep a project's separate application installation path out of plugin
bootstrap. No global plugin installation is needed. After a version containing the plugin is published,
`bundle plugin install bonebed --version REVIEWED_VERSION` provides the normal registry installation
route; that explicit installation may use the network.

Then run a frozen install, enabling plugins explicitly:

```sh
BUNDLE_PLUGINS=true BUNDLE_FROZEN=true bundle install --local
```

`--local` is optional and controls Bundler's package retrieval, not the observation checker. Frozen
mode is required so Bundler cannot resolve a changed Gemfile into unreviewed versions. A second hook
checks the actual name/version/platform before each package install. Bundler's own already-running
metadata specification is the only implicit exception; a Bundler package explicitly listed in the
lockfile still needs approval during the initial check.

Use `bundle plugin uninstall bonebed` from the same project to remove the registration. Disabling
Bundler plugins also disables this check; this is a developer/CI guard, not an enforcement boundary.
Keep the explicit `bonebed check` CI job when plugin configuration is not controlled.

## Paths and errors

Defaults are relative to the Gemfile's project root, including when Bundler is called from a subdirectory.

| Environment variable | Default |
| --- | --- |
| `BONEBED_PLUGIN_RESULTS` | `results` |
| `BONEBED_PLUGIN_LOCK` | `Gemfile.capabilities.lock` |
| `BONEBED_PLUGIN_POLICY` | `.bonebed.yml` if present; otherwise built-in rules |

Explicit paths can be absolute or relative to that root. A missing explicitly selected policy fails.
The hook reads Bundler's selected lockfile and raises a `Bundler::BundlerError` subclass for rejection;
the enclosing `bundle` process exits unsuccessfully. Bonebed CLI exit-code meanings do not apply to
Bundler's exit code.

The implementation uses the [documented Bundler plugin API](https://guides.rubygems.org/bundler_plugins/)
and its before-install hooks. Local integration checks covered Ruby 3.3.12/Bundler 2.5.22,
Ruby 3.4.11/Bundler 2.6.9, and Ruby 4.0/Bundler 4.0.16. The repository's Ruby matrix exercises the same
subprocess fixtures; hosted results for a particular commit must be checked separately.
