# Policies and enforcement

Bonebed has two separate policy formats. A capability policy evaluates saved observations and can
fail CI. A Landlock policy restricts supported operations while target code runs. Passing a capability
policy to `--enforce` is an error; a successful post-execution check is not proof that execution was confined.

## Evaluate observations

`bonebed check results --policy .bonebed.yml --fail-on high` evaluates capability keys and exits 3 when
an unapproved finding meets the threshold. The default rules cover credential reads, install-time
network activity, Git hook writes, fileless execution, external commands, threads, and exposed canaries.
Severities are `info`, `low`, `medium`, `high`, and `critical`.

```yaml
version: 1
defaults:
  fail_on: high
  require_container: true
rules:
  extends: default
  disable: []
allow:
  demo:
    install:
      - 'exec:/usr/bin/make'
```

Gem and capability patterns support globs. Allow rules are scoped to a gem and phase; approved findings
remain visible but do not fail checks. `rules.custom` accepts full rule objects containing `id`,
`severity`, and a nonempty `match` array, with optional `phase`, `message`, and HTTPS references.
A custom rule can replace a default rule with the same ID. Unknown configuration fields, severities,
and disabled rule IDs are rejected. YAML object deserialization and aliases are disabled.
The boolean CLI defaults `require_container`, `allow_host`, and `verbose` control host-execution checks
and diagnostics. An explicit `--allow-host` overrides a configured container requirement.
`defaults.top_fallback` accepts a nonempty path to an operator-reviewed, ranked gem-name list used only
when a `survey --top` lookup fails. `--top-fallback FILE` overrides that path; snapshot validation and
update instructions are described in the README.

`check` accepts `--format md|json|csv|html|sarif`. Use `--gemfile Gemfile.lock` to locate SARIF results
on matching lockfile entries. `--strict` fails on observer errors before treating a policy result as
successful. Target failures remain failures regardless of whether policy findings are approved.

`diff`, `compare`, `diff-lock`, and `history` classify changed capabilities with the default rules
for their observed phase. JSON preserves the `added` and `removed` key arrays and includes `findings`
for additions and `removed_findings` for removals. Markdown displays their severities; SARIF includes
only additions, using the same rule IDs and levels. Capabilities without a matching rule are labeled
`unclassified-capability` at `info`; this is not a safety verdict. Counts alone do not create findings.

## Capability approval lock

```sh
bonebed lock --gemfile Gemfile.lock --offline
bonebed check results --lock Gemfile.capabilities.lock
bonebed lock --gemfile Gemfile.lock --update demo --offline
```

The separate `Gemfile.capabilities.lock` records observed keys by gem and phase. Added keys generate
findings on subsequent checks. Updating one gem preserves other approvals. Generating or updating the
lock executes observations and refuses to approve target or observer failures. Run it in a disposable
environment and review the resulting diff before approving changes.

## Restrict target execution with Landlock

Create a separate file such as `enforcement.yml`:

```yaml
read_paths: []
write_paths: []
tcp_connect_ports: []
tcp_bind_ports: []
```

Then use it on an observation:

```sh
bonebed dig demo --phase all --enforce enforcement.yml --offline --strict
```

Bonebed adds its required runtime read paths and disposable environment to this configuration. Listed
read paths grant reading and execution; write paths grant supported read, write, creation, removal,
rename, and execution operations beneath a directory or on a single file. Paths must exist and be
absolute after expansion of `$HOME`, `$PWD`, `$GEM_HOME`, and `$TMPDIR`. These placeholders refer to
the observation environment. They do not grant access to the invoking user's directories automatically.

TCP port lists are allowlists on kernels supporting Landlock ABI 4 or newer. Empty lists deny supported
TCP bind/connect operations. Earlier ABIs support filesystem rules only and reject nonempty TCP lists.
ABI 1 lacks cross-directory rename grants; ABIs 1 and 2 cannot mediate truncation. The implementation
handles device ioctl rights from ABI 5, but does not claim to mediate every kernel operation. Check
`bonebed doctor` and the [threat model](threat-model.md) before relying on a particular restriction.

If the kernel cannot apply requested Landlock rules, execution fails rather than silently continuing
without them. Rules affect the target child and its descendants; they are not a policy for unrelated
processes. Combining `--enforce` and `--offline` applies both filesystem/TCP restrictions and the selected
offline mechanism. `--strict` makes a namespace fallback an automation failure.

`bonebed policy generate results > enforcement.yml` drafts rules from recorded activity. Review that
output: observed paths can refer to temporary files that no longer exist, placeholders, or paths that
should not be granted. Replace appropriate temporary file entries with intentionally chosen existing
directories. The generated file is a starting point, not automatic approval of every observed action.
