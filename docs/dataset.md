# Local observation datasets

`bonebed dataset RESULTS --output DIRECTORY` exports a static site and machine-readable data from
existing observations. It does not execute gems, upload files, create a repository, or send notifications.
Open `DIRECTORY/index.html` in a browser to search gem names and inspect observed capabilities.

## Exported files

| File | Contents |
| --- | --- |
| `index.html` | Searchable gem directory; search runs locally in the browser |
| `gems/NAME.html` | Observations by version, phase, platform, and require path |
| `search-index.json` | Gem names, versions, phases, and relative page paths |
| `manifests.json` | Original manifests, including tool, run, and environment metadata for reproduction |
| `changes.json` | Added and removed capability keys between adjacent observed versions |
| `changes.rss` | The same changes as an RSS 2.0 feed |
| `badges/NAME.json` | Shields endpoint data reporting whether network activity was observed |

Version comparisons use RubyGems version ordering and compare only observations with matching gem
name, phase, platform, require path, executable invocation, and observation settings. Unresolved versions such as `unknown` remain visible but
are excluded from chronological comparisons. Changes in call counts alone do not create feed entries.
Repeated samples contribute the union of observed keys for each version; the feed does not compare
two samples of the same version as if a new release occurred.
A comparison can reflect environment or execution differences as well as changes to the gem itself;
inspect the reproduction metadata before drawing conclusions.

Badges summarize the latest observed version across available phases and platforms. They say
`observed`, `not observed`, or `unknown` when an incomplete run has no recorded network activity.
They do not assert safety, complete coverage, or lack of malicious behavior. Hosted Shields badges
require publishing the JSON endpoint separately; the exporter does not do that.

Generated pages escape target-controlled text and link to the correction issue template. The RSS
feed describes observed changes without assigning a maliciousness label. Its channel link points
to the Bonebed project until a publisher chooses a dataset-specific feed URL.

## CycloneDX augmentation

The Ruby API can add observations to an existing CycloneDX JSON document:

```ruby
dataset = Bonebed::Dataset.new("results")
sbom = JSON.parse(File.read("bom.json"))
File.write("bom-observed.json", JSON.pretty_generate(dataset.augment_sbom(sbom)))
```

Components match exact gem name and version. A component with a package URL from another ecosystem
is left unchanged. The `bonebed:capabilities` property stores a JSON array of capability keys, combined
across observed phases and platforms. Existing unrelated properties are preserved, and repeated
augmentation replaces the Bonebed property without duplicating it. The input object is not modified.

## Reproduction and publication

Retain the original manifests and the container image digest alongside published data. Tool versions,
kernel, architecture, baseline IDs, and recorded mode settings are preserved, but the exporter cannot
recover missing historical metadata or infer an image digest that was never recorded.

Use a new output directory for a fresh publication. Re-exporting atomically replaces generated files
but leaves unrelated or obsolete files in place. Symlink output files and gem/badge directories are
rejected. Before choosing to publish, review captured output, command arguments, paths, and metadata
for private data. A disposable environment and fake credentials reduce exposure; they do not guarantee
that every manifest is suitable for public distribution.

Scheduling surveys, publishing datasets, signing artifacts, monitoring RubyGems releases, and notifying
maintainers are separate operational steps. This export command performs none of those actions.

## Monitor a local watchlist

Place one gem name per line in `watchlist.txt`, then run:

```sh
bonebed monitor --file watchlist.txt --results results --state .bonebed/monitor.json
```

The monitor reads the official [RubyGems versions API](https://guides.rubygems.org/rubygems-org-api/#get---apiv1versionsgem-namejsonyaml),
selects stable releases compatible with the local platform, and runs install plus require observations.
The CLI selects offline observations and quiet target output; RubyGems plugin loading is included when
declared by the package. The injected Ruby API `Dig` can choose other modes.
It never evaluates metadata returned by the registry. HTTP connections have a 5-second open timeout,
a 10-second read timeout, a 30-second total request limit, and an 8 MiB response limit. Redirects,
HTTP errors, malformed JSON, and malformed version records are treated as errors.

For a gem without successful local observations, the first run starts at the latest available release.
If earlier observations exist, it starts with releases newer than the most recent successful install
and require pair. Subsequent runs retain that starting point and record individual successful versions,
so an intermediate failed version remains retryable even after a newer version succeeds. Target and
observer errors both prevent a monitoring success checkpoint. A failed first observation does not
create a success state file.

Explicitly yanked releases, prereleases, and versions no longer listed by the registry are not newly
observed. Existing observations and checkpoints are retained; disappearance is not evidence of malicious
behavior. Corrupt state is rejected without overwriting it. Successful checkpoints use atomic writes,
and a nonblocking lock prevents two monitors from using the same state file at once. Keep state and
results together when backing up or moving a watchlist.

Checkpoints are scoped to the local platform and the injected `Dig` observation mode, including offline,
honeypot, environment profile, write-only capture, real-home/project choices, enforcement-policy digest,
and repetition count. Incomplete repeated-observation groups cannot advance a checkpoint.
Changing those settings cannot reuse a success checkpoint from a different mode. Required RubyGems
plugin observations must also succeed before that gem version is checkpointed.

Each run refreshes the local dataset at `RESULTS/dataset/`, including its JSON and RSS change feeds.
It does not publish the feed or send email, chat messages, issues, or abuse reports. The Ruby API accepts
an injected `Dig` object; its offline and environment settings control how observations execute.

## Opt-in scheduled survey template

[examples/data-workflow.yml](../examples/data-workflow.yml) is an inactive example until copied into
`.github/workflows/` by an operator. It splits a curated 1000-name `data/top1000.txt` into ten shards,
runs at most two shards concurrently, and retains compressed observations as review artifacts.
The list is supplied by the operator: the current RubyGems ranking scraper exposes only 100 gems,
so the example does not claim to fetch an authoritative top 1000 list automatically.

Set `BONEBED_DATA_IMAGE` to a reviewed production image reference pinned with `@sha256:` and a full
digest. The placeholder deliberately fails validation. All Actions are pinned to full commit hashes.
Target containers receive a writable observation directory but no checkout credentials, host home,
or service tokens. They use the bundled Docker seccomp profile; their root filesystem is read-only
and resources are bounded. These limits do not
replace the threat model or a dedicated environment for hostile samples.

The template requests a GitHub artifact attestation for each completed archive, including archives
containing failed observations. The signed digest binds the archive bytes to the workflow identity;
it does not certify that a gem is safe or that an observation is complete. The attestation step uses
OIDC on the runner after the target container exits; the target receives no signing credentials.
After downloading an archive, verify it against the actual publishing repository before extracting it:

```sh
gh attestation verify bonebed-shard-0.tar.gz --repo OWNER/bonebed-data
```

Retain the verification output and confirm its workflow/ref matches the publisher you intended to
trust. Repacking or editing an archive changes its digest. This source template has not itself produced
a published dataset attestation; operators must enable it and verify a real run.

The template runs fresh surveys; it does not restore monitoring state, publish a website, create an
external dataset repository, or notify maintainers. Configure those operational steps separately if
needed, and retain the image digest from each artifact for reproduction.

## Review observations before public allegations

Describe a changed capability and the command/environment that produced it. Do not label a gem or
author malicious solely because a rule fired, credentials were probed, or a version was yanked.
Reproduce the finding, compare environments and dependency changes, inspect observer errors and
truncation, and determine whether the activity has an ordinary explanation. Have a person review
high-impact findings before publishing allegations or contacting an abuse team.

Use private maintainer or registry security channels for sensitive exploit details; follow
[SECURITY.md](../SECURITY.md) for problems in Bonebed itself. The exporter and monitor never send such
reports automatically. Gem authors can request corrections through the
[misleading observation template](https://github.com/ydah/bonebed/issues/new?template=false_positive.yml).
Include the observation identity and a reproducible explanation, remove private data, and preserve a
record of corrected findings so readers can distinguish an observation from its interpretation.
