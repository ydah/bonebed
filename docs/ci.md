# CI integration

The repository's test matrix enables unprivileged user namespaces on its disposable GitHub-hosted
Ubuntu runners so the sinkhole fixtures execute rather than skip. This test-only kernel setting is
not applied by the CLI or container launcher. Restricted hosts still receive a sinkhole setup error
before target execution; see [sinkhole requirements](sinkhole.md).

Use the composite action on a Linux GitHub-hosted runner with Docker. It builds the checked-out action source, compares the base and head `Gemfile.lock`, observes changed or added dependencies, and writes a Markdown diff, JSON diff, and SARIF report. Unchanged dependencies are not executed.

Pin the action to a reviewed full commit SHA. A workflow in this repository can use `uses: ./` after checkout. Other repositories use `uses: ydah/bonebed@<reviewed-full-commit-sha>`.

```yaml
name: Dependency capabilities
on:
  pull_request:
    paths: [Gemfile.lock]
permissions:
  contents: read
jobs:
  observe:
    runs-on: ubuntu-24.04
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          persist-credentials: false
      - uses: ydah/bonebed@<reviewed-full-commit-sha>
        id: bonebed
        with:
          base-sha: ${{ github.event.pull_request.base.sha }}
          fail-on: high
          offline: 'true'
          results: bonebed-results
```

The action accepts `fail-on: info|low|medium|high|critical|none`. Its threshold applies to the default policy findings for the current versions of changed dependencies, including capabilities also present in their previous versions. `none` still records findings but does not fail because of them. Observation failures still fail the job. Results are exposed as `steps.bonebed.outputs.sarif` and `steps.bonebed.outputs.markdown`; the Markdown diff is also appended to the job summary.

To publish SARIF to code scanning, retain the report as an artifact and add a separate upload job using a reviewed, SHA-pinned `github/codeql-action/upload-sarif`. Download the report there and grant `security-events: write` only to that job. Public fork pull requests may restrict token permissions; keep the report as an artifact when upload is unavailable. Use SHA-pinned artifact actions and `if: always()` to retain the reports even when observations or policy checks fail.

The observation container receives only two read-only lockfiles and the dedicated writable results directory. It runs with an unprivileged UID, a read-only image, no Linux capabilities, and process/memory limits. The disposable `/tmp` mount permits execution because native-extension builds run compiler probes and load shared libraries there. The Docker socket, repository `.git`, host HOME, and runner environment are not mounted or forwarded; `GITHUB_TOKEN` and cloud credentials are not available to target gems. Package resolution needs container network access; `offline: true` asks Bonebed to block target network calls while prefetching happens outside observation. This mode has the limitations described in [the threat model](threat-model.md).

The container uses the checked-in `contrib/docker-seccomp.json` profile, which permits the offline namespace and observation setup while retaining Docker's default syscall restrictions. Operations blocked by the outer profile may be invisible to the inner observer. Use disposable hosted runners rather than privileged or persistent hosts. Never mount a Docker socket into the observation container, and never run this workflow under `pull_request_target` with untrusted code checked out.

## Pull request comments

Keep comments in a separate `workflow_run` workflow. The observation job needs no `pull-requests: write` permission. Upload only the generated Markdown and a small metadata file containing the pull request number and observed head SHA. In the privileged workflow, verify the triggering workflow, repository, event, and head SHA against GitHub's API before posting. Treat the downloaded report as data: do not source it, execute scripts from the artifact, or interpolate it into shell commands. Use a structured API body or a file argument. Pin all actions to reviewed SHAs and keep the commenter free of repository code execution.

## Other CI systems

Build the image from reviewed source with `docker build -t bonebed .`. Run `bonebed diff-lock BASE_LOCK HEAD_LOCK --offline --format json` inside a disposable container, then `bonebed check RESULTS --fail-on high` to enforce the policy. Use the same read-only input mounts, dedicated writable results mount, unprivileged UID, read-only image, and lack of credential mounts as the composite action. GitLab can retain the JSON/Markdown reports as job artifacts; SARIF support depends on the GitLab integration in use.

Local pre-commit checks can run `bonebed check results --lock Gemfile.capabilities.lock` against existing observations. Avoid executing newly added dependencies in a developer's credential-bearing process just to update an approval file.

The optional [Bundler plugin](bundler-plugin.md) applies a stricter saved-observation gate before frozen
installation: each compatible locked package must have exact-version approvals and complete observations.
Its hook runs after Gemfile evaluation and is disabled when Bundler plugins are disabled.

[examples/gitlab-ci.yml](../examples/gitlab-ci.yml) supplies an opt-in merge-request job for an ephemeral
Linux shell runner with Docker. Set `BONEBED_CI_IMAGE` to a reviewed image digest, provide the bundled
`contrib/docker-seccomp.json` at the indicated path, and register the dedicated runner tag. The job
mounts only the two lockfiles and results, retains artifacts on failure, and uses no privileged Docker
service. Review runner trust before enabling it for fork contributions. The example assumes the base
revision already has a lockfile.

[examples/lefthook.yml](../examples/lefthook.yml) adds a local pre-push check of existing observations
and the separate capability approval lock. Merge it into your Lefthook configuration after generating
and reviewing both. It does not refresh stale observations or prove they match an unobserved lockfile
change; the isolated CI observation remains necessary.

The nightly workflow runs fixed Linux fixtures, a fixed three-sample benchmark, and a separate live
top-20 RubyGems survey. A separate job compares retained artifacts with the previous successful run
of the same workflow and branch, searching at most the latest 100 successful runs. Only this comparison
job has `actions: read`; target execution receives no GitHub token. Downloads have deadlines and require
matching workflow, repository, run, and artifact metadata. The JSON comparison artifact records missing
history, invalid inputs, failed observations, and incompatible contexts explicitly; it creates no issues
or external notifications. The [hosted validation record](validation.md) includes a successful
comparison with the previous workflow's observations.
Older successful runs without a benchmark still provide observation history; their benchmark result
is explicitly `no_previous_benchmark`. Missing current artifacts or invalid existing artifacts fail retrieval.

Capability comparisons require successful known target status, matching observer/dependency versions,
Ruby/architecture/kernel, observation mode and invocation. Plugin/bundle observations also require a
matching Bundler version. Package version changes are reported separately from added/removed capabilities,
and added capabilities carry default-policy findings. Benchmarks record CPU, kernel, Ruby, observer,
workload and mode metadata; only exact known environments are compared. The report shows sample means
and deltas, without an uncalibrated performance pass/fail threshold or safety verdict.

## Release image provenance

The tag-triggered release workflow verifies the package version and runs checks before publishing.
Its container job builds amd64/arm64 images, requests BuildKit provenance and an SBOM, and submits a
GitHub build-provenance attestation for the published digest using OIDC. This workflow is implemented
but has not yet produced a release image or verified attestation for the unreleased changes. Review
the release environment and trusted-publishing configuration before tagging; source configuration
alone does not establish an artifact's provenance.
