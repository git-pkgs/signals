# signals

A command for tracing security-relevant evidence stored in Git across repository history. It shows when detected evidence appears, changes, or disappears, with the commit and path behind each change. `signals` walks commit trees with [`github.com/git-pkgs/history`](https://github.com/git-pkgs/history). Local parsers detect workflow risks and permissions, artifact-provenance configuration, CI and security tools, threat surface, secrets, certificates and trust stores, Agent Skills, REUSE metadata, package managers, manifests, lockfiles, dependency pinning, update configuration, licenses, SBOMs, fuzzers, and binary artifacts. Commit data adds dependency-bot and signature events plus contributor, maintenance, review, and signing metrics. The output contains the evidence and its provenance without calculating a score. The scan reads local Git objects, with forge APIs, release APIs, credential validation, and external services disabled.

The local-only timeline answers questions about when repository evidence changed. Examples include:

- What was the complete detected state before and after a grant-funded period?
- When was a security policy, CI system, or security tool added or removed?
- Which commit introduced an unpinned GitHub Action or container image?
- How have workflow token permissions changed over time?
- When did a package manager, manifest, lockfile, or integrity record appear?
- How did Dependabot or Renovate configuration and schedules change?
- Did a credential enter the history, and when was it removed from the tree?
- How did licensing coverage, contributor activity, review proxies, and commit signing change?

## Repository evidence and limits

Git retains deleted configuration, earlier licensing coverage, embedded commit signatures, canonical author identities, and the exact commit that introduced or removed a file-backed practice. The same local scan works across hosting services and avoids API rate limits. Blob IDs and changed paths allow results to be reused across thousands of commits.

Some security state exists only on the hosting service or in an external dataset. Branch protection, webhooks, issue activity, successful CI runs, release assets, vulnerability databases, and external registries require separate sources. Review patterns in commit metadata do not prove that a pull request was approved, signature presence does not prove verification, and recent commits do not show whether a repository is marked as archived. Removing a credential from the tree does not remove its blob from Git history or show that it was revoked. Scorecard remains useful for current forge configuration and external evidence, while `signals` supplies the repository history those sources cannot reconstruct.

## Install

The project requires Go 1.27.3 or later. Install the latest version with:

```bash
go install github.com/git-pkgs/signals@latest
```

To work from source, build the current checkout directly. This writes the binary beside the source files:

```bash
go build -o signals .
```

## Quick start

Run `signals log` inside a Git repository, or pass another local repository as the final argument. History readers can work concurrently, while output remains in commit order:

```bash
./signals log --workers 8 .
./signals log --workers 8 --ref v1.0.0 .
./signals log --workers 8 --since v1.0.0 .
./signals log --workers 8 /path/to/repository
```

Date bounds make it possible to inspect changes around an event such as grant funding. `--after` includes the named UTC committer date, while `--before` excludes it:

```bash
./signals log --workers 8 --jsonl --snapshots \
  --after 2024-01-01 \
  --before 2025-01-01 \
  /path/to/repository > grant-window.jsonl
```

The scan still computes signal state before the lower bound. A removal within the selected dates can therefore refer to a signal added before the funding date. With `--snapshots`, the first JSONL record contains the complete signal set and 90-day commit metrics at the last first-parent commit before `--after`; the final record does the same for `--before`.

Flags must appear before the repository path. The timeline is written to stdout, while progress, detector errors, and optional statistics are written to stderr:

```bash
./signals log --workers 8 --progress 1000 --stats /path/to/repository \
  > /tmp/signals.log \
  2> /tmp/signals.stats
```

The `log` command accepts these options. Run `signals log --help` to print the same list locally:

```text
--ref REVISION   revision to walk (default HEAD)
--since REVISION exclude this revision and its ancestors
--after DATE     include commits on or after YYYY-MM-DD
--before DATE    include commits before YYYY-MM-DD
--workers N      concurrent history readers (default 1)
--progress N     report progress every N commits
--stats          report detector and blob-cache statistics
--jsonl          write JSON Lines change, event, and snapshot records
--snapshots      emit signal snapshots at both date boundaries
```

## Output

Each block names a commit where the detected state changed or commit-local evidence was found. A `+` line adds a signal, a `-` line removes the previous one, and a `*` line records an event:

```text
15dfa527561f  2016-12-18  Add support for Docker Compose development environment
  + Pinned-Dependencies/containerImage ruby at Dockerfile = unpinned

62308ad45a2d  2026-02-10  build(deps): Bump actions/checkout from 6.0.1 to 6.0.2
  * Dependency-Update-Tool/commit Dependabot
  * Signed-Commit/openpgp
  + Pinned-Dependencies/GitHubAction actions/checkout at .github/workflows/release.yml = pinned@de0fac2e4500dabe0009e67214ff5f5447ce83dd
  - Pinned-Dependencies/GitHubAction actions/checkout at .github/workflows/release.yml = pinned@8e8c483db84b4bee98b60c0593521ed34d9990e8
```

Non-merge commits are compared with their first parent. Merge snapshots are scanned and cached so later commits inherit the right state. Merge commits omit tree-state changes but can produce commit events.

### JSONL

`--jsonl` writes structured change and event records. Each record contains the full commit hash, author and committer identities and timestamps, and subject:

```json
{"type":"change","commit":"cb52a20b85fc2af8f7e6db0bc2cac843735eff49","author":{"name":"dependabot[bot]","email":"49699333+dependabot[bot]@users.noreply.github.com"},"committer":{"name":"GitHub","email":"noreply@github.com"},"authored_at":"2026-09-07T23:55:23Z","committed_at":"2026-09-08T00:02:11Z","subject":"build(deps): Bump zizmorcore/zizmor-action from 0.6.2 to 0.6.3","changes":[{"change":"added","check":"Pinned-Dependencies","kind":"GitHubAction","name":"zizmorcore/zizmor-action","value":"pinned@70fb788f84895a7701f5643d103d587e460b5c99","path":".github/workflows/zizmor.yml"},{"change":"removed","check":"Pinned-Dependencies","kind":"GitHubAction","name":"zizmorcore/zizmor-action","value":"pinned@3dc1ecc9bcb9e94e9b2c709687979e1298497054","path":".github/workflows/zizmor.yml"}]}
{"type":"event","commit":"cb52a20b85fc2af8f7e6db0bc2cac843735eff49","author":{"name":"dependabot[bot]","email":"49699333+dependabot[bot]@users.noreply.github.com"},"committer":{"name":"GitHub","email":"noreply@github.com"},"authored_at":"2026-09-07T23:55:23Z","committed_at":"2026-09-08T00:02:11Z","subject":"build(deps): Bump zizmorcore/zizmor-action from 0.6.2 to 0.6.3","events":[{"check":"Dependency-Update-Tool","kind":"commit","name":"Dependabot"},{"check":"Signed-Commit","kind":"openpgp"}]}
```

Change records have `type` set to `change`. Commit-local evidence uses `type: event` and an `events` array. Boundary records use `type: snapshot`, identify the `start` or `end` boundary, and contain the full detected state in `signals` plus commit-stream measurements in `metrics`. Ratios retain their numerator and denominator. `history_complete` is false for shallow or `--since` scans, and `mailmap_oid` identifies the `.mailmap` blob used to normalize contributor identities. Detector failures remain on stderr and also appear in an `errors` array when their state changes on an emitted commit. Every object occupies one physical line, including values containing escaped newlines.

Commit events cover dependency updates authored by Dependabot, Renovate, Scala Steward, or Greenkeeper and the presence of OpenPGP, SSH, X.509, or unclassified commit signatures. Signature presence does not imply successful verification.

Snapshot metrics use the preceding 90 days. They report non-bot contributor and email-domain counts, commit activity, review proxies, and signed-commit presence. Review proxies include pull-request merge and squash subjects, differing author and committer identities, and `Reviewed-by`, `Acked-by`, or `Tested-by` trailers. `Signed-off-by` remains separate because it records sign-off rather than review.

## Detected signals

Nine checks retain names used by Scorecard, but their evidence is detected by local parsers in `signals`.

| Check | Local evidence | Remote evidence omitted |
| --- | --- | --- |
| Binary-Artifacts | Compiled and packaged binary files identified by `git-pkgs/magic` and known extensions | Successful Gradle wrapper-validation runs |
| Dangerous-Workflow | Script injection and untrusted checkout patterns parsed with Actionlint | None |
| Dependency-Update-Tool | Dependabot, Renovate, and Scala Steward configuration | Dependabot-authored commit search |
| Fuzzing | ClusterFuzzLite configuration and language-specific source patterns outside bundled or derived paths | OSS-Fuzz membership |
| License | License and notice files classified by path, license expressions identified in their contents, and license values or file references declared by parsed manifests; manifest declarations are validated as strict, syntax-only, normalized, or invalid SPDX expressions | Forge license classification |
| SAST | Known Actions, Sonar configuration, and Qodana configuration | Successful check runs |
| SBOM | SPDX and CycloneDX documents detected from content, plus named candidates that cannot be parsed | Release assets |
| Security-Policy | Accepted policy paths with extracted email addresses and links | Inherited policy from the organization `.github` repository |
| Token-Permissions | Top-level and job-level Actions permission declarations parsed with Actionlint, with reusable definitions and calls identified separately | None |

The scan performs no network requests. Detector errors are reported on stderr. The previous successful state for that detector remains in place until detection succeeds again.

The additional detectors use the same persistent signal model. A threat-surface signal means the detected component makes that threat category relevant to the project. It does not identify a vulnerable version, an exploit, or a call to a dangerous API.

| Check | Local evidence |
| --- | --- |
| Artifact-Provenance | GitHub artifact-attestation actions and SLSA generator reusable workflows, including the workflow path; configuration does not show that a run completed or its claims were verified |
| Agent-Skill | Skill metadata, instruction digests, allowed tools, and script digests with file modes; scripts over 4 MB record size and mode without a content digest, and instruction text is not retained in output |
| CI | CI configuration detected by the Brief knowledge base, including GitHub Actions, GitLab CI, Azure Pipelines, CircleCI, Jenkins, Buildkite, Drone, and Travis CI |
| Build | Tools classified as build tools by Brief, including Make, CMake, Meson, Bazel, Buck, and language-specific build tools |
| Certificate | Certificate identities, fixed validity dates, CA status, trust-store collection digests, matches against embedded reference catalogs, and incomplete or oversized scan coverage |
| Security-Tool | Security tools detected by Brief, with its taxonomy function retained as the signal kind |
| Threat-Surface | Threat categories mapped by Brief from detected languages, package managers, application platforms, libraries, and tools; records the threat ID, introducing component, and CWE |
| Secrets-Management | SOPS configuration |
| Pre-Commit | pre-commit, Lefthook, Husky, and Overcommit configuration |
| Dependency-Update-Config | Dependabot and Renovate configuration, including package managers, directories, schedules, cooldowns, groups, and semantic configuration changes |
| Package-Manager | The selected package manager for each detected package ecosystem and project directory |
| Package-File | Manifest and lockfile presence, including files recognized by package-manager definitions before dependency parsing is available |
| Package-Provenance | Explicit npm publication provenance settings in `publishConfig.provenance` or `.npmrc` |
| Dependency-Constraint | Ranged, unparsed, and unversioned direct dependency constraints as written in parsed manifests |
| Dependency-Pin | Exact direct dependency constraints found in parsed manifests |
| Dependency-Pinning | Exact, ranged, unparsed, and resolved dependency counts from manifests and lockfiles |
| Lockfile-Integrity | Dependencies with declared integrity metadata compared with the total entries in a lockfile |
| Pinned-Dependencies | Repository-based `uses` steps pinned to commit hashes and container images pinned to SHA-256 digests, parsed from changed workflows, Dockerfiles, and Compose files |
| Cache-Mode | Explicit workflow and job cache access modes parsed from Actions workflows |
| Job-Timeout | Configured Actions job timeouts, including expression-backed values |
| Packaging | Literal packaging and publication commands or known publication Actions; presence does not show that a workflow ran |
| Package-Provenance | Explicit npm provenance flags or environment settings, and PyPI publication configured with an OIDC token |
| Runner-Selection | Explicit self-hosted runner labels, runner groups, and dynamic runner expressions in GitHub Actions jobs |
| Package-Parse | Package files that were identified but could not be parsed |
| Secret | Findings from the embedded `git-pkgs/secrets` rule corpus; output contains `[redacted]` in place of the credential |
| REUSE | Per-file SPDX license declarations, REUSE.toml or DEP5 metadata, and the number of non-empty covered files with both license and copyright information |

## History scanning

The root commit and missing history boundaries receive a full scan. Later commits reuse their first parent's signal state and update the paths changed by that commit. Cross-file detectors, including Agent Skills, dependency-update configuration, and REUSE metadata, receive a full commit tree when one of their inputs changes. Agent Skills rerun when a `SKILL.md` or a file inside a known skill package changes.

Parser results for changed files are cached by Git blob OID and path for the whole run. Repository files that cannot contain a certificate, license, SBOM, fuzzer, policy, or SAST configuration need only a 1 KB prefix for binary classification. Commit reading can run concurrently, while signal-state updates remain ordered. `github.com/git-pkgs/languages` keeps a language inventory so Brief can rerun language-gated detection only when needed. `github.com/git-pkgs/roles` removes bundled and derived paths from fuzzing and license detection, and removes test, fixture, example, cache, and build-output paths from certificate detection. Test paths remain eligible for fuzz detection because fuzz targets commonly use them.

Brief reads commit trees through `history.TreeFS` and reruns only when Brief's changed-file filter identifies an input to one of the emitted tool signals. Package files are parsed when their paths change, and the parse result supplies dependency constraints, pins, Actions references, container images, lockfile resolution, integrity records, and manifest-declared license values or file references. Results are cached by blob OID and path. Shell commands that download or install packages are not yet included in this local package detector. Package-manager detection uses `managers.AffectedDirectories` to rescan only the affected projects. Secret scanning updates changed paths and caches results by blob OID and path because some rules depend on the filename. REUSE metadata changes trigger a full REUSE scan; ordinary changes update the affected file state and coverage count.

## Related git-pkgs modules

The local detectors share parsers and changed-path caches across related signals:

- [`github.com/git-pkgs/magic`](https://github.com/git-pkgs/magic) detects binary content.
- [`github.com/git-pkgs/certs`](https://github.com/git-pkgs/certs) scans bounded certificate files, trust stores, and small archives.
- [`github.com/git-pkgs/licenses`](https://github.com/git-pkgs/licenses) identifies license text, notices, and SPDX declarations with its embedded ScanCode corpus.
- [`github.com/git-pkgs/manifests`](https://github.com/git-pkgs/manifests) parses package metadata, declared licenses, Actions, Docker, NuGet, and other dependency files.
- [`github.com/git-pkgs/managers`](https://github.com/git-pkgs/managers) identifies package managers and their manifest or lockfile evidence from commit trees.
- [`github.com/git-pkgs/sbom`](https://github.com/git-pkgs/sbom) identifies and parses SPDX and CycloneDX JSON documents.
- [`github.com/git-pkgs/spdx`](https://github.com/git-pkgs/spdx) validates and normalizes SPDX expressions declared by package manifests.
- [`github.com/git-pkgs/brief`](https://github.com/git-pkgs/brief) detects CI systems, build tools, security tools, and pre-commit runners from an `fs.FS` commit tree.
- [`github.com/git-pkgs/languages`](https://github.com/git-pkgs/languages) detects source languages from paths and blob content.
- [`github.com/git-pkgs/reuse`](https://github.com/git-pkgs/reuse) resolves SPDX headers, sidecars, REUSE.toml annotations, and DEP5 metadata from an `fs.FS` commit tree.
- [`github.com/git-pkgs/roles`](https://github.com/git-pkgs/roles) classifies CI, fuzz, legal, generated, vendored, and packaging paths.
- [`github.com/git-pkgs/secrets`](https://github.com/git-pkgs/secrets) scans changed blob content with its embedded local rule corpus.
- [`github.com/git-pkgs/skills`](https://github.com/git-pkgs/skills) discovers and parses Agent Skill packages from commit trees.

Actionlint parses each changed Actions workflow once for Artifact-Provenance, Dangerous-Workflow, SAST, Token-Permissions, Cache-Mode, Job-Timeout, Packaging, Package-Provenance, and Runner-Selection signals. Package parsing separately records Actions references and their pinning state. Packaging observations cover known Actions and literal commands in `run:` steps without treating their presence as evidence of a successful workflow run. Package provenance requires an explicit npm setting, or an OIDC-enabled PyPI publication without a configured password or uv token. Runner observations record configuration without determining which machine handled a particular job.

## Development

Run the tests with the standard Go command. The suite covers the CLI boundary and historical state changes:

```bash
go test ./...
```

## License

[MIT](LICENSE).
