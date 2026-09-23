# signals

A command for tracing repository-contained security signals across Git history. It shows when detected evidence appears, changes, or disappears, with the commit and path behind each change.

`signals` walks commit trees with [`github.com/git-pkgs/history`](https://github.com/git-pkgs/history) and runs ten raw detectors from OpenSSF Scorecard v5.5.0. The output contains raw findings and omits score calculation. The scan reads only local Git objects, with forge APIs, release APIs, and external services disabled.

The local-only timeline answers questions about when repository evidence changed. Examples include:

- When was a security policy added or removed?
- Which commit introduced an unpinned GitHub Action or container image?
- How have workflow token permissions changed over time?
- When did SAST, fuzzing, dependency updates, or SBOM files first appear?

## Install

The project requires Go 1.26. Install the latest version with:

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

Date bounds make it possible to inspect changes around an event such as grant funding. `--after` includes the named author date, while `--before` excludes it:

```bash
./signals log --workers 8 --jsonl --snapshots \
  --after 2024-01-01 \
  --before 2025-01-01 \
  /path/to/repository > grant-window.jsonl
```

The scan still computes signal state before the lower bound. A removal within the selected dates can therefore refer to a signal added before the funding date. With `--snapshots`, the first JSONL record contains the complete signal set at the last first-parent commit before `--after`; the final record does the same for `--before`.

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
--jsonl          write one JSON object per changed commit
--snapshots      emit signal snapshots at both date boundaries
```

## Output

Each block names a commit where the detected state changed. A `+` line adds a signal, while a `-` line removes the previous one:

```text
15dfa527561f  2016-12-18  Add support for Docker Compose development environment
  + Pinned-Dependencies/containerImage ruby at Dockerfile:1 = unpinned

62308ad45a2d  2026-02-10  build(deps): Bump actions/checkout from 6.0.1 to 6.0.2
  + Pinned-Dependencies/GitHubAction actions/checkout at .github/workflows/release.yml:20 = pinned@de0fac2e4500dabe0009e67214ff5f5447ce83dd
  - Pinned-Dependencies/GitHubAction actions/checkout at .github/workflows/release.yml:20 = pinned@8e8c483db84b4bee98b60c0593521ed34d9990e8
```

Non-merge commits are compared with their first parent. Merge snapshots are scanned and cached so later commits inherit the right state, while merge commits produce no timeline block themselves.

### JSONL

`--jsonl` writes one object per changed commit. Each object contains the full commit hash, author identity and timestamp, subject, and structured additions or removals:

```json
{"type":"change","commit":"cb52a20b85fc2af8f7e6db0bc2cac843735eff49","author":{"name":"dependabot[bot]","email":"49699333+dependabot[bot]@users.noreply.github.com"},"authored_at":"2026-09-07T23:55:23Z","subject":"build(deps): Bump zizmorcore/zizmor-action from 0.6.2 to 0.6.3","changes":[{"change":"added","check":"Pinned-Dependencies","kind":"GitHubAction","name":"zizmorcore/zizmor-action","value":"pinned@70fb788f84895a7701f5643d103d587e460b5c99","path":".github/workflows/zizmor.yml","line":30},{"change":"removed","check":"Pinned-Dependencies","kind":"GitHubAction","name":"zizmorcore/zizmor-action","value":"pinned@3dc1ecc9bcb9e94e9b2c709687979e1298497054","path":".github/workflows/zizmor.yml","line":30}]}
```

Change records have `type` set to `change`. Boundary records use `type: snapshot`, identify the `start` or `end` boundary, and contain a `signals` array with the full detected state. Detector failures remain on stderr and also appear in an `errors` array when their state changes on an emitted commit. Every object occupies one physical line, including values containing escaped newlines.

## Detected signals

The command runs ten Scorecard checks. Several retain the repository-backed part of a check because Scorecard combines local files with remote evidence.

| Check | Local evidence | Remote evidence omitted |
| --- | --- | --- |
| Binary-Artifacts | Binary files identified by content or extension | Successful Gradle wrapper-validation runs |
| Dangerous-Workflow | Script injection and untrusted checkout patterns in Actions workflows | None |
| Dependency-Update-Tool | Dependabot, Renovate, and Scala Steward configuration | Dependabot-authored commit search |
| Fuzzing | ClusterFuzzLite configuration and source patterns for supported languages | OSS-Fuzz membership and forge language statistics |
| License | Root license filename detection | Forge license classification |
| Pinned-Dependencies | Actions, container images, shell downloads, Dockerfiles, workflow scripts, and NuGet configuration | None |
| SAST | Known Actions and Sonar configuration in `pom.xml` | Successful check runs |
| SBOM | Root source SBOM filenames | Release assets |
| Security-Policy | Policy files and their contact or disclosure text | Inherited policy from the organization `.github` repository |
| Token-Permissions | Top-level and job-level Actions permissions | None |

Unsupported client methods return Scorecard's `ErrUnsupportedFeature`, and the scan performs no network requests. Detector errors are reported on stderr. The previous successful state for that check remains in place until detection succeeds again.

## History scanning

The root commit receives a full scan. Later commits reuse their first parent's signal state and rerun a detector only when relevant paths change. Checks with cross-file behavior, including License, SBOM, Security-Policy, dependency-update configuration, and NuGet pinning, receive a full commit tree when one of their inputs changes.

File content is cached by Git blob OID for the whole run. Unchanged bytes are read once even when they appear in many commits or several detectors request them. Commit reading can run concurrently, while signal-state updates remain ordered.

## Performance

One development run scanned the full Octobox history at `b71659d9399a`. Its 5,756 commits completed in 6.71 seconds with eight history workers. The run read 10,083 unique blobs, served 19,510 of 29,593 reads from the blob cache, and produced a 95 KB timeline. `Pinned-Dependencies` accounted for 5.29 seconds of detector time.

## Related git-pkgs modules

The Scorecard dependency brings a large set of transitive packages and repeatedly parses the same files for related checks. Existing git-pkgs modules already cover several parts of the scan:

- `github.com/git-pkgs/magic` detects binary content.
- `github.com/git-pkgs/licenses` finds license texts, notices, and SPDX declarations.
- `github.com/git-pkgs/manifests` parses Actions, Docker, NuGet, and other dependency files.
- `github.com/git-pkgs/sbom` identifies and parses SPDX and CycloneDX JSON documents.
- `github.com/git-pkgs/roles` classifies CI, fuzz, legal, generated, vendored, and packaging paths.

A shared Actions workflow parser could remove the largest duplication outside Pinned-Dependencies. One parsed workflow could feed Dangerous-Workflow, action pinning, SAST, Token-Permissions, Packaging, and Gradle wrapper validation.

## Development

Run the tests with the standard Go command. The suite covers the CLI boundary and historical state changes:

```bash
go test ./...
```

## License

[MIT](LICENSE).
