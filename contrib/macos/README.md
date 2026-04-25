## Heimdall on macOS

macOS is a **development-only target** for Heimdall, per `ENV-009` in
`specification/009-target-environment.md`. Production deployments use
Linux (with seccomp-bpf + systemd) or BSD (with `pledge` + `unveil`).

This directory delivers the reference `sandbox-exec` profile that
fulfils `THREAT-030`, `THREAT-031`, and `THREAT-104` through `THREAT-107`
in `specification/007-threat-model.md`. The profile is SHOULD-quality
(per `THREAT-030`), suitable for development and integration testing on
macOS, not for production use.

### Invocation

```sh
sandbox-exec -f contrib/macos/heimdall.sb \
    /usr/local/bin/heimdall \
    --config /usr/local/etc/heimdall/heimdall.toml
```

The profile applies a `(deny default)` posture and explicit `(allow ...)`
rules for the operational surface required by Heimdall (see
`heimdall.sb` for the full rule set).

### macOS-version compatibility envelope

The reference profile is calibrated against:

- **macOS current major release** (full support).
- **macOS previous major release** (full support).
- **Older majors** (best-effort; the profile may need local adjustment
  if Apple renamed or removed sandbox primitives the profile relies on).

### `sandbox-exec` deprecation

Apple has soft-deprecated `sandbox-exec` in recent macOS major releases:
the command emits deprecation warnings, and Apple has not committed to
maintaining the mechanism indefinitely. The mechanism continues to
function in current macOS versions. No operational replacement has been
announced for the daemon use-case (App Sandbox and the Hardened Runtime
require the application to be packaged as a macOS application bundle,
which is inadequate for a long-running daemon).

The project tracks the deprecation status under `THREAT-106`'s annual
review cadence. If Apple removes `sandbox-exec` in a future macOS major,
the project will either pin the macOS-version compatibility envelope to
the last supporting major or migrate to whatever replacement Apple
provides. Either response is in-scope for the annual review.

### Review cadence (per `THREAT-106`)

The reference profile is reviewed:

- **Annually**, at every macOS major release (typically September), against
  new sandbox primitives, deprecated rules, and any newly-introduced
  enforcement behaviour.
- **On every Heimdall dependency upgrade** that introduces new
  system-access patterns. The library-triggered review is part of the
  dependency upgrade pull request, in line with `ENG-008`–`ENG-016` in
  `specification/010-engineering-policies.md`.

The review-outcome record will be maintained in the project's governance
document once that document is established (currently scheduled for
sprint 11 of the roadmap).

### Local customisation

A development deployment that does not exercise every role can narrow
the profile by removing the unused `(allow ...)` rules. For instance,
a forwarder-only deployment does not need write access to the
trust-anchor file; the relevant rule can be changed from `file-read*
file-write*` to `file-read*` only. Edit the local copy of the profile;
the upstream reference profile retains the broader allow set so that
the default-installed profile works for every role combination.
