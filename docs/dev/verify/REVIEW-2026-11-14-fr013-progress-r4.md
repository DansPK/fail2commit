# FR-013 progress re-review — round 4

**Pinned submitted snapshot:** `f928a451758a8fac774ac80989bf000f1cabe5e9`. Code fix reviewed: `7b775d10c6cd2d5ec74765d1ae12a1833bd1e403`, against previous snapshot `1991f1fca09ce346e0027d659c52adb1a6cf0098` and r3 report `74f436a2741891ef5919b3ed26afaec0217ebe08`. Scope was the sole r3 monotonic-step finding. Earlier source-accepted fixes were not reopened by this delta.

## Verdict

**Source accepted for integration.** The r3 regression is resolved: pip candidate activity stays in `Resolve`, and `DownloadVerify` begins once, after the final plan is known. This is a code-review verdict, **not** full FR-013 platform verification.

## Finding disposition and evidence

| r3 finding | Disposition | Evidence |
|---|---|---|
| Pip moved from `DownloadVerify` back to `Resolve` | **Resolved in source** | `crates/fail2commit-core/src/pip/proxy.rs:173-180,286-295` emits candidate text with `advance(0, ...)` and no `step(DownloadVerify, 0)`. `pip/mod.rs:153-154,273-292` remains in Resolve while the final report is parsed, completes Resolve at `1/1`, then calls `step(DownloadVerify, wheels.len())` and advances the selected plan count. The second Resolve call is an equal-step reset, so the Step sequence is nondecreasing under the frozen `progress.rs:11-23` rule. |

The backtracking integration test at `crates/fail2commit/tests/pip_install.rs:117-198` fetches a rejected beta 2.0 wheel, asserts its candidate events have `done=0` while the active step is Resolve, checks the **entire** step sequence for monotonic order, requires the resolver's own completion before final DownloadVerify, and checks the final plan's immediate `3/3` event. These assertions cover the failure mode from r3 rather than merely checking a helper in isolation. The verification report records exit 0 for that test, the result-helper pipe EOF regression, six core progress tests, format check, and `git diff --check` on `7b775d1`. It also records one overlapping Windows linker collision followed by a sequential pass; the transient failure was a build-artifact collision, not a passing test result. I inspected the exact delta and test assertions and ran `git diff 1991f1fc 7b775d1 --check` (exit 0); no cold broad build was needed for this focused review.

## Remaining platform gates

Windows native window first paint within 1 second, clean auto-close, retained result while the CLI exits, close without cancelling an active review, setting toggle, and current-source Windows npm/pip integration remain **pending** on an unlocked disposable Windows desktop. The previously reported AppContainer `CreateAppContainerProfile` HRESULT `0x80070002` also prevents treating the Windows package runtime as passed. The earlier Debian guest PTY npm/pip installs and timing results used source `40c512efa2fee78ad440ca71178a74856a2b4d8f`, not this exact code fix; they support the unchanged terminal path but are not a new exact-source runtime pass. No VM, host integration, production code, or published artifact was changed in this review.
