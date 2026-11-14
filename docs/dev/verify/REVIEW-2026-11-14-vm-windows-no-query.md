# Windows unsupported-VM preflight review

Manager source inspection of `27378f2eff3db4616554cdc469c3335665385a3b` relative to `054bc809952473b006284b897512c80636bb2025`.

The active preflight now reads only the firmware virtualization processor feature. Proven absence maps to the documented fallback. Otherwise it returns lifecycle-unavailable before an external query, install-path inspection, mapping or VM launch. The synchronous feature-query code and its process/pipe helpers are removed. Thus VM-R4-01 no longer applies to an active feature-query path; no absolute query-I/O deadline is claimed. The existing Windows guest dispatch refusal remains in the branch. Dormant WSB launch code is unreachable through current selection and must not be enabled without supported instance lifecycle/context proof.

Worker reports Windows VM tests 9 passed, guest-refusal test 1 passed, targeted rustfmt and diff check exit 0. These were not repeated by manager. Full formatting was blocked in the worker by unrelated uncommitted Linux module wiring; the combined source must be checked after manager integration. No WSB boot or full FR-029 verification is established. Source is acceptable as an unavailable Windows backend; Linux review and final shared-file integration remain pending.
