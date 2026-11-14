# VM source integration

Sol accepted Linux lifecycle source `443e0b453706dfa51696e0a8f8909db78cf5a4b0`; evidence snapshot `f0541db44b1245bab71ab17cef5029a500f53021` was merged, followed by Windows refusal source `27378f2eff3db4616554cdc469c3335665385a3b`. The only merge conflict was SPEC-019; both CR-026 stage isolation and the current Windows-unavailable probe description were preserved. Windows guest dispatch still returns unavailable before reading controls. Linux guest context and capability checks remain compiled separately.

Manager `cargo check --workspace --all-targets --locked` passed (exit 0, 28.95s) on combined source. Formatting after merge normalized the Windows test at `8d3134e`; `git diff --check` passed. Workspace Clippy with `-D warnings` failed platform/test dead-code/import/module-order diagnostics; assigned a narrow cleanup task. These checks do not establish runtime acceptance.

Root preparation/removal, real QEMU/KVM boot, QEMU acceptance of fd-backed 9p roots, guest filesystem/network/bait effects, timeout/recovery and export sequencing remain pending. Windows VM lifecycle/context implementation is unavailable; its guest/run/probe paths remain refused. Broader FR-027 runtime and Windows progress GUI gates and external FirewallAPI writer limitation remain open. Version is still 0.1.3; 0.1.4 is not release-ready.
