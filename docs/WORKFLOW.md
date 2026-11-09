# Implementation workflow

The BRD, PRD and FRD record the user-authorized baseline. The SPEC files define ownership and technical design. The test plan and traceability map link each requirement to observable evidence.

1. Coordinator claims tasks and records file ownership.
2. Worker implements the assigned spec and tests in its own worktree.
3. Coordinator integrates the worker commit and runs shared tests.
4. Reviewer records verification by test ID, platform, tested SHA and command. Missing evidence remains pending.
5. Coordinator updates the task board and completed work log.

Use the original agent hook checks throughout. Routine implementation choices within the baseline may proceed autonomously. Record material changes in the requirement change log and seek a decision only for the affected work. Continue independent tasks.
