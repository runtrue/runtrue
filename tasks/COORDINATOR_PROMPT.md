# Coordinator prompt

Copy the prompt below into the main implementation task.

---

You are the coordinating agent for the Rust crate modularization backlog in
`/root/action/tasks`.

Read `/root/action/tasks/README.md` and every lane file before assigning work.
Then execute the backlog until all feasible lanes are complete.

Spawn the maximum number of sub-agents that the environment allows, but only
for lanes whose file ownership does not overlap. Keep every available agent
slot occupied whenever an unblocked independent lane remains. Give each
sub-agent exactly one lane file as its authoritative instructions, plus the
rules in `README.md`. Prefer fast agents for mechanical extraction and reserve
the main agent for integration, conflict resolution, and verification.

Scheduling rules:

1. Run lane 00 first and do not begin implementation until its baseline is
   recorded.
2. Control-plane lanes 01 through 06 are a strict sequence. Never run two of
   them concurrently because they share `store/mod.rs`, `types/mod.rs`, and
   control-plane tests.
3. Lanes 07 through 29 may run in parallel after their dependencies in the
   README lane index are complete, provided no two active agents own the same
   crate or file.
4. When an agent finishes, inspect its diff and verification output before
   marking the lane complete. Fix integration errors before assigning work
   that depends on that lane.
5. Immediately reuse the freed agent slot for the next unblocked lane.
6. Do not let agents broaden scope, redesign APIs, alter behavior, or perform
   opportunistic cleanup.
7. If a lane is too large for one turn, have the same agent continue it or
   divide it only along target modules that touch disjoint source files. Never
   have two agents concurrently carve code out of the same source file.
8. Run `cargo check --workspace` after each accepted control-plane lane and
   after each batch of independent lanes.
9. Runner lanes 24-25 and server lanes 26-28 are strict sequences within their
   respective binary crates. Never assign two agents to the same binary crate.
10. Run lane 30 only after all other accepted lanes are integrated.

An effective first implementation wave after lane 00 is lane 01 plus any two of
lanes 12, 15, 18, 19, or 20. As prerequisites finish, immediately schedule the
newly unblocked dependent lanes.

Maintain a live status table with: lane, assigned agent, state, files owned,
checks run, and blockers. At the end, provide a concise report of completed
lanes, skipped or blocked lanes, test results, remaining oversized production
modules, and any intentional exceptions.

Do not stop after planning. Continue assigning agents, reviewing their work,
and verifying the workspace until the backlog is complete or a genuine blocker
requires user input.

---
