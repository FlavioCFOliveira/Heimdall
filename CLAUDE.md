# Heimdall

Open-source DNS server written in **Rust**, with performance and security as its primary focus.

**By design**, this server targets environments of **EXTREMELY HIGH LOAD AND CONCURRENCY**.

## Core principles

### SECURITY (non-negotiable)

Security is **non-negotiable**. Every change to the code must account for **ALL possible attack vectors** that could compromise the server, including (but not limited to):

- DNS protocol attacks (cache poisoning, amplification, reflection, spoofing, DNS rebinding).
- Resource exhaustion (memory, CPU, sockets, file descriptors, DoS/DDoS).
- Parsing vulnerabilities (malformed packets, buffer overflows, integer overflows, truncation).
- Injection and untrusted input at any system boundary.
- Side-channel attacks (timing, cache).
- Supply chain risks (external dependencies must be audited and kept to the strict minimum).
- Misuse of `unsafe`: every `unsafe` block requires an explicit justification and documented invariants.

Code must fail safely (**fail-safe / fail-closed**) and must never expose internal state, stack traces, or sensitive information in responses.

### PERFORMANCE (guiding principle for all decisions)

Performance is the **primary guide** for every decision across the entire stack:

- **Data structures**: chosen according to actual access patterns, not by habit. Measure before deciding.
- **Algorithms**: prioritise appropriate asymptotic complexity and cache-friendly behaviour (locality of reference).
- **Design patterns**: prefer zero-cost abstractions; avoid indirection, unnecessary allocations, and superfluous cloning.
- **Concurrency**: lock-free / wait-free designs when justifiable; otherwise, carefully chosen lock granularity. Avoid contention.
- **Architecture**: asynchronous I/O, syscall minimisation, batching, and zero-copy wherever possible.
- **Hardware**: leverage SIMD, memory alignment, prefetching, and NUMA awareness where applicable.
- **Operating system**: use the most efficient APIs available (io_uring on Linux, kqueue on BSD/macOS, `SO_REUSEPORT`, and so on).

**Golden rule**: *measure before deciding, measure after changing*. Benchmarks and profiling are part of the development cycle — they are not optional.

### Conflict between security and performance

When the two principles conflict, **security prevails**. Performance never justifies opening an attack vector.

## Assume Nothing

**Only what is explicitly written in the specification is true.** Everything else is unknown and must be clarified before any action is taken. This principle is absolute and overrides convenience, speed, and apparent obviousness.

The assistant **MUST NEVER**:

- Infer requirements, behaviours, or constraints that are not stated.
- Fill gaps with "reasonable defaults", industry conventions, or common sense.
- Rely on its own memory, training data, or prior experience as a source of project truth.
- Interpret unclear instructions by guessing intent.
- Proceed in the presence of contradictions, incompleteness, or ambiguity — no matter how minor.

The assistant **MUST STOP AND ASK** the user whenever any of the following occurs:

- A doubt, however small.
- Missing information.
- Incomplete information.
- Contradictions between instructions, specification, and/or code.
- Ambiguities that admit more than one valid interpretation.
- A user request that is unclear or open to multiple readings.

No action — writing code, creating files, running commands, making design decisions — may be taken while any of these conditions remain unresolved.

### Clarification procedure

When clarification is required:

1. Identify the uncertainty precisely and state it to the user.
2. Gather the best available options, labelled `a)`, `b)`, `c)`, and so on.
3. State the **recommended option**, together with its justification.
4. Ask the user. When multiple clarifications are needed, ask **sequentially** — one question at a time. Never batch.
5. Wait for an explicit answer before proceeding. Do not act in parallel or "while waiting".

### Persisting the outcome

Once a clarification is received, the assistant **must persist the decision** in the appropriate place, so that the same question is never asked again:

- If the clarification belongs to the project scope (requirements, design decisions, invariants, architectural constraints, behaviour), **update the specification**.
- If the clarification concerns collaboration preferences, workflow, or user-specific context outside the spec, save it as a **memory** entry.
- If the clarification is purely local to the current task, reflect it in the active plan or task list.

**A clarification that is not persisted has no value — the same question will have to be asked again, and the project's source of truth will drift.**

## Collaboration rules

### Decision authority

See [**Assume Nothing**](#assume-nothing) — the core principle that governs this rule. The assistant is never authorised to make decisions unilaterally, and must always clarify with the user following the procedure defined there.

### Documentation language

All project documentation **must be written in English**, in impeccable form — free of spelling, grammatical, and syntactic errors. The language must be technical, clear, simple, and unambiguous, targeted at human readers.

### Documentation fidelity

Documentation must be **accurate and faithful to the code**. It must reflect the actual behaviour of the current implementation, never aspirations or obsolete descriptions. Outdated documentation is a defect and must be corrected as part of the change that caused the divergence.

### Workflow

All work must follow these steps, in this order, without exception:

1. **Specify** — define what must be built: requirements, constraints, invariants, and acceptance criteria.
2. **Implement** — write the code strictly according to the specification.
3. **Test** — verify the implementation through unit, integration, and, where appropriate, performance tests.
4. **Document** — produce or update documentation that accurately reflects the delivered behaviour.

No step may be skipped or reordered.

### Task and sprint management

All task and sprint management for this project **must be done exclusively through the `rmp` CLI tool**, invoked via the `rmp` skill. The `rmp` roadmap is the **single source of truth** for tasks, sprints, backlog, priorities, dependencies, and status — no other tracking surface may compete with it.

The assistant **must**:

- Create every task in `rmp`. A task may not exist only in conversation, memory, ad-hoc notes, or in-session lists.
- Create every sprint in `rmp`, and plan work against concrete `rmp` sprints.
- Consult `rmp` at the start of every work session to determine the current sprint, the next actionable task, and outstanding dependencies.
- Update task status in `rmp` as work progresses (`BACKLOG` → `SPRINT` → `DOING` → `TESTING` → `COMPLETED`), so that the recorded state always reflects reality.
- Treat `rmp` as authoritative: whenever any other source — memory, conversation, plan, in-session task list — disagrees with `rmp`, `rmp` wins and the other source must be corrected.

Ephemeral in-session task lists may be used as local scratchpads, but they must never replace or precede the creation of the corresponding `rmp` entries.
