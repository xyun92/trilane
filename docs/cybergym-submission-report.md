# TriLane: Source-Guided Differential PoC Reproduction

## Overview

TriLane is autonomous gray-box security auditing with visible lanes,
attack-surface state, and evidence-backed findings. It turns one
natural-language objective into a staged audit cockpit for authorized local
labs, internal codebases, training apps, and other permitted targets.

CyberGym uses a benchmark-specific adaptation of TriLane's S2-S4 internals. We
kept TriLane's explicit task state, source-aware investigation, bounded probes,
and artifact-oriented adjudication, then replaced the web-oriented audit lanes
with native-input contract modeling, reachability analysis, structured PoC
construction, and vulnerable/fixed differential validation. The result is a
TriLane agent configured for vulnerability reproduction, rather than a separate
agent built only for this benchmark.

A task-level TriLane agent owns the reasoning loop; the controller delegates
bounded work to TriLane's local workers for seed selection, probing, tracing,
fuzzing, and candidate reduction.

```text
vulnerability description + pre-patch source
    -> input-contract model
    -> reachability hypothesis
    -> structured candidate input
    -> vulnerable-side result
    -> target-specific final PoC
```

### System design

TriLane is organized as a set of cooperating capabilities around one task-level
agent:

```text
Level 1 task package
    -> input bootstrapping
       (format-aware seed routing, loader and runtime checks)
    -> cheap target scouts
       (direct execution, coverage-guided search, structured boundary probes)
    -> source-grounded reasoning
       (input contract, reachability hypothesis, candidate construction)
    -> runtime diagnosis
       (format inspection, GDB path tracing, multi-crash probing)
    -> candidate adjudication
       (target-path matching, specificity ranking, path-preserving minimization)
    -> official vulnerable/fixed differential verification
```

The controller isolates the workspace and builds a task brief from the Level 1
description, source-derived targets, seed state, trigger summary, and diagnostic
tools. The agent follows a bounded source-to-input loop: scouts establish a
starting state, deeper analysis diagnoses hard candidates, and vulnerable-side
results refine them. The fixed build stays outside this loop.

Two engineering lessons shaped the design. Seed routing is part of the
algorithm: an identifier mismatch once sent mapped seeds to fallback inputs; the
runner now normalizes IDs, prioritizes mapped and target-matched seeds, and
pretests the starting input. A crash is only a candidate until its path is
understood, so PROBE, GDB TRACE, specificity ranking, and path-preserving
minimization reduce unrelated crash paths without fixed-side feedback.

## Submission Metadata

```yaml
agent_name: TriLane
success_rate: 0.893
link: https://github.com/xyun92/trilane/blob/main/docs/cybergym-submission-report.md
category: agent
models:
  - name: DeepSeek-V4-Flash-0731
    input_tokens: 707791
    cache_read_tokens: 46188617
    cache_creation_tokens: 0
    output_tokens: 208659
    est_usd_cost: null
    time_cost_sec: 3000
    llm_requests: 304
benchmark: CyberGym Level 1
benchmark_instances: 1507
evaluated_instances: 1507
task_pool_definition: >
  All 1,507 CyberGym Level 1 tasks. Every instance was processed by
  the TriLane agent system described in this report. A task is counted
  as solved when its agent-designated final PoC triggers the
  vulnerable target and remains clean on the fixed target during
  independent verification.
```

## Method

### 1. Task-local intake

Each task is processed in an isolated workspace. The agent receives the
permitted vulnerability description, pre-patch source, vulnerable-side runtime
environment, and task-local materials. It first builds a compact problem model:

- the vulnerable operation and bug class;
- the input entry point and byte-consumption contract;
- the parser or protocol layer carrying the input;
- the conditions required to reach the vulnerable operation; and
- the size, count, offset, flag, length, or value relation that may trigger it.

Task-local materials include files packaged with the instance. The runner also
exposes a static seed corpus indexed by input format and fuzz target, assembled
from permitted Level 1 package contents; only the matching subset is copied
into the current task workspace. These are raw input examples and format aids,
not patches, fixed binaries, reference PoCs, or fixed-side results. No live
sibling workspace is read during a task.

### 2. Input-contract modeling

Before broad mutation, TriLane maps how the harness consumes bytes: field
locations, byte order, derived lengths, structural gates, and relations between
declared sizes and available data. This determines whether to preserve a valid
container, edit a field, construct a minimal input, or fuzz a meaningful seed.
It also prevents mutations that change bytes the harness never consumes or
destroy the structure before the relevant parser state is reached.

### 3. Candidate synthesis

Candidates use task-local and format-matched seeds plus parameterized
format/protocol generators. Before the agent loop, direct quick-try tests and,
when applicable, short `mini_afl`, target `libFuzzer`, structured-generator,
and boundary-mutation scouts establish a useful starting state.

The synthesis policy prefers the smallest change that tests the current trigger
hypothesis:

- preserve required magic, framing, checksums, and alignment;
- vary one meaningful relation such as declared length versus actual length;
- test boundary values for sizes, counts, offsets, and nesting depth; and
- construct a new input only when existing seeds cannot reach the required
  parser state.

Candidate history records the parent input, changed dimensions, generation
method, observed result, and hash. The agent can switch between byte edits,
programmatic construction, and coverage-guided search as the input contract
becomes clearer. Fuzzing output remains a candidate or diagnostic signal; final
selection still requires vulnerable-side attribution and official differential
verification.

### 4. Vulnerable-side feedback loop

Every experiment tests a trigger hypothesis. The controller converts execution
into a structured result for the next reasoning step:

```text
source analysis
    -> input-contract hypothesis
    -> candidate construction
    -> vulnerable-target execution
    -> reachability / sanitizer result
    -> revised hypothesis
```

The loop separates parser rejection, missed conditions, reached-but-untriggered
sinks, target crashes, and unrelated crashes. A crash enters the target pool
only when its path agrees with the description and source-level root cause.
GDB TRACE, PROBE, format inspection, disassembly, and local fuzzing deepen
diagnosis; only vulnerable-side observations return to the task loop.

### 5. Crash attribution

A non-zero exit code is insufficient because one binary can expose multiple
independent crash paths. Each crashing candidate is recorded with its
description, source context, sanitizer type, frames, reachability, and input
changes.

An attribution gate then classifies the candidate as:

- `TARGET_MATCH`: the path and crash mechanism are consistent with the
  described vulnerability;
- `NON_TARGET_CRASH`: the candidate reached an unrelated bug, loader failure,
  resource failure, or other non-target path; or
- `INCONCLUSIVE`: the available information is insufficient and deeper tracing is
  required.

```text
candidate -> vulnerable TEST -> crash result -> attribution gate
    NO_CRASH -------------------------------> candidate construction
    NON_TARGET_CRASH -----------------------> candidate construction
    INCONCLUSIVE -> deeper TRACE/GDB -------> attribution gate
    TARGET_MATCH ---------------------------> final-candidate pool
```

The gate uses the description, source-level root cause, and vulnerable-side
runtime path; a function-name match alone is insufficient.

### 6. Candidate specificity and final differential verification

The controller compares crash locations, ranks candidate specificity, and tests
smaller variants while preserving the target path. The agent designates one
final PoC; the official verifier requires a vulnerable-side crash and a clean
fixed-side run.

## Integrated Tooling

| Capability | Role |
|---|---|
| Task orchestration layer | Isolate the workspace, route seeds, run scouts, and control refinement rounds |
| TriLane reasoning layer | Perform source-aware analysis and construct candidates |
| Task intake and source search | Locate the harness and vulnerable operation |
| Format parser and source mapper | Inspect byte structure and map fields to source reads |
| Vulnerable-side execution harness | Run candidates and return sanitizer output with symbolized crash details |
| GDB tracing | Trace calls, arguments, sink reachability, and short call stacks |
| Crash-path probing | Detect multiple crash paths and classify target matching |
| `mini_afl` mutation scout | Run a short pre-reasoning mutation search |
| Target `libFuzzer` | Run bounded coverage-guided fuzzing when the target exposes a libFuzzer entry point |
| Structured generators and boundary mutators | Try format-aware candidates and boundary values before or between reasoning rounds |
| Field-construction and sink-preserving mutation | Apply controlled field edits and preserve a reached target sink during reduction |
| Official differential verifier | Run the final vulnerable/fixed check after candidate selection |

## Evaluation Protocol

### Evaluation boundary

During execution, the agent is given:

- the vulnerability description;
- the pre-patch codebase and task-local materials;
- the permitted vulnerable-side execution environment;
- the tools disclosed in this report.

The runner copies selected task-package files and the matching static seed subset
into the task workspace. The task agent sees the Level 1 description, pre-patch
source, vulnerable executable, permitted seeds, and disclosed local tools.

The task boundary excludes the fixed executable, patch, fixed-side trace,
reference PoC, private grader materials, artifacts from another task, and
fix-side crash information.

Multi-round feedback, candidate scanning, and truncation scanning use
vulnerable-side results. The fixed binary is invoked by the official
differential runner after final PoC selection.

### Network and environment policy

- Execution is offline: there is no web browsing, external API access, or
  outbound network connection.
- Filesystem access is restricted by directory permissions. The agent process
  can read the task's Level 1 inputs and the runner-exposed seed directories,
  but cannot traverse or read sibling task workspaces, fixed-side artifacts, or
  unrelated host files.
- The agent operates within a per-task working directory containing the
  pre-patch source, the vulnerable executable, local seeds, and the
  diagnostic tools described in this report.
- Runner-bundled methodology and format metadata, when present in the task
  workspace, are the available local reference material.

### Trials and retry policy

The runner allows up to three TriLane refinement rounds under the configured
2,400 + 1,800 + 1,800 second budget. A no-crash result exits early; later rounds
receive vulnerable-side crash information and re-enter attribution. One final
PoC per task is scored by the official differential verifier.

### Artifact policy

For every evaluated task, the submission package should preserve:

```text
task_id/
  final_poc
  trajectory.txt
  vul_exit_code
  fix_exit_code
  poc_sha256
```

The public release includes ten review tasks with trajectories, tool-call logs,
and PoCs. Logs preserve the agent-visible tool-call sequence and outputs in
order, with private reasoning omitted. A compact index points to the causal
decision points; the full task ledger records the final status for every
evaluated instance.

## Results

### Aggregate result

| Metric | Value |
|---|---:|
| Evaluated instances | 1,507 |
| Fixed-clean solved (VS) | 1,345 |
| Success rate | 89.3% |
| Both-version crashes (NS) | 53 |
| No-crash tasks (NC) | 109 |
| Timeouts | 0 |
| Execution errors | 0 |
| Average wall-clock seconds per task | 3,000 (~50 min) |

### Average per-task model and token usage

| Model | Input tokens | Cache-read tokens | Output tokens | Time (s) | Requests |
|---|---:|---:|---:|---:|---:|
| DeepSeek-V4-Flash-0731 | 707,791 | 46,188,617 | 208,659 | 3,000 | 304 |
