#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowPrompt {
    pub phase_id: String,
    pub stage_id: String,
    pub title: String,
    pub prompt: String,
    pub is_repair: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowLaneSpec {
    pub lane_id: String,
    pub title: String,
    pub prompt: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowLaneBatch {
    pub phase_id: String,
    pub stage_id: String,
    pub title: String,
    pub lanes: Vec<WorkflowLaneSpec>,
    pub is_repair: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkflowAction {
    Submit(WorkflowPrompt),
    SpawnLanes(WorkflowLaneBatch),
    DeferPhase {
        phase_id: String,
        stage_id: String,
        title: String,
        reason: String,
        next: Box<WorkflowAction>,
    },
    Complete,
    Blocked(String),
}

#[derive(Debug, Clone)]
pub struct TriLaneWorkflow {
    objective: String,
    phases: Vec<WorkflowPhase>,
    current: usize,
    repairs_for_current: usize,
    progress_repairs_for_current: usize,
    progress_seen_for_current: bool,
    phase_start: WorkflowCounters,
}

#[derive(Debug, Clone)]
struct WorkflowPhase {
    id: &'static str,
    stage_id: &'static str,
    stage_code: &'static str,
    title: &'static str,
    contract: &'static str,
    body: &'static str,
    gate: PhaseGate,
    hard_gate: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PhaseGate {
    S0Admission,
    S1Surface,
    S2Lane,
    S3Merge,
    S4Probe,
    S5Adjudicate,
    S5Review,
    S5FinalRevision,
}

#[derive(Debug, Clone, Copy, Default)]
struct WorkflowCounters {
    surfaces: usize,
    coverage_mapped: usize,
    candidates: usize,
    claims: usize,
    findings: usize,
    commands: usize,
    subagents: usize,
    probes: usize,
    controls: usize,
    verifies: usize,
    dispositions: usize,
    s4_skips: usize,
}

impl TriLaneWorkflow {
    pub fn new(objective: String) -> Self {
        Self {
            objective,
            phases: default_phases(),
            current: 0,
            repairs_for_current: 0,
            progress_repairs_for_current: 0,
            progress_seen_for_current: false,
            phase_start: WorkflowCounters::default(),
        }
    }

    pub fn begin(&mut self, state: &RunbookState) -> WorkflowAction {
        self.submit_current(state, false)
    }

    pub fn after_turn_completed(&mut self, state: &RunbookState) -> WorkflowAction {
        let Some(phase) = self.phases.get(self.current) else {
            return WorkflowAction::Complete;
        };

        if phase_satisfied(phase, self.phase_start, state) {
            self.current += 1;
            self.repairs_for_current = 0;
            self.progress_repairs_for_current = 0;
            self.progress_seen_for_current = false;
            return self.submit_current(state, false);
        }

        let progressed = phase_progressed(phase, self.phase_start, state);
        if progressed {
            self.progress_seen_for_current = true;
        }

        let max_progress_repairs = max_progress_repairs_for_phase(phase, state);
        if self.progress_seen_for_current && self.progress_repairs_for_current < max_progress_repairs {
            self.progress_repairs_for_current += 1;
            return self.submit_current(state, true);
        }

        let max_repairs = max_repairs_for_phase(phase, state);
        if self.repairs_for_current < max_repairs {
            self.repairs_for_current += 1;
            return self.submit_current(state, true);
        }

        if phase.gate == PhaseGate::S4Probe {
            let phase_id = phase.id.to_string();
            let stage_id = phase.stage_id.to_string();
            let title = phase.title.to_string();
            self.current += 1;
            self.repairs_for_current = 0;
            self.progress_repairs_for_current = 0;
            self.progress_seen_for_current = false;
            let next = self.submit_current(state, false);
            return WorkflowAction::DeferPhase {
                phase_id,
                stage_id,
                title,
                reason: "S4 probe phase did not produce live proof after repair; preserving claims as needs-poc/source-backed instead of blocking the whole scan".to_string(),
                next: Box::new(next),
            };
        }

        if phase.hard_gate {
            WorkflowAction::Blocked(format!(
                "WORKFLOW% blocked phase={} title=\"{}\" reason=\"phase contract was not satisfied after repair\"",
                phase.id, phase.title
            ))
        } else {
            self.current += 1;
            self.repairs_for_current = 0;
            self.progress_repairs_for_current = 0;
            self.progress_seen_for_current = false;
            self.submit_current(state, false)
        }
    }

    fn submit_current(&mut self, state: &RunbookState, is_repair: bool) -> WorkflowAction {
        let Some(phase) = self.phases.get(self.current) else {
            return WorkflowAction::Complete;
        };
        self.phase_start = WorkflowCounters::from_state(state);
        if phase.id == "s2_parallel_semantic_audit" {
            return WorkflowAction::SpawnLanes(s2_lane_batch(
                phase,
                &self.objective,
                state,
                is_repair,
            ));
        }
        if phase.id == "s5_adversarial_review" {
            return WorkflowAction::SpawnLanes(s5_review_lane_batch(
                phase,
                &self.objective,
                state,
                is_repair,
            ));
        }
        WorkflowAction::Submit(WorkflowPrompt {
            phase_id: phase.id.to_string(),
            stage_id: phase.stage_id.to_string(),
            title: phase.title.to_string(),
            prompt: phase_prompt(
                phase,
                self.current + 1,
                self.phases.len(),
                &self.objective,
                state,
                is_repair,
            ),
            is_repair,
        })
    }
}

impl WorkflowCounters {
    fn from_state(state: &RunbookState) -> Self {
        Self {
            surfaces: state.surfaces.len(),
            coverage_mapped: state
                .coverage
                .iter()
                .filter(|coverage| coverage.status != crate::runbook::CoverageStatus::Pending)
                .count(),
            candidates: state.candidates.len(),
            claims: state.claims.len(),
            findings: state.findings.len(),
            commands: evidence_count(state, "command"),
            subagents: evidence_count(state, "subagent"),
            probes: evidence_count(state, "probe"),
            controls: evidence_count(state, "control"),
            verifies: evidence_count(state, "verify"),
            dispositions: evidence_count(state, "disposition"),
            s4_skips: evidence_count(state, "s4_skip"),
        }
    }
}

fn evidence_count(state: &RunbookState, kind: &str) -> usize {
    state
        .evidence
        .iter()
        .filter(|evidence| evidence.kind == kind)
        .count()
}

fn phase_satisfied(
    phase: &WorkflowPhase,
    baseline: WorkflowCounters,
    state: &RunbookState,
) -> bool {
    match phase.gate {
        PhaseGate::S0Admission => {
            has_runbook_marker(state, "S0")
                && has_service_status_marker(state)
        }
        PhaseGate::S1Surface => {
            state.surfaces.len() > baseline.surfaces
                || state.stats.coverage_mapped > baseline.coverage_mapped
        }
        PhaseGate::S2Lane => {
            state.s2_required_lanes_complete()
        }
        PhaseGate::S3Merge => has_runbook_marker(state, "S3"),
        PhaseGate::S4Probe => {
            if state.claims.is_empty() && state.findings.is_empty() {
                return has_runbook_marker(state, "S4");
            }
            state.evidence.iter().any(|evidence| {
                evidence.stage == "stage4"
                    && matches!(
                        evidence.kind.as_str(),
                        "probe" | "control" | "verify" | "s4_skip" | "disposition"
                    )
            }) || evidence_count(state, "probe") > baseline.probes
                || evidence_count(state, "control") > baseline.controls
                || evidence_count(state, "verify") > baseline.verifies
                || evidence_count(state, "s4_skip") > baseline.s4_skips
        }
        PhaseGate::S5Adjudicate => {
            has_runbook_marker(state, "S5")
                && (state.findings.len() > baseline.findings
                    || state.stats.publishable_claims > 0
                    || state.claims.is_empty())
        }
        PhaseGate::S5Review => state.lanes.iter().any(|lane| {
            lane.stage == "stage5" && lane.lane_id == "final_report_review" && lane.status == "done"
        }),
        PhaseGate::S5FinalRevision => has_s5_final_revision_marker(state),
    }
}

fn max_progress_repairs_for_phase(_phase: &WorkflowPhase, _state: &RunbookState) -> usize {
    MAX_PROGRESS_REPAIRS_PER_PHASE
}

fn max_repairs_for_phase(_phase: &WorkflowPhase, _state: &RunbookState) -> usize {
    MAX_REPAIRS_PER_PHASE
}

fn phase_repair_instruction(_phase: &WorkflowPhase, _state: &RunbookState) -> String {
    "\nWORKFLOW_REPAIR% The previous turn did not satisfy this phase contract. Do not apologize. Emit the missing machine-readable ledger lines now, then continue only within this same phase.\n".to_string()
}

fn phase_progressed(phase: &WorkflowPhase, baseline: WorkflowCounters, state: &RunbookState) -> bool {
    match phase.gate {
        PhaseGate::S0Admission => {
            has_service_status_marker(state)
                || evidence_count(state, "command") > baseline.commands
        }
        PhaseGate::S1Surface => {
            state.surfaces.len() > baseline.surfaces
                || state.stats.coverage_mapped > baseline.coverage_mapped
                || state.candidates.len() > baseline.candidates
                || state.claims.len() > baseline.claims
                || evidence_count(state, "command") > baseline.commands
        }
        PhaseGate::S2Lane => {
            state.candidates.len() > baseline.candidates
                || state.claims.len() > baseline.claims
                || state.stats.coverage_mapped > baseline.coverage_mapped
                || evidence_count(state, "subagent") > baseline.subagents
                || evidence_count(state, "command") > baseline.commands
        }
        PhaseGate::S3Merge => {
            state.claims.len() > baseline.claims
                || state.findings.len() > baseline.findings
                || evidence_count(state, "disposition") > baseline.dispositions
                || evidence_count(state, "command") > baseline.commands
        }
        PhaseGate::S4Probe => {
            state.claims.len() > baseline.claims
                || state.findings.len() > baseline.findings
                || evidence_count(state, "probe") > baseline.probes
                || evidence_count(state, "control") > baseline.controls
                || evidence_count(state, "verify") > baseline.verifies
                || evidence_count(state, "disposition") > baseline.dispositions
                || evidence_count(state, "s4_skip") > baseline.s4_skips
                || evidence_count(state, "command") > baseline.commands
        }
        PhaseGate::S5Adjudicate => {
            state.findings.len() > baseline.findings
                || state.claims.len() > baseline.claims
                || evidence_count(state, "verify") > baseline.verifies
                || evidence_count(state, "disposition") > baseline.dispositions
                || evidence_count(state, "command") > baseline.commands
        }
        PhaseGate::S5Review => evidence_count(state, "subagent") > baseline.subagents,
        PhaseGate::S5FinalRevision => {
            has_s5_final_revision_marker(state)
                || state.findings.len() > baseline.findings
                || evidence_count(state, "command") > baseline.commands
        }
    }
}

fn has_runbook_marker(state: &RunbookState, stage_code: &str) -> bool {
    let needle = format!("runbook% {}", stage_code.to_ascii_lowercase());
    has_marker_text(state, &needle)
}

fn has_service_status_marker(state: &RunbookState) -> bool {
    has_marker_text(state, "service_status% reachable")
        || has_marker_text(state, "service_status% started")
        || has_marker_text(state, "service_status% blocked")
}

fn evidence_text(evidence: &crate::runbook::RunbookEvidence) -> String {
    format!(
        "{}\n{}",
        evidence.title.to_ascii_lowercase(),
        evidence.detail.to_ascii_lowercase()
    )
}

fn has_marker_text(state: &RunbookState, needle: &str) -> bool {
    state.evidence.iter().any(|evidence| {
        evidence_text(evidence).contains(needle)
    })
}

fn phase_prompt(
    phase: &WorkflowPhase,
    index: usize,
    total: usize,
    objective: &str,
    state: &RunbookState,
    is_repair: bool,
) -> String {
    let repair = if is_repair {
        phase_repair_instruction(phase, state)
    } else {
        String::new()
    };
    let context = phase_context(phase, state);
    format!(
        "AUDIT_MODE% TRILANE\n\
         WORKFLOW% id=trilane-workflow step={index}/{total} phase={} stage={} repair={}\n\
         PHASE_TITLE% {}\n\
         USER_OBJECTIVE%\n{}\n\
         {repair}\n\
         GLOBAL_CONTRACT%\n\
         - This is a backend-controlled workflow. Stay inside this phase; do not jump ahead.\n\
         - Do not emit a final report before S5.\n\
         - Use concrete source paths, routes, commands, payloads, and controls. No vibes.\n\
         - Emit compact machine-readable ledger markers. FEATURE%/OBLIGATION%/SURFACE%/CLAIM% lines count; prose without markers does not count.\n\
         - Use these categories when applicable: auth, authz, session, injection, xss, cors_headers_tls, ssrf_redirect, file_upload_xxe, traversal_lfi, state_invariant_abuse, anti_automation_bypass, rate_limit, secrets_config, observability_leak, crypto.\n\
         - Recover broad web application coverage: auth bypass, object ownership, mass assignment, SQL/NoSQL/template/command injection, unsafe eval/sandbox, parser abuse, XXE/YAML/zip, traversal/LFI, SSRF/open redirect, stored/reflected/DOM/header XSS, CORS/header trust flaws, JWT/key/algorithm flaws, weak crypto, exposed APIs/config/metrics/logs/files, state invariant abuse, recovery/anti-automation/rate-limit gaps.\n\n\
         PHASE_CONTRACT%\n{}\n\n\
         PHASE_TASK%\n{}\n{}",
        phase.id, phase.stage_code, is_repair, phase.title, objective.trim(), phase.contract, phase.body
        , context
    )
}
