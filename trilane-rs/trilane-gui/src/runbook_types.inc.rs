use std::collections::BTreeSet;

use serde::Deserialize;
use serde::Serialize;

use crate::runbook_claims::canonical_claim_fingerprint;
use crate::runbook_claims::infer_evidence_level;
use crate::runbook_claims::status_from_evidence;
use crate::runbook_claims::ClaimSeed;
use crate::runbook_claims::ClaimStatus;
use crate::runbook_claims::EvidenceLevel;
use crate::runbook_claims::RunbookClaim;
use crate::runbook_claims::RunbookClaimSummary;
use crate::runbook_claims::RunbookSurface;

const MAX_EVIDENCE: usize = 80;
const MAX_CANDIDATES: usize = 120;
const MAX_FINDINGS: usize = 80;
const MAX_SURFACES: usize = 160;
const MAX_CLAIMS: usize = 180;
const MAX_ATTACK_ATOMS: usize = 180;
const MAX_CHAIN_CANDIDATES: usize = 48;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RunbookStatus {
    Idle,
    Running,
    Completed,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum StageStatus {
    Pending,
    Active,
    Done,
    Blocked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuditMode {
    Safe,
    Lab,
}

impl AuditMode {
    pub fn from_wire(value: Option<&str>) -> Self {
        match value.map(str::to_ascii_lowercase).as_deref() {
            Some("lab") | Some("trilane_audit") => Self::Lab,
            Some("safe") | None => Self::Safe,
            Some(_) => Self::Safe,
        }
    }

    pub fn as_marker(&self) -> &'static str {
        match self {
            Self::Safe => "SAFE",
            Self::Lab => "LAB",
        }
    }

    pub fn grants_full_access(&self) -> bool {
        matches!(self, Self::Lab)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunbookStage {
    pub id: String,
    pub code: String,
    pub name: String,
    pub label: String,
    pub status: StageStatus,
    pub summary: String,
    pub evidence_count: usize,
    pub candidate_count: usize,
    pub findings_count: usize,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CoverageStatus {
    Pending,
    Mapped,
    Partial,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunbookCoverage {
    pub id: String,
    pub category: String,
    pub label: String,
    pub mapped_count: usize,
    pub total_hint: Option<usize>,
    pub status: CoverageStatus,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CandidateStatus {
    Candidate,
    Probed,
    NeedsVerify,
    Rejected,
    Duplicate,
    OutOfScope,
    Confirmed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunbookCandidate {
    pub id: String,
    pub stage: String,
    pub category: String,
    pub title: String,
    pub target: String,
    pub status: CandidateStatus,
    pub severity: Option<String>,
    pub evidence_count: usize,
    pub verification_count: usize,
    pub source_confirmed: bool,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunbookEvidence {
    pub id: String,
    pub stage: String,
    pub kind: String,
    pub title: String,
    pub detail: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunbookLane {
    pub lane_id: String,
    pub stage: String,
    pub status: String,
    #[serde(default)]
    pub report_seen: bool,
    pub claim_count: usize,
    pub candidate_count: usize,
    pub thread_id: String,
    pub summary: String,
    pub updated_at: String,
}

pub struct RunbookLaneUpdate<'a> {
    pub stage: &'a str,
    pub lane_id: &'a str,
    pub status: &'a str,
    pub report_seen: bool,
    pub claim_count: Option<usize>,
    pub candidate_count: Option<usize>,
    pub thread_id: Option<&'a str>,
    pub summary: &'a str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunbookAttackAtom {
    pub id: String,
    pub stage: String,
    pub lane_id: String,
    pub kind: String,
    pub category: String,
    pub target: String,
    pub label: String,
    pub claim_id: Option<String>,
    pub bridge_keys: Vec<String>,
    pub evidence: String,
    pub confidence: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunbookChainCandidate {
    pub id: String,
    pub stage: String,
    pub title: String,
    pub status: String,
    pub impact: String,
    pub atom_ids: Vec<String>,
    pub bridge_keys: Vec<String>,
    pub verify_plan: String,
    pub score: u16,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunbookFinding {
    pub id: String,
    pub stage: String,
    pub candidate_id: Option<String>,
    pub severity: String,
    pub title: String,
    pub code_path: String,
    pub confidence: String,
    pub evidence_state: String,
    pub detail: String,
    pub payload: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunbookFinalFinding {
    pub id: String,
    pub original_id: String,
    pub candidate_id: Option<String>,
    pub severity: String,
    pub title: String,
    pub code_path: String,
    pub location: String,
    pub confidence: String,
    pub evidence_state: String,
    pub verification_status: String,
    pub detail: String,
    pub payload: String,
    pub duplicates: Vec<String>,
    pub canonical_key: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RunbookDedupeSummary {
    pub raw_findings: usize,
    pub final_findings: usize,
    pub duplicates: usize,
    pub verified: usize,
    pub source_backed: usize,
    pub needs_poc: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RunbookStats {
    pub coverage_mapped: usize,
    pub coverage_total: usize,
    pub coverage_debt: usize,
    pub surfaces: usize,
    pub surface_covered: usize,
    pub domain_queues: usize,
    pub domain_queues_closed: usize,
    pub hypothesis_count: usize,
    pub hypothesis_floor: usize,
    pub hypothesis_debt: usize,
    pub candidates: usize,
    pub root_claims: usize,
    pub probed: usize,
    pub rejected: usize,
    pub merged_claims: usize,
    pub blocked_claims: usize,
    pub discarded_claims: usize,
    pub needs_verify: usize,
    pub confirmed: usize,
    pub publishable_claims: usize,
    pub source_confirmed: usize,
    pub evidence_signals: usize,
}

struct RunbookFindingInput<'a> {
    stage: &'a str,
    candidate_id: Option<String>,
    severity: &'a str,
    title: &'a str,
    code_path: &'a str,
    confidence: &'a str,
    evidence_state: &'a str,
    detail: String,
    payload: String,
}

#[derive(Debug, Clone, Default)]
struct SurfaceGateMetrics {
    coverage_mapped: usize,
    surfaces: usize,
    surface_covered: usize,
    domain_queues: usize,
    domain_queues_closed: usize,
    hypothesis_count: usize,
    hypothesis_floor: usize,
    hypothesis_debt: usize,
    open_candidates: usize,
    open_claims: usize,
    debt: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunbookState {
    pub status: RunbookStatus,
    #[serde(default)]
    pub revision: u64,
    pub audit_mode: AuditMode,
    pub objective: String,
    pub current_stage: String,
    pub turn_id: Option<String>,
    pub stages: Vec<RunbookStage>,
    pub coverage: Vec<RunbookCoverage>,
    pub surfaces: Vec<RunbookSurface>,
    pub candidates: Vec<RunbookCandidate>,
    pub claims: Vec<RunbookClaim>,
    pub lanes: Vec<RunbookLane>,
    #[serde(default)]
    pub attack_atoms: Vec<RunbookAttackAtom>,
    #[serde(default)]
    pub chain_candidates: Vec<RunbookChainCandidate>,
    pub evidence: Vec<RunbookEvidence>,
    #[serde(default)]
    pub evidence_total: usize,
    pub findings: Vec<RunbookFinding>,
    pub final_findings: Vec<RunbookFinalFinding>,
    pub dedupe_summary: RunbookDedupeSummary,
    pub claim_summary: RunbookClaimSummary,
    pub stats: RunbookStats,
    pub last_updated: String,
}

impl Default for RunbookState {
    fn default() -> Self {
        Self {
            status: RunbookStatus::Idle,
            revision: 0,
            audit_mode: AuditMode::Safe,
            objective: String::new(),
            current_stage: "stage0".to_string(),
            turn_id: None,
            stages: default_stages(),
            coverage: default_coverage(&AuditMode::Safe),
            surfaces: Vec::new(),
            candidates: Vec::new(),
            claims: Vec::new(),
            lanes: Vec::new(),
            attack_atoms: Vec::new(),
            chain_candidates: Vec::new(),
            evidence: Vec::new(),
            evidence_total: 0,
            findings: Vec::new(),
            final_findings: Vec::new(),
            dedupe_summary: RunbookDedupeSummary::default(),
            claim_summary: RunbookClaimSummary::default(),
            stats: RunbookStats::default(),
            last_updated: now(),
        }
    }
}
