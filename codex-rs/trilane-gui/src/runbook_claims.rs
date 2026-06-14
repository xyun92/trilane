use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    Seed,
    Anchored,
    Armed,
    Running,
    Corroborated,
    Verified,
    Weaponized,
    Publishable,
    Blocked,
    Discarded,
    Merged,
}

impl ClaimStatus {
    pub fn from_marker(value: &str) -> Self {
        match normalize_token(value).as_str() {
            "anchored" | "sourceconfirmed" | "sourcebacked" => Self::Anchored,
            "armed" | "ready" | "readyforverification" => Self::Armed,
            "running" | "executing" | "probing" => Self::Running,
            "corroborated" | "oracleconfirmed" => Self::Corroborated,
            "verified" | "strictverified" => Self::Verified,
            "weaponized" | "exploitconfirmed" => Self::Weaponized,
            "publishable" | "reportable" | "confirmed" => Self::Publishable,
            "blocked" | "defenseblocked" => Self::Blocked,
            "discarded" | "rejected" | "falsepositive" => Self::Discarded,
            "merged" | "duplicate" => Self::Merged,
            _ => Self::Seed,
        }
    }

    pub fn as_marker(&self) -> &'static str {
        match self {
            Self::Seed => "seed",
            Self::Anchored => "anchored",
            Self::Armed => "armed",
            Self::Running => "running",
            Self::Corroborated => "corroborated",
            Self::Verified => "verified",
            Self::Weaponized => "weaponized",
            Self::Publishable => "publishable",
            Self::Blocked => "blocked",
            Self::Discarded => "discarded",
            Self::Merged => "merged",
        }
    }

    pub fn rank(&self) -> usize {
        match self {
            Self::Seed => 1,
            Self::Anchored => 2,
            Self::Armed => 3,
            Self::Running => 4,
            Self::Corroborated => 5,
            Self::Verified => 6,
            Self::Weaponized => 7,
            Self::Publishable => 8,
            Self::Blocked => 4,
            Self::Discarded | Self::Merged => 0,
        }
    }

    pub fn merge(self, next: Self) -> Self {
        if matches!(next, Self::Discarded | Self::Merged | Self::Blocked) {
            return next;
        }
        if next.rank() >= self.rank() {
            next
        } else {
            self
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceLevel {
    Signal,
    SourceBacked,
    RuntimeSignal,
    Reproducible,
    ImpactProven,
    ControlPassed,
}

impl EvidenceLevel {
    pub fn from_marker(value: &str) -> Self {
        match normalize_token(value).as_str() {
            "source" | "sourcebacked" | "sourceconfirmed" | "l1" => Self::SourceBacked,
            "runtime" | "runtimesignal" | "oracle" | "l2" => Self::RuntimeSignal,
            "repro" | "reproducible" | "poc" | "l3" => Self::Reproducible,
            "impact" | "impactproven" | "exploit" | "l4" => Self::ImpactProven,
            "control" | "negativecontrol" | "controlpassed" | "triad" | "l5" => Self::ControlPassed,
            _ => Self::Signal,
        }
    }

    pub fn as_marker(&self) -> &'static str {
        match self {
            Self::Signal => "signal",
            Self::SourceBacked => "source-backed",
            Self::RuntimeSignal => "runtime-signal",
            Self::Reproducible => "reproducible",
            Self::ImpactProven => "impact-proven",
            Self::ControlPassed => "control-passed",
        }
    }

    pub fn rank(&self) -> usize {
        match self {
            Self::Signal => 1,
            Self::SourceBacked => 2,
            Self::RuntimeSignal => 3,
            Self::Reproducible => 4,
            Self::ImpactProven => 5,
            Self::ControlPassed => 6,
        }
    }

    pub fn merge(self, next: Self) -> Self {
        if next.rank() >= self.rank() {
            next
        } else {
            self
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunbookSurface {
    pub id: String,
    pub stage: String,
    pub kind: String,
    pub category: String,
    pub label: String,
    pub target: String,
    pub signal_count: usize,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunbookClaim {
    pub id: String,
    pub fingerprint: String,
    pub stage: String,
    pub category: String,
    pub title: String,
    pub target: String,
    pub status: ClaimStatus,
    pub evidence_level: EvidenceLevel,
    pub severity: Option<String>,
    pub code_path: String,
    pub root_cause: String,
    pub precondition: String,
    pub impact: String,
    pub payload: String,
    pub positive_evidence: String,
    pub negative_evidence: String,
    pub merged_into: Option<String>,
    pub signal_count: usize,
    pub probe_count: usize,
    pub verification_count: usize,
    pub updated_at: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RunbookClaimSummary {
    pub surfaces: usize,
    pub raw_signals: usize,
    pub root_claims: usize,
    pub publishable: usize,
    pub verified: usize,
    pub blocked: usize,
    pub discarded: usize,
    pub merged: usize,
    pub coverage_debt: usize,
    pub evidence_ladder_complete: usize,
}

pub struct ClaimSeed<'a> {
    pub id: Option<String>,
    pub stage: &'a str,
    pub category: &'a str,
    pub title: &'a str,
    pub target: &'a str,
    pub code_path: &'a str,
    pub root_cause: &'a str,
    pub precondition: &'a str,
    pub impact: &'a str,
    pub payload: &'a str,
    pub positive_evidence: &'a str,
    pub negative_evidence: &'a str,
    pub severity: Option<String>,
    pub status: ClaimStatus,
    pub evidence_level: EvidenceLevel,
    pub timestamp: String,
}

pub fn canonical_claim_fingerprint(seed: &ClaimSeed<'_>) -> String {
    let location_values = [seed.code_path, seed.target, seed.root_cause];
    let location = first_non_empty(&location_values);
    let cause_values = [seed.root_cause, seed.title];
    let cause = first_non_empty(&cause_values);
    format!(
        "{}:{}:{}",
        normalize_token(seed.category),
        normalize_location(location),
        normalize_token(cause)
    )
}

pub fn infer_evidence_level(
    code_path: &str,
    positive_evidence: &str,
    negative_evidence: &str,
    payload: &str,
    confidence: &str,
) -> EvidenceLevel {
    let haystack =
        format!("{positive_evidence}\n{negative_evidence}\n{payload}").to_ascii_lowercase();
    let has_source = !code_path.trim().is_empty()
        || haystack.contains("root_cause")
        || haystack.contains("source");
    let has_runtime = contains_any(
        &haystack,
        &[
            "status 200",
            "http ",
            "curl ",
            "returned",
            "response",
            "challenge",
        ],
    );
    let has_repro = !payload.trim().is_empty() || contains_any(&haystack, &["poc", "repro"]);
    let has_impact = contains_any(
        &haystack,
        &[
            "admin",
            "exfil",
            "takeover",
            "data extracted",
            "unauthorized",
            "bypass",
        ],
    );
    let has_control = contains_any(
        &haystack,
        &["negative", "control", "isolation", "clean", "baseline"],
    );
    if has_control && has_source && has_repro {
        EvidenceLevel::ControlPassed
    } else if has_impact && has_repro {
        EvidenceLevel::ImpactProven
    } else if has_repro {
        EvidenceLevel::Reproducible
    } else if has_runtime {
        EvidenceLevel::RuntimeSignal
    } else if has_source || confidence.eq_ignore_ascii_case("high") {
        EvidenceLevel::SourceBacked
    } else {
        EvidenceLevel::Signal
    }
}

pub fn status_from_evidence(level: &EvidenceLevel, has_negative_control: bool) -> ClaimStatus {
    match level {
        EvidenceLevel::Signal => ClaimStatus::Seed,
        EvidenceLevel::SourceBacked => ClaimStatus::Anchored,
        EvidenceLevel::RuntimeSignal => ClaimStatus::Corroborated,
        EvidenceLevel::Reproducible => ClaimStatus::Verified,
        EvidenceLevel::ImpactProven => ClaimStatus::Weaponized,
        EvidenceLevel::ControlPassed if has_negative_control => ClaimStatus::Publishable,
        EvidenceLevel::ControlPassed => ClaimStatus::Weaponized,
    }
}

fn first_non_empty<'a>(values: &'a [&'a str]) -> &'a str {
    values
        .iter()
        .copied()
        .find(|value| !value.trim().is_empty())
        .unwrap_or("unknown")
}

fn normalize_location(value: &str) -> String {
    value
        .to_ascii_lowercase()
        .replace("http://localhost:3000", "")
        .replace("https://localhost:3000", "")
        .split_whitespace()
        .next()
        .unwrap_or("unknown")
        .trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '/' && ch != ':' && ch != '_')
        .replace(['/', ':'], "_")
}

fn normalize_token(value: &str) -> String {
    let normalized: String = value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    if normalized.is_empty() {
        "unknown".to_string()
    } else {
        normalized
    }
}

fn contains_any(text: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| text.contains(needle))
}
