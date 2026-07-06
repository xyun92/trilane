use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use chrono::Local;
use dirs::home_dir;
use serde_json::json;
use tracing::warn;

use crate::runbook::AuditMode;
use crate::runbook::RunbookState;

const STAGES: [&str; 6] = ["stage0", "stage1", "stage2", "stage3", "stage4", "stage5"];
const STAGE_TITLES: [(&str, &str); 6] = [
    ("stage0", "S0 Gate"),
    ("stage1", "S1 Recon"),
    ("stage2", "S2 Audit"),
    ("stage3", "S3 FoA"),
    ("stage4", "S4 Fuzz"),
    ("stage5", "S5 Verify"),
];

pub struct TranscriptArchive {
    root: PathBuf,
    active: Option<ActiveTranscript>,
}

struct ActiveTranscript {
    run_id: String,
    dir: PathBuf,
    started_at: String,
    objective: String,
    audit_mode: AuditMode,
    turn_id: Option<String>,
    final_status: Option<String>,
}

#[derive(Clone, Copy)]
enum TranscriptRole {
    User,
    System,
    Assistant,
}

impl TranscriptArchive {
    pub fn new() -> Self {
        Self::with_root(default_root())
    }

    pub fn with_root(root: PathBuf) -> Self {
        Self { root, active: None }
    }

    pub fn start_turn(&mut self, objective: &str, audit_mode: AuditMode) {
        let started_at = Local::now();
        let run_id = new_run_id(objective, &started_at);
        let dir = self.root.join(&run_id);
        if let Err(error) =
            initialize_run_dir(&self.root, &run_id, started_at.to_rfc3339().as_str())
        {
            warn!("Failed to create run dir {}: {error}", dir.display());
            self.active = None;
            return;
        }

        self.active = Some(ActiveTranscript {
            run_id,
            dir,
            started_at: started_at.to_rfc3339(),
            objective: objective.trim().to_string(),
            audit_mode,
            turn_id: None,
            final_status: None,
        });
        self.write_metadata();
    }

    pub fn start_resume_turn(
        &mut self,
        run_id: &str,
        objective: &str,
        audit_mode: AuditMode,
    ) -> Result<(), String> {
        let run_id = safe_run_id(run_id)?;
        let dir = self.root.join(&run_id);
        if !dir.is_dir() {
            return Err(format!("run not found: {run_id}"));
        }
        fs::write(self.root.join("current_run.txt"), &run_id)
            .map_err(|error| format!("write current_run.txt: {error}"))?;
        self.active = Some(ActiveTranscript {
            run_id,
            dir,
            started_at: Local::now().to_rfc3339(),
            objective: objective.trim().to_string(),
            audit_mode,
            turn_id: None,
            final_status: None,
        });
        self.write_metadata();
        Ok(())
    }

    pub fn load_resume_state(&self, run_id: &str, stage_id: &str) -> Result<RunbookState, String> {
        load_resume_state_from_root(&self.root, run_id, stage_id)
    }

    pub fn list_runs(&self) -> Vec<String> {
        let Ok(entries) = fs::read_dir(&self.root) else {
            return Vec::new();
        };
        let mut runs = entries
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let path = entry.path();
                let run_id = entry.file_name().to_string_lossy().to_string();
                (path.is_dir() && path.join("stage0").is_dir() && safe_run_id(&run_id).is_ok())
                    .then_some(run_id)
            })
            .collect::<Vec<_>>();
        runs.sort_by(|a, b| b.cmp(a));
        runs
    }

    pub fn resume_file_context(&self, run_id: &str, stage_id: &str) -> Result<String, String> {
        resume_file_context_from_root(&self.root, run_id, stage_id)
    }

    pub fn set_turn_id(&mut self, turn_id: &str) {
        if let Some(active) = self.active.as_mut() {
            active.turn_id = Some(turn_id.to_string());
            self.write_metadata();
        }
    }

    pub fn record_stage_start(&mut self, stage_id: &str, prompt: &str) {
        let Some(active) = self.active.as_ref() else {
            return;
        };
        let stage_id = normalize_stage_id(stage_id);
        if let Err(error) = write_stage_prompt(active, stage_id, prompt) {
            warn!("Failed to write stage prompt for {stage_id}: {error}");
        }
    }

    pub fn record_stage_snapshot(&mut self, stage_id: &str, status: &str, runbook: &RunbookState) {
        let Some(active) = self.active.as_ref() else {
            return;
        };
        let stage_id = normalize_stage_id(stage_id);
        if let Err(error) = write_stage_snapshot(active, stage_id, status, runbook) {
            warn!("Failed to write stage snapshot for {stage_id}: {error}");
        }
    }

    pub fn finish_turn(&mut self, status: &str, runbook: &RunbookState) {
        if let Some(active) = self.active.as_mut() {
            active.final_status = Some(status.to_string());
            if let Err(error) =
                write_stage_snapshot(active, &runbook.current_stage, status, runbook)
            {
                warn!("Failed to write final stage snapshot: {error}");
            }
            self.write_metadata_with_summary(runbook);
        }
        self.active = None;
    }

    pub fn record_message(&mut self, timestamp: &str, role: &str, stage_hint: &str, content: &str) {
        let Some(active) = self.active.as_ref() else {
            return;
        };
        let Some(role) = TranscriptRole::from_role(role) else {
            return;
        };
        let stage_id = infer_stage_id(content).unwrap_or_else(|| normalize_stage_id(stage_hint));
        let path = stage_dir(active, stage_id).join("transcript.md");
        let entry = format!(
            "\n## {timestamp}\n### {}%\n\n```text\n{}\n```\n",
            role.label(),
            content.trim()
        );
        if let Err(error) = append_file(&path, &entry) {
            warn!(
                "Failed to append transcript entry to {}: {error}",
                path.display()
            );
        }
    }
}

impl TranscriptRole {
    fn from_role(role: &str) -> Option<Self> {
        match role {
            "user" => Some(Self::User),
            "system" => Some(Self::System),
            "assistant" => Some(Self::Assistant),
            _ => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::User => "YOU",
            Self::System => "SYS",
            Self::Assistant => "TRI",
        }
    }
}

fn default_root() -> PathBuf {
    home_dir()
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
        .join(".trilane")
        .join("runs")
}

fn new_run_id(objective: &str, started_at: &chrono::DateTime<Local>) -> String {
    let lower = objective.to_ascii_lowercase();
    let prefix = if lower.contains("juice-shop") || lower.contains("juiceshop") {
        "juiceshop"
    } else {
        "trilane"
    };
    format!("{prefix}-{}", started_at.format("%Y%m%d-%H%M%S"))
}

fn initialize_run_dir(root: &Path, run_id: &str, started_at: &str) -> std::io::Result<()> {
    let dir = root.join(run_id);
    fs::create_dir_all(&dir)?;
    fs::write(root.join("current_run.txt"), run_id)?;
    for stage_id in STAGES {
        let stage = dir.join(stage_id);
        fs::create_dir_all(&stage)?;
        write_stage_header(&stage, stage_id, started_at)?;
    }
    Ok(())
}

fn write_stage_header(stage_dir: &Path, stage_id: &str, started_at: &str) -> std::io::Result<()> {
    let title = stage_title(stage_id);
    fs::write(stage_dir.join("prompt.md"), "")?;
    fs::write(
        stage_dir.join("transcript.md"),
        format!(
            "# {title}\n\n- Stage: {stage_id}\n- Started at: {started_at}\n- Entries: chronological transcript for this stage.\n"
        ),
    )?;
    fs::write(stage_dir.join("runbook.json"), "{}\n")?;
    fs::write(
        stage_dir.join("status.json"),
        json!({
            "stage": stage_id,
            "status": "pending",
            "updated_at": started_at
        })
        .to_string(),
    )?;
    Ok(())
}

fn append_file(path: &Path, content: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(content.as_bytes())
}

fn stage_title(stage_id: &str) -> &'static str {
    STAGE_TITLES
        .iter()
        .find_map(|(id, title)| (*id == stage_id).then_some(*title))
        .unwrap_or("S0 Gate")
}

fn normalize_stage_id(stage_id: &str) -> &'static str {
    match stage_id {
        "stage0" => "stage0",
        "stage1" => "stage1",
        "stage2" => "stage2",
        "stage3" => "stage3",
        "stage4" => "stage4",
        "stage5" => "stage5",
        _ => "stage0",
    }
}

fn infer_stage_id(content: &str) -> Option<&'static str> {
    let normalized = content.to_ascii_lowercase();
    if normalized.contains("runbook% s0") || normalized.contains("stage=stage0") {
        return Some("stage0");
    }
    if normalized.contains("runbook% s1") || normalized.contains("stage=stage1") {
        return Some("stage1");
    }
    if normalized.contains("runbook% s2") || normalized.contains("stage=stage2") {
        return Some("stage2");
    }
    if normalized.contains("runbook% s3") || normalized.contains("stage=stage3") {
        return Some("stage3");
    }
    if normalized.contains("runbook% s4") || normalized.contains("stage=stage4") {
        return Some("stage4");
    }
    if normalized.contains("runbook% s5") || normalized.contains("stage=stage5") {
        return Some("stage5");
    }
    None
}

fn stage_dir(active: &ActiveTranscript, stage_id: &str) -> PathBuf {
    active.dir.join(normalize_stage_id(stage_id))
}

fn write_stage_prompt(
    active: &ActiveTranscript,
    stage_id: &str,
    prompt: &str,
) -> std::io::Result<()> {
    let dir = stage_dir(active, stage_id);
    fs::create_dir_all(&dir)?;
    fs::write(dir.join("prompt.md"), prompt)?;
    fs::write(
        dir.join("status.json"),
        json!({
            "stage": stage_id,
            "status": "running",
            "updated_at": Local::now().to_rfc3339()
        })
        .to_string(),
    )
}

fn write_stage_snapshot(
    active: &ActiveTranscript,
    stage_id: &str,
    status: &str,
    runbook: &RunbookState,
) -> std::io::Result<()> {
    let dir = stage_dir(active, stage_id);
    fs::create_dir_all(&dir)?;
    let runbook_json = serde_json::to_string_pretty(runbook).map_err(std::io::Error::other)?;
    fs::write(dir.join("runbook.json"), runbook_json)?;
    fs::write(
        dir.join("status.json"),
        json!({
            "stage": normalize_stage_id(stage_id),
            "status": status,
            "updated_at": Local::now().to_rfc3339(),
            "revision": runbook.revision,
            "current_stage": runbook.current_stage,
            "root_claims": runbook.stats.root_claims,
            "final_findings": runbook.final_findings.len()
        })
        .to_string(),
    )
}

fn load_resume_state_from_root(
    root: &Path,
    run_id: &str,
    stage_id: &str,
) -> Result<RunbookState, String> {
    let run_id = safe_run_id(run_id)?;
    let stage_idx = stage_index(stage_id).ok_or_else(|| format!("unknown stage: {stage_id}"))?;
    let source_stage = if stage_idx == 0 {
        "stage0"
    } else {
        STAGES[stage_idx - 1]
    };
    let run_dir = root.join(&run_id);
    let runbook_path = run_dir.join(source_stage).join("runbook.json");
    let json = fs::read_to_string(&runbook_path)
        .map_err(|error| format!("read {}: {error}", runbook_path.display()))?;
    let mut runbook: RunbookState =
        serde_json::from_str(&json).map_err(|error| format!("parse runbook.json: {error}"))?;
    for stage in &STAGES[stage_idx..] {
        let dir = run_dir.join(stage);
        if dir.exists() {
            fs::remove_dir_all(&dir)
                .map_err(|error| format!("remove {}: {error}", dir.display()))?;
        }
    }
    runbook.status = crate::runbook::RunbookStatus::Running;
    runbook.current_stage = normalize_stage_id(stage_id).to_string();
    runbook.turn_id = None;
    Ok(runbook)
}

fn resume_file_context_from_root(
    root: &Path,
    run_id: &str,
    stage_id: &str,
) -> Result<String, String> {
    let run_id = safe_run_id(run_id)?;
    let stage_idx = stage_index(stage_id).ok_or_else(|| format!("unknown stage: {stage_id}"))?;
    let run_dir = root.join(&run_id);
    if !run_dir.is_dir() {
        return Err(format!("run not found: {run_id}"));
    }
    let source_stage = if stage_idx == 0 {
        "stage0"
    } else {
        STAGES[stage_idx - 1]
    };
    let mut lines = vec![
        "RESUME_RUN_CONTEXT%".to_string(),
        format!(
            "run_id={run_id} restart_stage={}",
            normalize_stage_id(stage_id)
        ),
        format!(
            "source_state={}",
            run_dir.join(source_stage).join("runbook.json").display()
        ),
        "previous_stage_files=".to_string(),
    ];
    if stage_idx == 0 {
        lines.push("- none".to_string());
    } else {
        for stage in &STAGES[..stage_idx] {
            let dir = run_dir.join(stage);
            lines.push(format!(
                "- {stage}: prompt={} transcript={} runbook={} status={}",
                dir.join("prompt.md").display(),
                dir.join("transcript.md").display(),
                dir.join("runbook.json").display(),
                dir.join("status.json").display(),
            ));
        }
    }
    lines.push("Use these files as fixed prior-stage context; do not rerun earlier stages unless the user explicitly asks.".to_string());
    Ok(lines.join("\n"))
}

fn safe_run_id(run_id: &str) -> Result<String, String> {
    let trimmed = run_id.trim();
    if trimmed.is_empty() {
        return Err("run id is empty".to_string());
    }
    if trimmed
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        Ok(trimmed.to_string())
    } else {
        Err(format!("invalid run id: {trimmed}"))
    }
}

fn stage_index(stage_id: &str) -> Option<usize> {
    match stage_id.trim() {
        "stage0" => Some(0),
        "stage1" => Some(1),
        "stage2" => Some(2),
        "stage3" => Some(3),
        "stage4" => Some(4),
        "stage5" => Some(5),
        _ => None,
    }
}

impl TranscriptArchive {
    fn write_metadata(&self) {
        let Some(active) = self.active.as_ref() else {
            return;
        };
        let status = active.final_status.as_deref().unwrap_or("running");
        let turn_id = active.turn_id.as_deref().unwrap_or("pending");
        let metadata = format!(
            "# TriLane Run\n\n- Run ID: {}\n- Started at: {}\n- Objective: {}\n- Audit mode: {}\n- Turn ID: {}\n- Status: {}\n- Root: {}\n\n## Stage Dirs\n- stage0\n- stage1\n- stage2\n- stage3\n- stage4\n- stage5\n",
            active.run_id,
            active.started_at,
            active.objective,
            active.audit_mode.as_marker(),
            turn_id,
            status,
            active.dir.display()
        );
        if let Err(error) = fs::write(active.dir.join("README.md"), metadata) {
            warn!("Failed to write transcript metadata: {error}");
        }
    }

    fn write_metadata_with_summary(&self, runbook: &RunbookState) {
        let Some(active) = self.active.as_ref() else {
            return;
        };
        let status = active.final_status.as_deref().unwrap_or("completed");
        let turn_id = active.turn_id.as_deref().unwrap_or("pending");
        let metadata = format!(
            "# TriLane Run\n\n- Run ID: {}\n- Started at: {}\n- Objective: {}\n- Audit mode: {}\n- Turn ID: {}\n- Status: {}\n- Root claims: {}\n- Final findings: {}\n- Publishable claims: {}\n- Current stage at finish: {}\n- Root: {}\n\n## Stage Dirs\n- stage0\n- stage1\n- stage2\n- stage3\n- stage4\n- stage5\n",
            active.run_id,
            active.started_at,
            active.objective,
            active.audit_mode.as_marker(),
            turn_id,
            status,
            runbook.stats.root_claims,
            runbook.final_findings.len(),
            runbook.stats.publishable_claims,
            runbook.current_stage,
            active.dir.display()
        );
        if let Err(error) = fs::write(active.dir.join("README.md"), metadata) {
            warn!("Failed to write transcript summary: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;

    fn temp_root() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!("trilane-transcript-test-{unique}"))
    }

    #[test]
    fn infers_stage_from_runbook_marker_and_workflow_stage() {
        assert_eq!(infer_stage_id("RUNBOOK% S3 Summary: merge"), Some("stage3"));
        assert_eq!(
            infer_stage_id(
                "SYS% workflow phase start\nWORKFLOW% phase=x stage=stage4 repair=false"
            ),
            Some("stage4")
        );
        assert_eq!(infer_stage_id("plain text"), None);
    }

    #[test]
    fn creates_stage_files_and_appends_entries() {
        let root = temp_root();
        let mut archive = TranscriptArchive::with_root(root.clone());
        archive.start_turn("audit demo target", AuditMode::Lab);
        archive.set_turn_id("turn-123");
        archive.record_message(
            "2026-06-03T10:00:00Z",
            "assistant",
            "stage0",
            "RUNBOOK% S1 Recon: building surface ledger",
        );

        let run_id = fs::read_to_string(root.join("current_run.txt")).expect("current run");
        let run_dir = root.join(run_id.trim());
        let stage_file = run_dir.join("stage1").join("transcript.md");
        let readme = run_dir.join("README.md");

        let stage_text = fs::read_to_string(stage_file).expect("stage file");
        let readme_text = fs::read_to_string(readme).expect("readme");

        assert!(stage_text.contains("### TRI%"));
        assert!(stage_text.contains("RUNBOOK% S1 Recon"));
        assert!(readme_text.contains("turn-123"));

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn resume_reads_previous_stage_runbook_and_removes_later_dirs() {
        let root = temp_root();
        let mut archive = TranscriptArchive::with_root(root.clone());
        archive.start_turn("juice-shop audit", AuditMode::Lab);
        let run_id = fs::read_to_string(root.join("current_run.txt")).expect("current run");
        let run_id = run_id.trim().to_string();
        let mut runbook = RunbookState::default();
        runbook.start_turn("juice-shop audit", AuditMode::Lab);
        runbook.record_workflow_phase("stage2", "S2 done");
        archive.record_stage_snapshot("stage2", "completed", &runbook);
        fs::create_dir_all(root.join(&run_id).join("stage3")).expect("stage3");
        fs::write(
            root.join(&run_id).join("stage3").join("runbook.json"),
            "{}\n",
        )
        .expect("stage3 runbook");

        let resumed = archive
            .load_resume_state(&run_id, "stage3")
            .expect("resume state");

        assert_eq!(resumed.objective, "juice-shop audit");
        assert_eq!(resumed.current_stage, "stage3");
        assert!(!root.join(&run_id).join("stage3").exists());

        fs::remove_dir_all(root).expect("cleanup");
    }
}
