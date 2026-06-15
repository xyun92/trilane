use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use chrono::Local;
use dirs::home_dir;
use tracing::warn;

use crate::runbook::AuditMode;
use crate::runbook::RunbookState;

const STAGE_FILES: [(&str, &str, &str); 6] = [
    ("stage0", "s0_gate.md", "S0 Gate"),
    ("stage1", "s1_recon.md", "S1 Recon"),
    ("stage2", "s2_audit.md", "S2 Audit"),
    ("stage3", "s3_foa.md", "S3 FoA"),
    ("stage4", "s4_fuzz.md", "S4 Fuzz"),
    ("stage5", "s5_verify.md", "S5 Verify"),
];

pub struct TranscriptArchive {
    root: PathBuf,
    active: Option<ActiveTranscript>,
}

struct ActiveTranscript {
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
        let folder = format!("turn-{}", started_at.format("%Y%m%d-%H%M%S-%3f"));
        let dir = self.root.join(folder);
        if let Err(error) = fs::create_dir_all(&dir) {
            warn!("Failed to create transcript dir {}: {error}", dir.display());
            self.active = None;
            return;
        }

        for (stage_id, file_name, title) in STAGE_FILES {
            if let Err(error) = write_stage_header(
                &dir.join(file_name),
                title,
                stage_id,
                started_at.to_rfc3339().as_str(),
            ) {
                warn!(
                    "Failed to initialize transcript file {}: {error}",
                    dir.join(file_name).display()
                );
            }
        }

        self.active = Some(ActiveTranscript {
            dir,
            started_at: started_at.to_rfc3339(),
            objective: objective.trim().to_string(),
            audit_mode,
            turn_id: None,
            final_status: None,
        });
        self.write_metadata();
    }

    pub fn set_turn_id(&mut self, turn_id: &str) {
        if let Some(active) = self.active.as_mut() {
            active.turn_id = Some(turn_id.to_string());
            self.write_metadata();
        }
    }

    pub fn finish_turn(&mut self, status: &str, runbook: &RunbookState) {
        if let Some(active) = self.active.as_mut() {
            active.final_status = Some(status.to_string());
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
        let path = active.dir.join(stage_file_name(stage_id));
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
        .join("transcripts")
}

fn write_stage_header(
    path: &Path,
    title: &str,
    stage_id: &str,
    started_at: &str,
) -> std::io::Result<()> {
    fs::write(
        path,
        format!(
            "# {title}\n\n- Stage: {stage_id}\n- Started at: {started_at}\n- Entries: chronological transcript for this stage.\n"
        ),
    )
}

fn append_file(path: &Path, content: &str) -> std::io::Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(content.as_bytes())
}

fn stage_file_name(stage_id: &str) -> &'static str {
    STAGE_FILES
        .iter()
        .find_map(|(id, file_name, _)| (*id == stage_id).then_some(*file_name))
        .unwrap_or("s0_gate.md")
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

impl TranscriptArchive {
    fn write_metadata(&self) {
        let Some(active) = self.active.as_ref() else {
            return;
        };
        let status = active.final_status.as_deref().unwrap_or("running");
        let turn_id = active.turn_id.as_deref().unwrap_or("pending");
        let metadata = format!(
            "# TriLane Transcript\n\n- Started at: {}\n- Objective: {}\n- Audit mode: {}\n- Turn ID: {}\n- Status: {}\n- Root: {}\n\n## Stage Files\n- s0_gate.md\n- s1_recon.md\n- s2_audit.md\n- s3_foa.md\n- s4_fuzz.md\n- s5_verify.md\n",
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
            "# TriLane Transcript\n\n- Started at: {}\n- Objective: {}\n- Audit mode: {}\n- Turn ID: {}\n- Status: {}\n- Root claims: {}\n- Final findings: {}\n- Publishable claims: {}\n- Current stage at finish: {}\n- Root: {}\n\n## Stage Files\n- s0_gate.md\n- s1_recon.md\n- s2_audit.md\n- s3_foa.md\n- s4_fuzz.md\n- s5_verify.md\n",
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

        let turn_dir = fs::read_dir(&root)
            .expect("turn dir")
            .next()
            .expect("single transcript")
            .expect("dir entry")
            .path();
        let stage_file = turn_dir.join("s1_recon.md");
        let readme = turn_dir.join("README.md");

        let stage_text = fs::read_to_string(stage_file).expect("stage file");
        let readme_text = fs::read_to_string(readme).expect("readme");

        assert!(stage_text.contains("### TRI%"));
        assert!(stage_text.contains("RUNBOOK% S1 Recon"));
        assert!(readme_text.contains("turn-123"));

        fs::remove_dir_all(root).expect("cleanup");
    }
}
