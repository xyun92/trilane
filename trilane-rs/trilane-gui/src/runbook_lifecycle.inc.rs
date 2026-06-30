impl RunbookState {
    pub fn start_turn(&mut self, objective: &str, audit_mode: AuditMode) {
        let next_revision = self.revision.saturating_add(1);
        *self = Self::default();
        self.revision = next_revision;
        self.audit_mode = audit_mode;
        self.coverage = default_coverage(&self.audit_mode);
        self.status = RunbookStatus::Running;
        self.objective = objective.trim().to_string();
        self.activate_stage("stage0", "Admission check started");
        self.record_evidence(
            "stage0",
            "objective",
            "Agent objective",
            format!(
                "AUDIT_MODE% {}\n{}",
                self.audit_mode.as_marker(),
                truncate(objective, 500)
            ),
        );
    }

    pub fn set_turn_id(&mut self, turn_id: String) {
        self.status = RunbookStatus::Running;
        self.turn_id = Some(turn_id);
        self.touch();
    }

    pub fn complete(&mut self) {
        self.record_watchdog_if_needed();
        self.record_trilane_gate_if_needed();
        if let Some(reason) = self.trilane_s1_blocker() {
            self.record_evidence("stage1", "watchdog", "S1 surface ledger missing", reason);
            self.status = RunbookStatus::Error;
            self.current_stage = "stage1".to_string();
            self.mark_stage_blocked("stage1", "S1 ledger missing; rerun reconnaissance");
            self.touch();
            return;
        }
        if let Some(reason) = self.trilane_workflow_blocker() {
            self.record_evidence(
                "stage5",
                "workflow",
                "Workflow gate blocked before S5",
                reason,
            );
            self.status = RunbookStatus::Error;
            self.current_stage = "stage5".to_string();
            self.mark_stage_blocked("stage5", "Waiting for S5 verification/adjudication");
            self.touch();
            return;
        }
        self.finalize_stage5();
        self.status = RunbookStatus::Completed;
        self.mark_stage_done(&self.current_stage.clone());
        self.touch();
    }

    pub fn final_report_markdown(&self) -> String {
        let findings = if self.status == RunbookStatus::Error {
            self.final_findings.clone()
        } else if self.final_findings.is_empty() {
            crate::runbook_finalize::adjudicate_findings(&self.findings, &self.claims).0
        } else {
            self.final_findings.clone()
        };
        let mut report = String::new();
        report.push_str("# TriLane Final Security Findings\n\n");
        report.push_str(&format!(
            "- Objective: {}\n- Audit mode: {}\n- Workflow status: {:?}\n- Turn: {}\n- Root claims: {}\n- Publishable claims: {}\n- Raw findings: {}\n- Final findings: {}\n- Duplicates collapsed: {}\n- Needs PoC: {}\n\n",
            self.objective,
            self.audit_mode.as_marker(),
            self.status,
            self.turn_id.as_deref().unwrap_or("unknown"),
            self.claim_summary.root_claims,
            self.claim_summary.publishable,
            self.dedupe_summary.raw_findings.max(self.findings.len()),
            findings.len(),
            self.dedupe_summary.duplicates,
            self.dedupe_summary.needs_poc,
        ));
        report.push_str("## Findings\n\n");
        for finding in &findings {
            report.push_str(&format!("### {} - {}\n\n", finding.id, finding.title));
            report.push_str(&format!(
                "- Severity: {}\n- Status: {}\n- Confidence: {}\n- Location: {}\n- Code path: {}\n- Candidate: {}\n- Duplicates collapsed: {}\n\n",
                finding.severity.to_uppercase(),
                finding.verification_status,
                finding.confidence,
                empty_dash(&finding.location),
                empty_dash(&finding.code_path),
                finding.candidate_id.as_deref().unwrap_or("-"),
                finding.duplicates.len(),
            ));
            report.push_str("Evidence:\n\n");
            report.push_str("```text\n");
            report.push_str(&finding.detail);
            report.push_str("\n```\n\n");
            if !finding.payload.trim().is_empty() {
                report.push_str("Payload / Exploit:\n\n");
                report.push_str("```text\n");
                report.push_str(&finding.payload);
                report.push_str("\n```\n\n");
            }
        }
        report
    }

    pub fn fail(&mut self, message: &str) {
        self.status = RunbookStatus::Error;
        self.record_evidence(
            &self.current_stage.clone(),
            "error",
            "Agent error",
            truncate(message, 500),
        );
        self.touch();
    }

    pub fn record_workflow_phase(&mut self, stage_id: &str, summary: &str) {
        self.activate_stage(stage_id, summary);
        self.record_evidence(
            stage_id,
            "workflow",
            summary,
            format!("Backend workflow entered {stage_id}: {summary}"),
        );
    }

    pub fn record_subagent_lane(&mut self, update: RunbookLaneUpdate<'_>) {
        let RunbookLaneUpdate {
            stage,
            lane_id,
            status,
            report_seen,
            claim_count,
            candidate_count,
            thread_id,
            summary,
        } = update;
        let lane_id = lane_id.trim();
        if lane_id.is_empty() {
            return;
        }
        let normalized_status = normalize_lane_status(status);
        let position = self.lanes.iter().position(|lane| lane.lane_id == lane_id);
        let mut lane = position
            .and_then(|index| self.lanes.get(index).cloned())
            .unwrap_or_else(|| RunbookLane {
                lane_id: lane_id.to_string(),
                stage: stage.to_string(),
                status: "spawned".to_string(),
                report_seen: false,
                claim_count: 0,
                candidate_count: 0,
                thread_id: String::new(),
                summary: String::new(),
                updated_at: now(),
        });
        lane.stage = stage.to_string();
        lane.status = normalized_status.to_string();
        if report_seen {
            lane.report_seen = true;
        }
        if let Some(count) = claim_count {
            lane.claim_count = count;
        }
        if let Some(count) = candidate_count {
            lane.candidate_count = count;
        }
        match thread_id.map(str::trim) {
            Some(thread_id) if !thread_id.is_empty() => {
                lane.thread_id = thread_id.to_string();
            }
            Some(_) | None => {}
        }
        if !summary.trim().is_empty() {
            lane.summary = truncate(summary.trim(), 300);
        }
        lane.updated_at = now();
        if let Some(index) = position {
            self.lanes[index] = lane;
        } else {
            self.lanes.push(lane);
        }
        self.record_evidence(
            stage,
            "subagent",
            format!("S2 lane {lane_id} {normalized_status}"),
            format!(
                "SUBAGENT% lane={lane_id} status={normalized_status} claims={} candidates={} thread_id={} note={}",
                claim_count.unwrap_or(0),
                candidate_count.unwrap_or(0),
                thread_id.unwrap_or(""),
                truncate(summary, 300)
            ),
        );
        self.touch();
    }

    pub fn s2_required_lanes_complete(&self) -> bool {
        self.s2_missing_lanes().is_empty()
    }

    pub fn s2_missing_lanes(&self) -> Vec<String> {
        required_s2_lanes()
            .iter()
            .filter(|lane_id| {
                !self
                    .lanes
                    .iter()
                    .any(|lane| lane.lane_id == **lane_id && s2_lane_report_complete(lane))
            })
            .map(|lane_id| (*lane_id).to_string())
            .collect()
    }

    pub fn s2_completed_lane_count(&self) -> usize {
        required_s2_lanes()
            .iter()
            .filter(|lane_id| {
                self.lanes
                    .iter()
                    .any(|lane| lane.lane_id == **lane_id && s2_lane_report_complete(lane))
            })
            .count()
    }

    pub fn record_reasoning(&mut self, text: &str) {
        if text.trim().is_empty() {
            return;
        }
        let stage = self.ingest_stage(classify_stage(text, None));
        self.prepare_s5_final_revision_ingest(&stage, text);
        self.activate_stage_from_signal(&stage);
        self.record_evidence(&stage, "trace", first_line(text), truncate(text, 900));
        self.record_runbook_markers(text);
        self.extract_ledger_from_text(&stage, text);
    }

    pub fn record_agent_message(&mut self, text: &str) {
        if text.trim().is_empty() {
            return;
        }
        let stage = self.ingest_stage(classify_stage(text, None));
        self.prepare_s5_final_revision_ingest(&stage, text);
        self.activate_stage_from_signal(&stage);
        if looks_like_report(text) {
            self.activate_stage_from_signal("stage3");
        }
        self.record_evidence(&stage, "agent", first_line(text), truncate(text, 1200));
        self.record_runbook_markers(text);
        self.extract_ledger_from_text(&stage, text);
        if looks_like_report(text) {
            self.record_watchdog_if_needed();
        }
    }

    pub fn record_command(
        &mut self,
        command: &str,
        output: Option<&str>,
        status: &str,
        exit_code: Option<i32>,
    ) {
        let stage = self.ingest_stage(classify_stage(command, output));
        self.activate_stage_from_signal(&stage);
        let mut detail = format!("$ {command}\nstatus={status}");
        if let Some(code) = exit_code {
            detail.push_str(&format!(" exit={code}"));
        }
        if let Some(output) = output {
            if !output.trim().is_empty() {
                detail.push_str("\n--- output ---\n");
                detail.push_str(&truncate(output, 1200));
            }
        }
        self.record_evidence(&stage, "command", command_title(command), detail);
        let inferred_finding = (stage != "stage5")
            .then(|| infer_finding_from_command(command, output.unwrap_or_default()))
            .flatten();
        if let Some(finding) = inferred_finding {
            let candidate_id =
                self.upsert_candidate(&stage, "auto", finding.1, command_title(command));
            self.record_probe(&candidate_id, &stage, "machine signal from command output");
            self.add_finding(RunbookFindingInput {
                stage: &stage,
                candidate_id: Some(candidate_id),
                severity: finding.0,
                title: finding.1,
                code_path: "",
                confidence: "medium",
                evidence_state: "exploit proof",
                detail: finding.2,
                payload: extract_payload_from_text(command, output.unwrap_or_default()),
            });
        }
    }

    fn ingest_stage(&self, classified_stage: &str) -> String {
        if self.status != RunbookStatus::Idle {
            self.current_stage.clone()
        } else {
            classified_stage.to_string()
        }
    }

    fn prepare_s5_final_revision_ingest(&mut self, _stage: &str, text: &str) {
        if !text
            .to_ascii_lowercase()
            .contains("runbook% s5 final revision")
        {
            return;
        }
        self.findings.retain(|finding| finding.stage != "stage5");
        self.final_findings.clear();
        self.dedupe_summary = RunbookDedupeSummary::default();
    }

    fn activate_stage_from_signal(&mut self, _stage_id: &str) {
        // Workflow prompts, lane joins, and explicit backend phase transitions own the
        // visible stage state. Agent text is still ingested as evidence, but it cannot
        // make the Scan UI jump ahead of the scheduler.
    }

    fn activate_stage(&mut self, stage_id: &str, summary: &str) {
        let target_idx = stage_index(stage_id).unwrap_or(0);
        let current_idx = stage_index(&self.current_stage).unwrap_or(0);
        if self.status != RunbookStatus::Idle && target_idx < current_idx {
            if let Some(stage) = self.stages.iter_mut().find(|stage| stage.id == stage_id) {
                stage.summary = summary.to_string();
                stage.updated_at = now();
            }
            self.touch();
            return;
        }
        for (idx, stage) in self.stages.iter_mut().enumerate() {
            stage.status = if idx < target_idx {
                StageStatus::Done
            } else if idx == target_idx {
                StageStatus::Active
            } else {
                StageStatus::Pending
            };
        }
        self.current_stage = stage_id.to_string();
        if let Some(stage) = self.stages.iter_mut().find(|stage| stage.id == stage_id) {
            stage.summary = summary.to_string();
            stage.updated_at = now();
        }
        self.status = RunbookStatus::Running;
        self.touch();
    }

    fn mark_stage_done(&mut self, stage_id: &str) {
        if let Some(stage) = self.stages.iter_mut().find(|stage| stage.id == stage_id) {
            stage.status = StageStatus::Done;
            stage.updated_at = now();
        }
    }

    fn mark_stage_blocked(&mut self, stage_id: &str, summary: &str) {
        let target_idx = stage_index(stage_id).unwrap_or(0);
        for (idx, stage) in self.stages.iter_mut().enumerate() {
            stage.status = if idx < target_idx {
                StageStatus::Done
            } else if idx == target_idx {
                StageStatus::Blocked
            } else {
                StageStatus::Pending
            };
        }
        if let Some(stage) = self.stages.iter_mut().find(|stage| stage.id == stage_id) {
            stage.summary = summary.to_string();
            stage.updated_at = now();
        }
    }

    fn record_evidence(
        &mut self,
        stage: &str,
        kind: &str,
        title: impl Into<String>,
        detail: String,
    ) {
        self.evidence_total = self.evidence_total.saturating_add(1);
        let evidence = RunbookEvidence {
            id: format!("ev-{}", self.evidence_total),
            stage: stage.to_string(),
            kind: kind.to_string(),
            title: truncate(&title.into(), 120),
            detail,
            timestamp: now(),
        };
        self.evidence.push(evidence);
        if self.evidence.len() > MAX_EVIDENCE {
            self.evidence.remove(0);
        }
        self.mark_coverage_from_signal(&format!(
            "{}\n{}\n{}",
            kind,
            self.evidence
                .last()
                .map(|evidence| evidence.title.as_str())
                .unwrap_or_default(),
            self.evidence
                .last()
                .map(|evidence| evidence.detail.as_str())
                .unwrap_or_default()
        ));
        self.touch();
    }

    fn record_runbook_markers(&mut self, text: &str) {
        for line in text.lines() {
            let line = normalize_marker_line(line);
            let Some(stage) = runbook_marker_stage(&line) else {
                continue;
            };
            self.record_evidence(stage, "runbook", first_line(&line), truncate(&line, 300));
        }
    }

}
