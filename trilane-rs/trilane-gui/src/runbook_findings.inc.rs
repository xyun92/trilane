impl RunbookState {
    fn add_finding(&mut self, input: RunbookFindingInput<'_>) {
        let title = input.title.trim();
        if title.is_empty() {
            return;
        }
        if self.findings.iter().any(|finding| {
            finding.title == title
                && finding.severity == input.severity
                && finding.code_path == input.code_path
        }) {
            return;
        }
        if let Some(candidate_id) = input.candidate_id.as_deref() {
            if let Some(candidate) = self
                .candidates
                .iter_mut()
                .find(|candidate| candidate.id == candidate_id)
            {
                candidate.status = CandidateStatus::Confirmed;
                candidate.severity = Some(input.severity.to_string());
                candidate.source_confirmed = !input.code_path.trim().is_empty();
                candidate.updated_at = now();
            }
        }
        let category = input
            .candidate_id
            .as_deref()
            .and_then(|id| {
                self.candidates
                    .iter()
                    .find(|candidate| candidate.id == id)
                    .map(|candidate| candidate.category.clone())
            })
            .unwrap_or_else(|| {
                self.canonical_coverage_category(&infer_category(&format!(
                    "{}\n{}\n{}",
                    title, input.code_path, input.detail
                )))
            });
        self.mark_coverage_signal(&category, title);
        let evidence_level = infer_evidence_level(
            input.code_path,
            &input.detail,
            "",
            &input.payload,
            input.confidence,
        );
        let mut status = status_from_evidence(&evidence_level, false);
        if matches!(status, ClaimStatus::Verified | ClaimStatus::Weaponized)
            && !input.payload.trim().is_empty()
            && !input.code_path.trim().is_empty()
        {
            status = ClaimStatus::Publishable;
        }
        self.upsert_claim(ClaimSeed {
            id: input.candidate_id.clone(),
            stage: input.stage,
            category: &category,
            title,
            target: input.code_path,
            code_path: input.code_path,
            root_cause: input.code_path,
            precondition: "",
            impact: &input.detail,
            payload: &input.payload,
            positive_evidence: &input.detail,
            negative_evidence: "",
            severity: Some(input.severity.to_string()),
            status,
            evidence_level,
            timestamp: now(),
        });
        let finding = RunbookFinding {
            id: format!("finding-{}", self.findings.len() + 1),
            stage: input.stage.to_string(),
            candidate_id: input.candidate_id,
            severity: input.severity.to_string(),
            title: title.to_string(),
            code_path: input.code_path.to_string(),
            confidence: input.confidence.to_string(),
            evidence_state: input.evidence_state.to_string(),
            detail: input.detail,
            payload: input.payload,
            timestamp: now(),
        };
        self.findings.push(finding);
        if self.findings.len() > MAX_FINDINGS {
            self.findings.remove(0);
        }
        self.touch();
    }

    fn extract_ledger_from_text(&mut self, stage: &str, text: &str) {
        self.extract_finding_blocks(stage, text);
        let mut current_stage = stage;
        let mut attack_graph_dirty = false;
        for raw_line in text.lines() {
            let normalized_line = normalize_marker_line(raw_line);
            let line = normalized_line.as_str();
            if line.is_empty() {
                continue;
            }
            if let Some(marker_stage) = runbook_marker_stage(line) {
                current_stage = marker_stage;
            }
            let lower = line.to_ascii_lowercase();
            if lower.starts_with("subagent%") || lower.starts_with("lane_report%") {
                let report_seen = lower.starts_with("lane_report%");
                let lane_id = marker_value(line, "lane")
                    .or_else(|| marker_value(line, "id"))
                    .unwrap_or_else(|| "unknown".to_string());
                let status = marker_value(line, "status").unwrap_or_else(|| "done".to_string());
                let claim_count = marker_value(line, "claims")
                    .or_else(|| marker_value(line, "count"))
                    .and_then(|value| value.parse().ok());
                let candidate_count =
                    marker_value(line, "candidates").and_then(|value| value.parse().ok());
                let thread_id =
                    marker_value(line, "thread_id").or_else(|| marker_value(line, "thread"));
                let summary = marker_value(line, "note")
                    .or_else(|| marker_value(line, "summary"))
                    .or_else(|| marker_value(line, "error"))
                    .unwrap_or_else(|| strip_marker(line).to_string());
                self.record_subagent_lane(RunbookLaneUpdate {
                    stage: current_stage,
                    lane_id: &lane_id,
                    status: &status,
                    report_seen,
                    claim_count,
                    candidate_count,
                    thread_id: thread_id.as_deref(),
                    summary: &summary,
                });
            } else if lower.starts_with("coverage%") {
                let category = marker_value(line, "category")
                    .or_else(|| marker_value(line, "area"))
                    .unwrap_or_else(|| "unknown".to_string());
                let label = marker_value(line, "label")
                    .or_else(|| marker_value(line, "target"))
                    .unwrap_or_else(|| category.clone());
                let mapped = marker_value(line, "mapped").and_then(|value| value.parse().ok());
                let total = marker_value(line, "total").and_then(|value| value.parse().ok());
                self.record_coverage(&category, &label, mapped, total);
            } else if lower.starts_with("surface%") {
                let category =
                    marker_value(line, "category").unwrap_or_else(|| infer_category(line));
                let kind = marker_value(line, "kind").unwrap_or_else(|| "surface".to_string());
                let target = marker_value(line, "target")
                    .or_else(|| marker_value(line, "route"))
                    .unwrap_or_else(|| strip_marker(line).to_string());
                let label = marker_value(line, "label")
                    .or_else(|| marker_value(line, "title"))
                    .unwrap_or_else(|| target.clone());
                self.record_surface(current_stage, &kind, &category, &label, &target);
                attack_graph_dirty = true;
            } else if lower.starts_with("feature%") {
                let category =
                    marker_value(line, "category").unwrap_or_else(|| infer_category(line));
                let kind = marker_value(line, "kind").unwrap_or_else(|| "feature".to_string());
                let target = marker_value(line, "target")
                    .or_else(|| marker_value(line, "feature"))
                    .or_else(|| marker_value(line, "route"))
                    .unwrap_or_else(|| strip_marker(line).to_string());
                let label = marker_value(line, "label")
                    .or_else(|| marker_value(line, "feature"))
                    .or_else(|| marker_value(line, "title"))
                    .unwrap_or_else(|| target.clone());
                self.record_surface(current_stage, &kind, &category, &label, &target);
                attack_graph_dirty = true;
            } else if lower.starts_with("obligation%") {
                self.extract_obligation_marker(current_stage, line);
                attack_graph_dirty = true;
            } else if lower.starts_with("candidate%") {
                let title = marker_value(line, "title")
                    .or_else(|| marker_value(line, "target"))
                    .unwrap_or_else(|| strip_marker(line).to_string());
                let target = marker_value(line, "target").unwrap_or_default();
                let category =
                    marker_value(line, "category").unwrap_or_else(|| infer_category(&title));
                let id = marker_value(line, "id");
                self.upsert_candidate_with_id(current_stage, id, &category, &title, target);
                attack_graph_dirty = true;
            } else if lower.starts_with("claim%") {
                self.extract_claim_marker(current_stage, line);
                attack_graph_dirty = true;
            } else if lower.starts_with("attack_atom%") || lower.starts_with("atom%") {
                self.extract_attack_atom_marker(current_stage, line);
                attack_graph_dirty = true;
            } else if lower.starts_with("chain_candidate%") || lower.starts_with("chain_hint%") {
                self.extract_chain_candidate_marker(current_stage, line);
                attack_graph_dirty = true;
            } else if lower.starts_with("chain_verify%") {
                self.extract_chain_verify_marker(current_stage, line);
            } else if lower.starts_with("probe%") {
                let id = marker_value(line, "id").unwrap_or_else(|| "unlinked-probe".to_string());
                let result = marker_value(line, "result")
                    .or_else(|| marker_value(line, "evidence"))
                    .unwrap_or_else(|| strip_marker(line).to_string());
                self.record_probe(&id, current_stage, &result);
            } else if lower.starts_with("control%") {
                let id = marker_value(line, "id").unwrap_or_else(|| "unlinked-control".to_string());
                let result = marker_value(line, "negative")
                    .or_else(|| marker_value(line, "control"))
                    .or_else(|| marker_value(line, "result"))
                    .unwrap_or_else(|| strip_marker(line).to_string());
                self.record_negative_control(&id, current_stage, &result);
            } else if lower.starts_with("s4_skip%") {
                let id = marker_value(line, "id").unwrap_or_else(|| "unlinked-s4-skip".to_string());
                let reason =
                    marker_value(line, "reason").unwrap_or_else(|| strip_marker(line).to_string());
                self.record_evidence(current_stage, "s4_skip", id, truncate(&reason, 700));
            } else if lower.starts_with("rejected%")
                || lower.starts_with("duplicate%")
                || lower.starts_with("out_of_scope%")
            {
                let id =
                    marker_value(line, "id").unwrap_or_else(|| "unlinked-rejected".to_string());
                let reason =
                    marker_value(line, "reason").unwrap_or_else(|| strip_marker(line).to_string());
                let status = if lower.starts_with("duplicate%") {
                    CandidateStatus::Duplicate
                } else if lower.starts_with("out_of_scope%") {
                    CandidateStatus::OutOfScope
                } else {
                    CandidateStatus::Rejected
                };
                self.set_candidate_status(&id, current_stage, status, &reason);
            } else if lower.starts_with("merge%") {
                let id = marker_value(line, "id").unwrap_or_else(|| "unlinked-merge".to_string());
                let into = marker_value(line, "merge_into")
                    .or_else(|| marker_value(line, "merged_into"))
                    .unwrap_or_else(|| "unknown".to_string());
                let reason =
                    marker_value(line, "reason").unwrap_or_else(|| strip_marker(line).to_string());
                self.merge_claim(&id, &into, current_stage, &reason);
            } else if lower.starts_with("adjudicate%") {
                let id =
                    marker_value(line, "id").unwrap_or_else(|| "unlinked-adjudicate".to_string());
                let status = marker_value(line, "status")
                    .map(|value| ClaimStatus::from_marker(&value))
                    .unwrap_or(ClaimStatus::Verified);
                let reason =
                    marker_value(line, "reason").unwrap_or_else(|| strip_marker(line).to_string());
                self.set_claim_status(&id, current_stage, status, &reason);
            } else if lower.starts_with("verify%") {
                let id = marker_value(line, "id").unwrap_or_else(|| "unlinked-verify".to_string());
                let signal = marker_value(line, "evidence")
                    .or_else(|| marker_value(line, "result"))
                    .unwrap_or_else(|| strip_marker(line).to_string());
                self.record_verify(&id, current_stage, &signal, line);
            } else if lower.starts_with("finding%") {
                self.extract_finding_marker(current_stage, line);
                attack_graph_dirty = true;
            }
        }
        if attack_graph_dirty {
            self.synthesize_attack_graph(current_stage);
        }
    }

    fn extract_finding_blocks(&mut self, stage: &str, text: &str) {
        if stage == "stage5" {
            return;
        }
        let mut current_stage = stage;
        let mut lines = text.lines().peekable();
        while let Some(line) = lines.next() {
            let trimmed = line.trim();
            let normalized_line = normalize_marker_line(trimmed);
            if let Some(marker_stage) = runbook_marker_stage(&normalized_line) {
                current_stage = marker_stage;
            }
            if current_stage == "stage5" {
                continue;
            }
            if !is_finding_heading(trimmed) {
                continue;
            }
            let mut block = vec![trimmed.to_string()];
            while let Some(next) = lines.peek() {
                let next_trimmed = next.trim();
                let next_lower = next_trimmed.to_ascii_lowercase();
                if is_finding_heading(next_trimmed)
                    || next_lower.starts_with("runbook%")
                    || next_lower.starts_with("candidate%")
                    || next_lower.starts_with("coverage%")
                {
                    break;
                }
                if !next_trimmed.is_empty() {
                    block.push(next_trimmed.to_string());
                }
                lines.next();
            }
            self.add_finding_block(current_stage, &block);
        }
    }

    fn extract_finding_marker(&mut self, stage: &str, line: &str) {
        let title = marker_value(line, "title").unwrap_or_else(|| strip_marker(line).to_string());
        let severity = marker_value(line, "severity").unwrap_or_else(|| infer_severity(line));
        let code_path = marker_value(line, "code_path").unwrap_or_default();
        let confidence = marker_value(line, "confidence").unwrap_or_else(|| "medium".to_string());
        let evidence =
            marker_value(line, "evidence").unwrap_or_else(|| strip_marker(line).to_string());
        let payload = marker_value(line, "payload")
            .or_else(|| marker_value(line, "exploit"))
            .or_else(|| marker_value(line, "poc"))
            .unwrap_or_else(|| extract_payload_from_text(line, &evidence));
        let candidate_id = marker_value(line, "id");
        let category = candidate_id
            .as_deref()
            .and_then(|id| {
                self.candidates
                    .iter()
                    .find(|candidate| candidate.id == id)
                    .map(|candidate| candidate.category.clone())
            })
            .unwrap_or_else(|| infer_category(&title));
        if let Some(id) = candidate_id.as_deref() {
            self.upsert_candidate_with_id(
                stage,
                Some(id.to_string()),
                &category,
                &title,
                code_path.clone(),
            );
        }
        self.add_finding(RunbookFindingInput {
            stage,
            candidate_id,
            severity: &severity,
            title: &title,
            code_path: &code_path,
            confidence: &confidence,
            evidence_state: evidence_gate(&code_path, &evidence, &confidence),
            detail: truncate(&evidence, 500),
            payload: truncate(&payload, 900),
        });
    }

    fn add_finding_block(&mut self, stage: &str, block: &[String]) {
        let joined = block.join("\n");
        let title = finding_heading_title(&block[0]).unwrap_or("Confirmed vulnerability");
        let severity =
            field_from_block(block, "severity").unwrap_or_else(|| infer_severity(&joined));
        let code_path = field_from_block(block, "code_path").unwrap_or_default();
        let confidence =
            field_from_block(block, "confidence").unwrap_or_else(|| "medium".to_string());
        let candidate_id = field_from_block(block, "id");
        let evidence = field_from_block(block, "evidence").unwrap_or_else(|| joined.clone());
        let payload = field_from_block(block, "payload")
            .or_else(|| field_from_block(block, "exploit"))
            .or_else(|| field_from_block(block, "poc"))
            .or_else(|| field_from_block(block, "proof"))
            .unwrap_or_else(|| extract_payload_from_text(&joined, &evidence));
        if code_path.trim().is_empty()
            && candidate_id.is_none()
            && payload.trim().is_empty()
            && looks_like_stage5_summary_echo(stage, &joined)
        {
            self.record_evidence(
                stage,
                "dedupe",
                title,
                "Ignored summary-only finding echo".to_string(),
            );
            return;
        }
        let category = candidate_id
            .as_deref()
            .and_then(|id| {
                self.candidates
                    .iter()
                    .find(|candidate| candidate.id == id)
                    .map(|candidate| candidate.category.clone())
            })
            .unwrap_or_else(|| infer_category(title));
        if let Some(id) = candidate_id.as_deref() {
            self.upsert_candidate_with_id(
                stage,
                Some(id.to_string()),
                &category,
                title,
                code_path.clone(),
            );
        }
        self.add_finding(RunbookFindingInput {
            stage,
            candidate_id,
            severity: &severity,
            title,
            code_path: &code_path,
            confidence: &confidence,
            evidence_state: evidence_gate(&code_path, &evidence, &confidence),
            detail: truncate(&joined, 700),
            payload: truncate(&payload, 900),
        });
    }
}
