impl RunbookState {
    fn record_coverage(
        &mut self,
        category: &str,
        label: &str,
        mapped: Option<usize>,
        total: Option<usize>,
    ) {
        let category = self.canonical_coverage_category(category);
        let normalized = normalize_id(&category);
        if let Some(item) = self
            .coverage
            .iter_mut()
            .find(|item| normalize_id(&item.category) == normalized)
        {
            item.label = label.to_string();
            item.mapped_count = mapped.unwrap_or(item.mapped_count.max(1));
            item.total_hint = total.or(item.total_hint);
            item.status = if item
                .total_hint
                .is_some_and(|total| item.mapped_count < total)
            {
                CoverageStatus::Partial
            } else {
                CoverageStatus::Mapped
            };
            item.updated_at = now();
        } else {
            let mapped_count = mapped.unwrap_or(1);
            self.coverage.push(RunbookCoverage {
                id: format!("coverage-{normalized}"),
                category,
                label: label.to_string(),
                mapped_count,
                total_hint: total,
                status: if total.is_some_and(|total| mapped_count < total) {
                    CoverageStatus::Partial
                } else {
                    CoverageStatus::Mapped
                },
                updated_at: now(),
            });
        }
        self.touch();
    }

    fn record_surface(
        &mut self,
        stage: &str,
        kind: &str,
        category: &str,
        label: &str,
        target: &str,
    ) {
        let category = self.canonical_coverage_category(category);
        let id = format!(
            "surface-{}-{}-{}",
            normalize_id(kind),
            normalize_id(&category),
            normalize_id(target)
        );
        if let Some(surface) = self.surfaces.iter_mut().find(|surface| surface.id == id) {
            surface.stage = stage.to_string();
            surface.label = truncate(label, 140);
            surface.signal_count += 1;
            surface.updated_at = now();
        } else {
            self.surfaces.push(RunbookSurface {
                id,
                stage: stage.to_string(),
                kind: kind.to_string(),
                category: category.clone(),
                label: truncate(label, 140),
                target: truncate(target, 180),
                signal_count: 1,
                updated_at: now(),
            });
            if self.surfaces.len() > MAX_SURFACES {
                self.surfaces.remove(0);
            }
        }
        self.mark_coverage_signal(&category, label);
        self.touch();
    }

    fn canonical_coverage_category(&self, category: &str) -> String {
        match category {
            "input" => "injection",
            "ssrf" => "ssrf_redirect",
            "files" => "file_upload_xxe",
            "secrets" => "secrets_config",
            "api" | "rest" | "workflow" | "logic" | "business" | "business_logic" => {
                "state_invariant_abuse"
            }
            "automation" | "anti_automation" | "anti-bot" | "bot" => {
                "anti_automation_bypass"
            }
            "debug_metrics_docs" | "info_disclosure" | "debug" | "metrics" | "logs" | "docs" => {
                "observability_leak"
            }
            "observability" | "observability_leaks" => "observability_leak",
            "headers" | "cors" | "tls" => "cors_headers_tls",
            "storage" => "session",
            value => value,
        }
        .to_string()
    }

    fn upsert_candidate(
        &mut self,
        stage: &str,
        category: &str,
        title: &str,
        target: String,
    ) -> String {
        self.upsert_candidate_with_id(stage, None, category, title, target)
    }

    fn upsert_candidate_with_id(
        &mut self,
        stage: &str,
        id: Option<String>,
        category: &str,
        title: &str,
        target: String,
    ) -> String {
        let id = id.unwrap_or_else(|| {
            self.candidates
                .iter()
                .find(|candidate| {
                    normalize_id(&candidate.title) == normalize_id(title)
                        && normalize_id(&candidate.target) == normalize_id(&target)
                })
                .map(|candidate| candidate.id.clone())
                .unwrap_or_else(|| format!("CAND-{:02}", self.candidates.len() + 1))
        });
        if let Some(candidate) = self
            .candidates
            .iter_mut()
            .find(|candidate| candidate.id == id)
        {
            candidate.stage = stage.to_string();
            candidate.category = category.to_string();
            candidate.title = title.to_string();
            if !target.trim().is_empty() {
                candidate.target = append_compact(&candidate.target, &target, 220);
            }
            candidate.updated_at = now();
        } else {
            let category = self.canonical_coverage_category(category);
            self.candidates.push(RunbookCandidate {
                id: id.clone(),
                stage: stage.to_string(),
                category: category.clone(),
                title: truncate(title, 140),
                target: truncate(&target, 160),
                status: CandidateStatus::Candidate,
                severity: None,
                evidence_count: 0,
                verification_count: 0,
                source_confirmed: false,
                updated_at: now(),
            });
            if self.candidates.len() > MAX_CANDIDATES {
                self.candidates.remove(0);
            }
            self.mark_coverage_signal(&category, title);
        }
        self.upsert_claim(ClaimSeed {
            id: Some(id.clone()),
            stage,
            category,
            title,
            target: &target,
            code_path: "",
            root_cause: "",
            precondition: "",
            impact: "",
            payload: "",
            positive_evidence: title,
            negative_evidence: "",
            severity: None,
            status: ClaimStatus::Seed,
            evidence_level: EvidenceLevel::Signal,
            timestamp: now(),
        });
        self.touch();
        id
    }

    fn extract_claim_marker(&mut self, stage: &str, line: &str) {
        let title = marker_value(line, "title")
            .or_else(|| marker_value(line, "target"))
            .unwrap_or_else(|| strip_marker(line).to_string());
        let target = marker_value(line, "target")
            .or_else(|| marker_value(line, "surface"))
            .unwrap_or_default();
        let category = marker_value(line, "category").unwrap_or_else(|| infer_category(&title));
        let code_path = marker_value(line, "code_path").unwrap_or_default();
        let root_cause = marker_value(line, "root_cause").unwrap_or_default();
        let precondition = marker_value(line, "precondition").unwrap_or_default();
        let impact = marker_value(line, "impact").unwrap_or_default();
        let payload = marker_value(line, "payload")
            .or_else(|| marker_value(line, "exploit"))
            .unwrap_or_default();
        let positive = marker_value(line, "positive")
            .or_else(|| marker_value(line, "evidence"))
            .unwrap_or_else(|| strip_marker(line).to_string());
        let negative = marker_value(line, "negative").unwrap_or_default();
        let status = marker_value(line, "status")
            .map(|value| ClaimStatus::from_marker(&value))
            .unwrap_or(ClaimStatus::Seed);
        let evidence_level = marker_value(line, "level")
            .map(|value| EvidenceLevel::from_marker(&value))
            .unwrap_or_else(|| {
                infer_evidence_level(&code_path, &positive, &negative, &payload, "medium")
            });
        self.upsert_claim(ClaimSeed {
            id: marker_value(line, "id"),
            stage,
            category: &category,
            title: &title,
            target: &target,
            code_path: &code_path,
            root_cause: &root_cause,
            precondition: &precondition,
            impact: &impact,
            payload: &payload,
            positive_evidence: &positive,
            negative_evidence: &negative,
            severity: marker_value(line, "severity"),
            status,
            evidence_level,
            timestamp: now(),
        });
    }

    fn extract_obligation_marker(&mut self, stage: &str, line: &str) {
        let category = marker_value(line, "category").unwrap_or_else(|| infer_category(line));
        let feature = marker_value(line, "feature")
            .or_else(|| marker_value(line, "target"))
            .unwrap_or_else(|| "unmapped-feature".to_string());
        let target = marker_value(line, "target")
            .or_else(|| marker_value(line, "route"))
            .unwrap_or_else(|| feature.clone());
        let must = marker_value(line, "must")
            .or_else(|| marker_value(line, "check"))
            .or_else(|| marker_value(line, "obligation"))
            .or_else(|| marker_value(line, "title"))
            .unwrap_or_else(|| strip_marker(line).to_string());
        let title = if feature == must {
            must.clone()
        } else {
            format!("{feature}: {must}")
        };
        let code_path = marker_value(line, "code_path").unwrap_or_default();
        let root_cause = marker_value(line, "root_cause").unwrap_or_default();
        let precondition = marker_value(line, "precondition").unwrap_or_default();
        let impact = marker_value(line, "impact").unwrap_or_else(|| {
            format!("Close this CVE-prior security obligation for feature {feature}.")
        });
        let payload = marker_value(line, "payload")
            .or_else(|| marker_value(line, "attack"))
            .unwrap_or_default();
        let evidence = marker_value(line, "evidence")
            .or_else(|| marker_value(line, "reason"))
            .or_else(|| marker_value(line, "cve_prior"))
            .unwrap_or_else(|| "feature matched empirical vulnerability prior".to_string());
        let status = marker_value(line, "status")
            .map(|value| ClaimStatus::from_marker(&value))
            .unwrap_or(ClaimStatus::Seed);
        let evidence_level = marker_value(line, "level")
            .map(|value| EvidenceLevel::from_marker(&value))
            .unwrap_or(EvidenceLevel::Signal);
        let candidate_id =
            self.upsert_candidate_with_id(stage, marker_value(line, "id"), &category, &title, target);
        let positive = format!("feature={feature}; must={must}; evidence={evidence}");
        self.upsert_claim(ClaimSeed {
            id: Some(candidate_id.clone()),
            stage,
            category: &category,
            title: &title,
            target: &feature,
            code_path: &code_path,
            root_cause: &root_cause,
            precondition: &precondition,
            impact: &impact,
            payload: &payload,
            positive_evidence: &positive,
            negative_evidence: "",
            severity: marker_value(line, "severity"),
            status,
            evidence_level,
            timestamp: now(),
        });
        self.record_evidence(stage, "obligation", &candidate_id, truncate(&positive, 700));
    }

    fn upsert_claim(&mut self, seed: ClaimSeed<'_>) -> String {
        let category = self.canonical_coverage_category(seed.category);
        let normalized_seed = ClaimSeed {
            category: &category,
            ..seed
        };
        let fingerprint = canonical_claim_fingerprint(&normalized_seed);
        let id = normalized_seed.id.clone().unwrap_or_else(|| {
            self.claims
                .iter()
                .find(|claim| claim.fingerprint == fingerprint)
                .map(|claim| claim.id.clone())
                .unwrap_or_else(|| format!("CLM-{:03}", self.claims.len() + 1))
        });
        if let Some(claim) = self
            .claims
            .iter_mut()
            .find(|claim| claim.id == id || claim.fingerprint == fingerprint)
        {
            claim.stage = normalized_seed.stage.to_string();
            claim.category = category.clone();
            if !normalized_seed.code_path.trim().is_empty()
                || !normalized_seed.root_cause.trim().is_empty()
            {
                claim.fingerprint = fingerprint;
            }
            claim.title = prefer_longer(&claim.title, normalized_seed.title, 180);
            if !normalized_seed.target.trim().is_empty() {
                claim.target = truncate(normalized_seed.target, 180);
            }
            if !normalized_seed.code_path.trim().is_empty() {
                claim.code_path = truncate(normalized_seed.code_path, 180);
            }
            if !normalized_seed.root_cause.trim().is_empty() {
                claim.root_cause = truncate(normalized_seed.root_cause, 220);
            }
            if !normalized_seed.precondition.trim().is_empty() {
                claim.precondition = truncate(normalized_seed.precondition, 220);
            }
            if !normalized_seed.impact.trim().is_empty() {
                claim.impact = truncate(normalized_seed.impact, 220);
            }
            if !normalized_seed.payload.trim().is_empty() {
                claim.payload = truncate(normalized_seed.payload, 900);
            }
            if !normalized_seed.positive_evidence.trim().is_empty() {
                claim.positive_evidence = append_compact(
                    &claim.positive_evidence,
                    normalized_seed.positive_evidence,
                    700,
                );
            }
            if !normalized_seed.negative_evidence.trim().is_empty() {
                claim.negative_evidence = append_compact(
                    &claim.negative_evidence,
                    normalized_seed.negative_evidence,
                    700,
                );
            }
            claim.severity = normalized_seed.severity.or_else(|| claim.severity.clone());
            claim.status = claim.status.clone().merge(normalized_seed.status);
            claim.evidence_level = claim
                .evidence_level
                .clone()
                .merge(normalized_seed.evidence_level);
            claim.signal_count += 1;
            claim.updated_at = normalized_seed.timestamp.clone();
            self.touch();
            id
        } else {
            self.claims.push(RunbookClaim {
                id: id.clone(),
                fingerprint,
                stage: normalized_seed.stage.to_string(),
                category: category.clone(),
                title: truncate(normalized_seed.title, 180),
                target: truncate(normalized_seed.target, 180),
                status: normalized_seed.status,
                evidence_level: normalized_seed.evidence_level,
                severity: normalized_seed.severity,
                code_path: truncate(normalized_seed.code_path, 180),
                root_cause: truncate(normalized_seed.root_cause, 220),
                precondition: truncate(normalized_seed.precondition, 220),
                impact: truncate(normalized_seed.impact, 220),
                payload: truncate(normalized_seed.payload, 900),
                positive_evidence: truncate(normalized_seed.positive_evidence, 700),
                negative_evidence: truncate(normalized_seed.negative_evidence, 700),
                merged_into: None,
                signal_count: 1,
                probe_count: 0,
                verification_count: 0,
                updated_at: normalized_seed.timestamp,
            });
            if self.claims.len() > MAX_CLAIMS {
                self.claims.remove(0);
            }
            self.mark_coverage_signal(&category, normalized_seed.title);
            self.touch();
            id
        }
    }

    fn record_probe(&mut self, id: &str, stage: &str, result: &str) {
        self.ensure_candidate_stub(id, stage);
        if let Some(candidate) = self
            .candidates
            .iter_mut()
            .find(|candidate| candidate.id == id)
        {
            if candidate.status == CandidateStatus::Candidate {
                candidate.status = CandidateStatus::Probed;
            }
            candidate.evidence_count += 1;
            candidate.updated_at = now();
        }
        self.advance_claim_from_signal(
            id,
            stage,
            ClaimStatus::Running,
            EvidenceLevel::RuntimeSignal,
            result,
            "",
        );
        self.record_evidence(stage, "probe", id, truncate(result, 700));
    }

    fn record_verify(&mut self, id: &str, stage: &str, signal: &str, raw: &str) {
        self.ensure_candidate_stub(id, stage);
        if let Some(candidate) = self
            .candidates
            .iter_mut()
            .find(|candidate| candidate.id == id)
        {
            candidate.status = CandidateStatus::NeedsVerify;
            candidate.verification_count += verification_weight(raw);
            candidate.source_confirmed = candidate.source_confirmed
                || raw.to_ascii_lowercase().contains("code_path")
                || raw.to_ascii_lowercase().contains("root_cause")
                || raw.to_ascii_lowercase().contains("source");
            candidate.updated_at = now();
        }
        let code_path = marker_value(raw, "code_path").unwrap_or_default();
        let control = marker_value(raw, "control")
            .or_else(|| marker_value(raw, "negative"))
            .unwrap_or_default();
        let payload = marker_value(raw, "exploit").unwrap_or_default();
        let level = infer_evidence_level(&code_path, signal, &control, &payload, "high");
        let status = status_from_evidence(&level, !control.trim().is_empty());
        self.advance_claim_from_signal(id, stage, status, level, signal, &control);
        self.record_evidence(stage, "verify", id, truncate(signal, 700));
    }

    fn record_negative_control(&mut self, id: &str, stage: &str, result: &str) {
        self.ensure_candidate_stub(id, stage);
        self.advance_claim_from_signal(
            id,
            stage,
            ClaimStatus::Verified,
            EvidenceLevel::ControlPassed,
            "",
            result,
        );
        self.record_evidence(stage, "control", id, truncate(result, 700));
    }

    fn set_candidate_status(
        &mut self,
        id: &str,
        stage: &str,
        status: CandidateStatus,
        reason: &str,
    ) {
        self.ensure_candidate_stub(id, stage);
        if let Some(candidate) = self
            .candidates
            .iter_mut()
            .find(|candidate| candidate.id == id)
        {
            candidate.status = status.clone();
            candidate.updated_at = now();
        }
        let claim_status = match status {
            CandidateStatus::Candidate => ClaimStatus::Seed,
            CandidateStatus::Probed => ClaimStatus::Running,
            CandidateStatus::NeedsVerify => ClaimStatus::Armed,
            CandidateStatus::Rejected | CandidateStatus::OutOfScope => ClaimStatus::Discarded,
            CandidateStatus::Duplicate => ClaimStatus::Merged,
            CandidateStatus::Confirmed => ClaimStatus::Publishable,
        };
        self.set_claim_status(id, stage, claim_status, reason);
        self.record_evidence(stage, "disposition", id, truncate(reason, 700));
    }

    fn advance_claim_from_signal(
        &mut self,
        id: &str,
        stage: &str,
        status: ClaimStatus,
        level: EvidenceLevel,
        positive: &str,
        negative: &str,
    ) {
        if let Some(claim) = self.claims.iter_mut().find(|claim| claim.id == id) {
            claim.stage = stage.to_string();
            claim.status = claim.status.clone().merge(status);
            claim.evidence_level = claim.evidence_level.clone().merge(level);
            if !positive.trim().is_empty() {
                claim.positive_evidence = append_compact(&claim.positive_evidence, positive, 700);
                claim.probe_count += 1;
            }
            if !negative.trim().is_empty() {
                claim.negative_evidence = append_compact(&claim.negative_evidence, negative, 700);
                claim.verification_count += 1;
            }
            claim.updated_at = now();
        } else {
            self.upsert_claim(ClaimSeed {
                id: Some(id.to_string()),
                stage,
                category: &infer_category(&format!("{positive}\n{negative}")),
                title: id,
                target: "",
                code_path: "",
                root_cause: "",
                precondition: "",
                impact: "",
                payload: "",
                positive_evidence: positive,
                negative_evidence: negative,
                severity: None,
                status,
                evidence_level: level,
                timestamp: now(),
            });
        }
        self.touch();
    }
}
