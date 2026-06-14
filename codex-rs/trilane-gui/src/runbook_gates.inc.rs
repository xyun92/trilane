impl RunbookState {
    fn set_claim_status(&mut self, id: &str, stage: &str, status: ClaimStatus, reason: &str) {
        if let Some(claim) = self.claims.iter_mut().find(|claim| claim.id == id) {
            claim.stage = stage.to_string();
            claim.status = status.clone();
            if !reason.trim().is_empty() {
                if matches!(status, ClaimStatus::Discarded | ClaimStatus::Blocked) {
                    claim.negative_evidence = append_compact(&claim.negative_evidence, reason, 700);
                } else {
                    claim.positive_evidence = append_compact(&claim.positive_evidence, reason, 700);
                }
            }
            claim.updated_at = now();
        } else {
            self.upsert_claim(ClaimSeed {
                id: Some(id.to_string()),
                stage,
                category: &infer_category(reason),
                title: id,
                target: "",
                code_path: "",
                root_cause: "",
                precondition: "",
                impact: "",
                payload: "",
                positive_evidence: reason,
                negative_evidence: "",
                severity: None,
                status,
                evidence_level: EvidenceLevel::Signal,
                timestamp: now(),
            });
        }
        self.touch();
    }

    fn merge_claim(&mut self, id: &str, into: &str, stage: &str, reason: &str) {
        self.set_claim_status(id, stage, ClaimStatus::Merged, reason);
        if let Some(claim) = self.claims.iter_mut().find(|claim| claim.id == id) {
            claim.merged_into = Some(into.to_string());
            claim.updated_at = now();
        }
        self.touch();
    }

    fn ensure_candidate_stub(&mut self, id: &str, stage: &str) {
        if self.candidates.iter().any(|candidate| candidate.id == id) {
            return;
        }
        self.candidates.push(RunbookCandidate {
            id: id.to_string(),
            stage: stage.to_string(),
            category: "unclassified".to_string(),
            title: id.to_string(),
            target: String::new(),
            status: CandidateStatus::Candidate,
            severity: None,
            evidence_count: 0,
            verification_count: 0,
            source_confirmed: false,
            updated_at: now(),
        });
    }

    fn record_watchdog_if_needed(&mut self) {
        let open = self
            .candidates
            .iter()
            .filter(|candidate| candidate.status == CandidateStatus::Candidate)
            .count();
        if open == 0 {
            return;
        }
        self.record_evidence(
            "stage3",
            "watchdog",
            "No silent candidate drop",
            format!("{open} candidates still need probe/disposition before final claims."),
        );
    }

    fn record_trilane_gate_if_needed(&mut self) {
        let metrics = self.surface_gate_metrics();
        if metrics.debt == 0 {
            return;
        }
        self.record_evidence(
            "stage3",
            "watchdog",
            "Surface-driven workflow debt",
            format!(
                "TRILANE is surface-driven: coverage={coverage_mapped}/{coverage_total}, surfaces queued={surface_covered}/{surfaces}, domain queues closed={domains_closed}/{domains}, hypothesis_pool={hypotheses}/{hypothesis_floor}, open candidates={open_candidates}, open claims={open_claims}, debt={debt}. Coverage categories may be marked not-applicable only with source/route evidence.",
                coverage_mapped = metrics.coverage_mapped,
                coverage_total = self.coverage.len(),
                surface_covered = metrics.surface_covered,
                surfaces = metrics.surfaces,
                domains_closed = metrics.domain_queues_closed,
                domains = metrics.domain_queues,
                hypotheses = metrics.hypothesis_count,
                hypothesis_floor = metrics.hypothesis_floor,
                open_candidates = metrics.open_candidates,
                open_claims = metrics.open_claims,
                debt = metrics.debt,
            ),
        );
    }

    fn trilane_s1_blocker(&self) -> Option<String> {
        if !self.surfaces.is_empty()
            || !self.candidates.is_empty()
            || !self.claims.is_empty()
            || !self.findings.is_empty()
        {
            return None;
        }
        Some(
            "TRILANE stopped before emitting any SURFACE% markers. S1 must produce a route/source-sink surface ledger before S2 or final reporting; prose such as 'now emitting the ledger' is not a ledger.".to_string(),
        )
    }

    fn trilane_workflow_blocker(&self) -> Option<String> {
        if self.findings.is_empty() && self.claims.is_empty() {
            return None;
        }
        let saw_s2 = self.saw_runbook_stage_marker("S2");
        let saw_s3 = self.saw_runbook_stage_marker("S3");
        let saw_s2_or_s3 = saw_s2 || saw_s3;
        if saw_s2
            && !saw_s3
            && (self.saw_runbook_stage_marker("S4") || self.saw_runbook_stage_marker("S5"))
        {
            return Some(
                "TRILANE reached S4/S5 without emitting RUNBOOK% S3 Summary. S3 is a mandatory FoA checkpoint: merge duplicate claim families, record unresolved coverage/hypothesis debt, and publish the S3 ledger before targeted S4 probing.".to_string(),
            );
        }
        if self.saw_runbook_stage_marker("S5") {
            if saw_s2_or_s3 && !self.saw_runbook_stage_marker("S4") {
                return Some(
                    "TRILANE reached S5 without emitting RUNBOOK% S4 Fuzz. S4 must record targeted variant probing, negative controls, or an evidence-backed skip decision before S5 can adjudicate final findings.".to_string(),
                );
            }
            if saw_s2_or_s3 && !self.has_stage4_validation_signal() {
                return Some(
                    "TRILANE reached S5 after a weak S4. S4 must emit per-claim PROBE%, CONTROL%, VERIFY%, REJECTED%, or S4_SKIP% evidence; a blanket 'skipped heavy fuzz' marker is not a valid S4.".to_string(),
                );
            }
            let metrics = self.surface_gate_metrics();
            if saw_s2_or_s3 && metrics.hypothesis_debt > 0 {
                return Some(format!(
                    "TRILANE S1/S2 breadth gate unmet: hypothesis_pool={count}/{floor}, surfaces={surface_covered}/{surfaces}, domains={domains_closed}/{domains}. Expand S1 surfaces and S2 candidate/claim families before S5 adjudication; do not publish from a thin hypothesis pool.",
                    count = metrics.hypothesis_count,
                    floor = metrics.hypothesis_floor,
                    surface_covered = metrics.surface_covered,
                    surfaces = metrics.surfaces,
                    domains_closed = metrics.domain_queues_closed,
                    domains = metrics.domain_queues,
                ));
            }
            return None;
        }
        if saw_s2_or_s3 {
            return Some(
                "TRILANE produced provisional S2/S3 findings but never emitted RUNBOOK% S5 Verify. S2/S3 output remains claim material until S5 emits ADJUDICATE% decisions and canonical FINDING% markers with verification status.".to_string(),
            );
        }
        None
    }

    fn has_stage4_validation_signal(&self) -> bool {
        self.evidence.iter().any(|evidence| {
            evidence.stage == "stage4"
                && matches!(
                    evidence.kind.as_str(),
                    "probe" | "control" | "verify" | "disposition" | "s4_skip"
                )
        })
    }

    fn saw_runbook_stage_marker(&self, stage_code: &str) -> bool {
        let needle = format!("runbook% {}", stage_code.to_ascii_lowercase());
        self.evidence.iter().any(|evidence| {
            let haystack = format!(
                "{}\n{}",
                evidence.title.to_ascii_lowercase(),
                evidence.detail.to_ascii_lowercase()
            );
            haystack.contains(&needle)
        })
    }

    fn surface_gate_metrics(&self) -> SurfaceGateMetrics {
        let coverage_mapped = self
            .coverage
            .iter()
            .filter(|item| item.status != CoverageStatus::Pending)
            .count();
        let coverage_pending = self.coverage.len().saturating_sub(coverage_mapped);
        let surface_covered = self
            .surfaces
            .iter()
            .filter(|surface| self.surface_has_queue(surface))
            .count();
        let open_candidates = self
            .candidates
            .iter()
            .filter(|candidate| candidate.status == CandidateStatus::Candidate)
            .count();
        let open_claims = self
            .claims
            .iter()
            .filter(|claim| {
                matches!(
                    claim.status,
                    ClaimStatus::Seed | ClaimStatus::Armed | ClaimStatus::Running
                )
            })
            .count();
        let domain_queues = self.active_domain_queues();
        let domain_queues_closed = domain_queues
            .iter()
            .filter(|domain| self.domain_queue_closed(domain))
            .count();
        let hypothesis_count = self.hypothesis_count();
        let hypothesis_floor = hypothesis_floor(self.surfaces.len(), domain_queues.len());
        let hypothesis_debt = hypothesis_floor.saturating_sub(hypothesis_count);
        let uncovered_surfaces = self.surfaces.len().saturating_sub(surface_covered);
        let open_domains = domain_queues.len().saturating_sub(domain_queues_closed);
        SurfaceGateMetrics {
            coverage_mapped,
            surfaces: self.surfaces.len(),
            surface_covered,
            domain_queues: domain_queues.len(),
            domain_queues_closed,
            hypothesis_count,
            hypothesis_floor,
            hypothesis_debt,
            open_candidates,
            open_claims,
            debt: coverage_pending
                .saturating_add(uncovered_surfaces)
                .saturating_add(open_domains)
                .saturating_add(hypothesis_debt)
                .saturating_add(open_candidates)
                .saturating_add(open_claims),
        }
    }

    fn hypothesis_count(&self) -> usize {
        let mut ids = BTreeSet::new();
        for candidate in &self.candidates {
            ids.insert(format!("candidate:{}", normalize_id(&candidate.id)));
        }
        for claim in &self.claims {
            if !matches!(claim.status, ClaimStatus::Merged) {
                ids.insert(format!("claim:{}", normalize_id(&claim.id)));
            }
        }
        for finding in &self.findings {
            let id = finding.candidate_id.as_deref().unwrap_or(&finding.id);
            ids.insert(format!("finding:{}", normalize_id(id)));
        }
        ids.len()
    }

    fn surface_has_queue(&self, surface: &RunbookSurface) -> bool {
        self.candidates.iter().any(|candidate| {
            same_domain(&candidate.category, &surface.category)
                && text_matches_surface(
                    &[candidate.title.as_str(), candidate.target.as_str()],
                    surface,
                )
        }) || self.claims.iter().any(|claim| {
            same_domain(&claim.category, &surface.category)
                && text_matches_surface(
                    &[
                        claim.title.as_str(),
                        claim.target.as_str(),
                        claim.code_path.as_str(),
                        claim.root_cause.as_str(),
                        claim.positive_evidence.as_str(),
                    ],
                    surface,
                )
        }) || self.findings.iter().any(|finding| {
            same_domain(
                &infer_category(&format!("{}\n{}", finding.title, finding.code_path)),
                &surface.category,
            ) && text_matches_surface(
                &[
                    finding.title.as_str(),
                    finding.code_path.as_str(),
                    finding.detail.as_str(),
                ],
                surface,
            )
        })
    }

    fn active_domain_queues(&self) -> BTreeSet<String> {
        let mut domains = BTreeSet::new();
        for surface in &self.surfaces {
            domains.insert(surface.category.clone());
        }
        for candidate in &self.candidates {
            domains.insert(candidate.category.clone());
        }
        for claim in &self.claims {
            domains.insert(claim.category.clone());
        }
        for item in &self.coverage {
            if item.status != CoverageStatus::Pending && item.total_hint != Some(0) {
                domains.insert(item.category.clone());
            }
        }
        domains
    }

    fn domain_queue_closed(&self, domain: &str) -> bool {
        let has_queue = self
            .candidates
            .iter()
            .any(|candidate| same_domain(&candidate.category, domain))
            || self
                .claims
                .iter()
                .any(|claim| same_domain(&claim.category, domain));
        if !has_queue {
            return false;
        }
        let has_open_candidate = self.candidates.iter().any(|candidate| {
            same_domain(&candidate.category, domain)
                && candidate.status == CandidateStatus::Candidate
        });
        let has_open_claim = self.claims.iter().any(|claim| {
            same_domain(&claim.category, domain)
                && matches!(
                    claim.status,
                    ClaimStatus::Seed | ClaimStatus::Armed | ClaimStatus::Running
                )
        });
        !has_open_candidate && !has_open_claim
    }

    fn finalize_stage5(&mut self) {
        self.activate_stage("stage5", "Final dedupe / verification ledger");
        let stage5_findings = self
            .findings
            .iter()
            .filter(|finding| finding.stage == "stage5")
            .cloned()
            .collect::<Vec<_>>();
        let raw = if stage5_findings.is_empty() {
            self.findings.len()
        } else {
            stage5_findings.len()
        };
        self.adjudicate_claims();
        let (final_findings, summary) = if stage5_findings.is_empty() {
            crate::runbook_finalize::adjudicate_findings(&self.findings, &self.claims)
        } else if self.has_s5_final_revision_marker() {
            crate::runbook_finalize::finalize_explicit_findings(&stage5_findings)
        } else {
            crate::runbook_finalize::adjudicate_findings(&stage5_findings, &[])
        };
        self.final_findings = final_findings;
        self.dedupe_summary = summary;
        self.record_evidence(
            "stage5",
            "validator",
            "Final claim adjudication",
            format!(
                "S5 adjudicated {claims} root claims and collapsed {raw} raw findings into {final_count} final findings; duplicates={duplicates}, needs_poc={needs_poc}.",
                claims = self.claim_summary.root_claims,
                final_count = self.final_findings.len(),
                duplicates = self.dedupe_summary.duplicates,
                needs_poc = self.dedupe_summary.needs_poc,
            ),
        );
    }

    fn adjudicate_claims(&mut self) {
        let fingerprints = self
            .claims
            .iter()
            .map(|claim| claim.fingerprint.clone())
            .collect::<Vec<_>>();
        for idx in 0..self.claims.len() {
            if matches!(
                self.claims[idx].status,
                ClaimStatus::Discarded | ClaimStatus::Merged | ClaimStatus::Blocked
            ) {
                continue;
            }
            let duplicate_of =
                fingerprints
                    .iter()
                    .enumerate()
                    .find_map(|(other_idx, fingerprint)| {
                        (other_idx < idx && *fingerprint == self.claims[idx].fingerprint)
                            .then(|| self.claims[other_idx].id.clone())
                    });
            if let Some(primary_id) = duplicate_of {
                self.claims[idx].status = ClaimStatus::Merged;
                self.claims[idx].merged_into = Some(primary_id);
                continue;
            }
            let has_source = !self.claims[idx].code_path.trim().is_empty()
                || !self.claims[idx].root_cause.trim().is_empty();
            let has_payload = !self.claims[idx].payload.trim().is_empty();
            let has_negative = !self.claims[idx].negative_evidence.trim().is_empty();
            let level = infer_evidence_level(
                &self.claims[idx].code_path,
                &self.claims[idx].positive_evidence,
                &self.claims[idx].negative_evidence,
                &self.claims[idx].payload,
                "high",
            );
            self.claims[idx].evidence_level =
                self.claims[idx].evidence_level.clone().merge(level.clone());
            let promoted = if has_source && has_payload && has_negative {
                ClaimStatus::Publishable
            } else if has_source && has_payload {
                ClaimStatus::Weaponized
            } else {
                status_from_evidence(&self.claims[idx].evidence_level, has_negative)
            };
            self.claims[idx].status = self.claims[idx].status.clone().merge(promoted);
        }
        self.refresh_claim_summary();
    }

    fn has_s5_final_revision_marker(&self) -> bool {
        self.evidence.iter().any(|evidence| {
            evidence.stage == "stage5"
                && evidence.kind == "runbook"
                && evidence
                    .detail
                    .to_ascii_lowercase()
                    .contains("runbook% s5 final revision")
        })
    }

    fn mark_coverage_from_signal(&mut self, text: &str) {
        if let Some(category) = infer_coverage_category(text) {
            let label = coverage_signal_label(text);
            self.mark_coverage_signal(&category, &label);
        }
    }

    fn mark_coverage_signal(&mut self, category: &str, label: &str) {
        let category = self.canonical_coverage_category(category);
        let normalized = normalize_id(&category);
        if let Some(item) = self
            .coverage
            .iter_mut()
            .find(|item| normalize_id(&item.category) == normalized)
        {
            item.mapped_count = item.mapped_count.max(1);
            if item.status == CoverageStatus::Pending {
                item.status = CoverageStatus::Partial;
            }
            if item.label == item.category || item.label.trim().is_empty() {
                item.label = truncate(label, 90);
            }
            item.updated_at = now();
        }
    }

    fn touch(&mut self) {
        self.revision = self.revision.saturating_add(1);
        self.refresh_counts();
        self.last_updated = now();
    }

    fn refresh_claim_summary(&mut self) {
        let root_claims = self
            .claims
            .iter()
            .filter(|claim| !matches!(claim.status, ClaimStatus::Merged))
            .count();
        self.claim_summary = RunbookClaimSummary {
            surfaces: self.surfaces.len(),
            raw_signals: self.claims.iter().map(|claim| claim.signal_count).sum(),
            root_claims,
            publishable: self
                .claims
                .iter()
                .filter(|claim| claim.status == ClaimStatus::Publishable)
                .count(),
            verified: self
                .claims
                .iter()
                .filter(|claim| {
                    matches!(
                        claim.status,
                        ClaimStatus::Verified | ClaimStatus::Weaponized | ClaimStatus::Publishable
                    )
                })
                .count(),
            blocked: self
                .claims
                .iter()
                .filter(|claim| claim.status == ClaimStatus::Blocked)
                .count(),
            discarded: self
                .claims
                .iter()
                .filter(|claim| claim.status == ClaimStatus::Discarded)
                .count(),
            merged: self
                .claims
                .iter()
                .filter(|claim| claim.status == ClaimStatus::Merged)
                .count(),
            coverage_debt: self
                .coverage
                .iter()
                .filter(|item| item.status == CoverageStatus::Pending)
                .count(),
            evidence_ladder_complete: self
                .claims
                .iter()
                .filter(|claim| claim.evidence_level == EvidenceLevel::ControlPassed)
                .count(),
        };
    }

    fn refresh_counts(&mut self) {
        self.refresh_claim_summary();
        let surface_metrics = self.surface_gate_metrics();
        for stage in &mut self.stages {
            stage.evidence_count = self
                .evidence
                .iter()
                .filter(|evidence| evidence.stage == stage.id)
                .count();
            stage.candidate_count = self
                .candidates
                .iter()
                .filter(|candidate| candidate.stage == stage.id)
                .count();
            stage.findings_count = self
                .findings
                .iter()
                .filter(|finding| finding.stage == stage.id)
                .count();
        }
        self.stats = RunbookStats {
            coverage_mapped: surface_metrics.coverage_mapped,
            coverage_total: self.coverage.len(),
            coverage_debt: surface_metrics.debt,
            surfaces: surface_metrics.surfaces,
            surface_covered: surface_metrics.surface_covered,
            domain_queues: surface_metrics.domain_queues,
            domain_queues_closed: surface_metrics.domain_queues_closed,
            hypothesis_count: surface_metrics.hypothesis_count,
            hypothesis_floor: surface_metrics.hypothesis_floor,
            hypothesis_debt: surface_metrics.hypothesis_debt,
            candidates: self.candidates.len(),
            root_claims: self.claim_summary.root_claims,
            probed: self
                .candidates
                .iter()
                .filter(|candidate| {
                    matches!(
                        candidate.status,
                        CandidateStatus::Probed
                            | CandidateStatus::NeedsVerify
                            | CandidateStatus::Rejected
                            | CandidateStatus::Duplicate
                            | CandidateStatus::OutOfScope
                            | CandidateStatus::Confirmed
                    )
                })
                .count(),
            rejected: self
                .candidates
                .iter()
                .filter(|candidate| {
                    matches!(
                        candidate.status,
                        CandidateStatus::Rejected
                            | CandidateStatus::Duplicate
                            | CandidateStatus::OutOfScope
                    )
                })
                .count(),
            merged_claims: self.claim_summary.merged,
            blocked_claims: self.claim_summary.blocked,
            discarded_claims: self.claim_summary.discarded,
            needs_verify: self
                .candidates
                .iter()
                .filter(|candidate| candidate.status == CandidateStatus::NeedsVerify)
                .count(),
            confirmed: if !self.final_findings.is_empty() {
                self.final_findings.len()
            } else if self.status == RunbookStatus::Error {
                0
            } else if self.claim_summary.publishable > 0 {
                self.claim_summary.publishable
            } else {
                self.findings.len()
            },
            publishable_claims: self.claim_summary.publishable,
            source_confirmed: self
                .final_findings
                .iter()
                .filter(|finding| !finding.code_path.trim().is_empty())
                .count(),
            evidence_signals: self.evidence_total,
        };
        if self.final_findings.is_empty() && self.status != RunbookStatus::Error {
            self.stats.source_confirmed = self
                .findings
                .iter()
                .filter(|finding| !finding.code_path.trim().is_empty())
                .count();
        }
    }
}
