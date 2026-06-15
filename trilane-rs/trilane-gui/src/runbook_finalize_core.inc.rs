
pub(crate) fn adjudicate_findings(
    findings: &[RunbookFinding],
    claims: &[RunbookClaim],
) -> (Vec<RunbookFinalFinding>, RunbookDedupeSummary) {
    let (mut final_findings, mut summary) = dedupe_findings(findings);
    for finding in &mut final_findings {
        if let Some(claim) = matching_claim(finding, claims) {
            let claim_status = verification_status_from_claim(claim);
            if verification_rank(claim_status) >= verification_rank(&finding.verification_status) {
                finding.verification_status = claim_status.to_string();
            }
            finding.evidence_state = evidence_state_from_claim(claim).to_string();
            if finding.code_path.trim().is_empty() {
                finding.code_path = claim.code_path.clone();
            }
            if finding.location.trim().is_empty() || finding.location == "-" {
                finding.location = claim_location(claim);
            }
            if finding.payload.trim().is_empty() {
                finding.payload = claim.payload.clone();
            }
            if !claim.root_cause.trim().is_empty() && !finding.detail.contains(&claim.root_cause) {
                finding.detail = format!(
                    "{}\nRoot cause: {}",
                    finding.detail.trim(),
                    claim.root_cause
                );
            }
        }
    }

    let mut existing_claim_ids = final_findings
        .iter()
        .filter_map(|finding| finding.candidate_id.clone())
        .collect::<Vec<_>>();
    let raw_claim_ids = findings
        .iter()
        .filter_map(|finding| finding.candidate_id.clone())
        .collect::<Vec<_>>();
    let mut materialized_claims = 0;
    let mut skipped_claim_duplicates = 0;
    for claim in claims
        .iter()
        .filter(|claim| should_materialize_claim(claim))
    {
        if existing_claim_ids.iter().any(|id| id == &claim.id) {
            continue;
        }
        if let Some(existing) = final_findings.iter_mut().find(|finding| {
            canonical_final_key(finding) == canonical_claim_key(claim)
                || (!claim.code_path.trim().is_empty()
                    && finding.code_path == claim.code_path
                    && same_category(&finding.canonical_key, &claim.category))
        }) {
            existing.duplicates.push(claim.id.clone());
            existing_claim_ids.push(claim.id.clone());
            if !raw_claim_ids.iter().any(|id| id == &claim.id) {
                skipped_claim_duplicates += 1;
            }
            continue;
        }
        existing_claim_ids.push(claim.id.clone());
        materialized_claims += 1;
        final_findings.push(RunbookFinalFinding {
            id: String::new(),
            original_id: claim.id.clone(),
            candidate_id: Some(claim.id.clone()),
            severity: claim
                .severity
                .clone()
                .unwrap_or_else(|| severity_from_claim(claim).to_string()),
            title: claim.title.clone(),
            code_path: claim.code_path.clone(),
            location: claim_location(claim),
            confidence: confidence_from_claim(claim).to_string(),
            evidence_state: evidence_state_from_claim(claim).to_string(),
            verification_status: verification_status_from_claim(claim).to_string(),
            detail: claim_detail(claim),
            payload: claim.payload.clone(),
            duplicates: Vec::new(),
            canonical_key: claim.fingerprint.clone(),
            timestamp: claim.updated_at.clone(),
        });
    }
    final_findings = collapse_final_findings(final_findings);
    final_findings.retain(should_keep_final_finding);
    for finding in &mut final_findings {
        normalize_final_finding_quality(finding);
    }
    final_findings.sort_by_key(final_finding_rank);
    final_findings.reverse();
    for (idx, finding) in final_findings.iter_mut().enumerate() {
        finding.id = format!("VULN-{:03}", idx + 1);
    }
    summary.final_findings = final_findings.len();
    summary.duplicates = findings
        .len()
        .saturating_add(materialized_claims)
        .saturating_add(skipped_claim_duplicates)
        .saturating_sub(final_findings.len());
    summary.verified = final_findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.verification_status.as_str(),
                "publishable" | "weaponized" | "verified"
            )
        })
        .count();
    summary.source_backed = final_findings
        .iter()
        .filter(|finding| !finding.code_path.trim().is_empty())
        .count();
    summary.needs_poc = final_findings
        .iter()
        .filter(|finding| {
            finding.payload.trim().is_empty()
                || matches!(
                    finding.verification_status.as_str(),
                    "source-backed" | "runtime-signal" | "needs-poc"
                )
        })
        .count();
    (final_findings, summary)
}

pub(crate) fn finalize_explicit_findings(
    findings: &[RunbookFinding],
) -> (Vec<RunbookFinalFinding>, RunbookDedupeSummary) {
    let mut seen = BTreeSet::new();
    let mut final_findings = Vec::new();
    let mut duplicates = 0usize;
    let mut dropped = 0usize;
    for finding in findings {
        let original_id = finding
            .candidate_id
            .clone()
            .filter(|id| !id.trim().is_empty())
            .unwrap_or_else(|| finding.id.clone());
        if !seen.insert(original_id.clone()) {
            duplicates = duplicates.saturating_add(1);
            continue;
        }
        let mut final_finding = RunbookFinalFinding {
            id: String::new(),
            original_id,
            candidate_id: finding.candidate_id.clone(),
            severity: finding.severity.clone(),
            title: finding.title.clone(),
            code_path: finding.code_path.clone(),
            location: finding_location(finding),
            confidence: finding.confidence.clone(),
            evidence_state: finding.evidence_state.clone(),
            verification_status: verification_status(finding).to_string(),
            detail: finding.detail.clone(),
            payload: finding.payload.clone(),
            duplicates: Vec::new(),
            canonical_key: finding
                .candidate_id
                .clone()
                .unwrap_or_else(|| canonical_finding_key(finding)),
            timestamp: finding.timestamp.clone(),
        };
        normalize_final_finding_quality(&mut final_finding);
        if should_keep_explicit_final_finding(&final_finding) {
            final_findings.push(final_finding);
        } else {
            dropped = dropped.saturating_add(1);
        }
    }
    final_findings.sort_by_key(final_finding_rank);
    final_findings.reverse();
    for (idx, finding) in final_findings.iter_mut().enumerate() {
        finding.id = format!("VULN-{:03}", idx + 1);
    }
    let summary = RunbookDedupeSummary {
        raw_findings: findings.len(),
        final_findings: final_findings.len(),
        duplicates: duplicates.max(findings.len().saturating_sub(final_findings.len() + dropped)),
        verified: final_findings
            .iter()
            .filter(|finding| {
                matches!(
                    finding.verification_status.as_str(),
                    "publishable" | "weaponized" | "verified"
                )
            })
            .count(),
        source_backed: final_findings
            .iter()
            .filter(|finding| !finding.code_path.trim().is_empty())
            .count(),
        needs_poc: final_findings
            .iter()
            .filter(|finding| {
                finding.payload.trim().is_empty()
                    || matches!(
                        finding.verification_status.as_str(),
                        "source-backed" | "runtime-signal" | "needs-poc"
                    )
            })
            .count(),
    };
    (final_findings, summary)
}

fn should_materialize_claim(claim: &RunbookClaim) -> bool {
    if matches!(
        claim.status,
        ClaimStatus::Seed | ClaimStatus::Blocked | ClaimStatus::Discarded | ClaimStatus::Merged
    ) {
        return false;
    }
    if has_blocking_control(claim) || looks_like_placeholder_title(&claim.title) {
        return false;
    }
    let has_anchor = !claim.code_path.trim().is_empty() || !claim.root_cause.trim().is_empty();
    let has_substance = !claim.positive_evidence.trim().is_empty()
        || !claim.impact.trim().is_empty()
        || !claim.payload.trim().is_empty();
    if !has_anchor || !has_substance {
        return false;
    }
    if matches!(
        claim.status,
        ClaimStatus::Publishable | ClaimStatus::Weaponized | ClaimStatus::Verified
    ) {
        return true;
    }
    matches!(
        claim.status,
        ClaimStatus::Anchored | ClaimStatus::Corroborated
    )
}

fn has_blocking_control(claim: &RunbookClaim) -> bool {
    let evidence = claim.negative_evidence.to_ascii_lowercase();
    contains_any(
        &evidence,
        &[
            "attack blocked",
            "blocked by",
            "cannot reproduce",
            "did not reproduce",
            "exploit failed",
            "false positive",
            "not exploitable",
            "overwrites userid",
            "prevent escape",
            "prevents cross-user",
            "prevents escape",
            "same-origin requests work identically",
        ],
    )
}

fn looks_like_placeholder_title(title: &str) -> bool {
    let normalized = title.trim().to_ascii_lowercase();
    normalized.is_empty()
        || normalized == "undefined"
        || normalized.ends_with("-cand-01")
        || normalized.ends_with("-cand-02")
        || normalized.ends_with("-cand-03")
        || normalized.ends_with("-cand-04")
        || normalized.ends_with("-cand-05")
        || normalized.starts_with("clm-")
}

pub(crate) fn dedupe_findings(
    findings: &[RunbookFinding],
) -> (Vec<RunbookFinalFinding>, RunbookDedupeSummary) {
    let mut groups: BTreeMap<String, Vec<RunbookFinding>> = BTreeMap::new();
    for finding in findings {
        groups
            .entry(canonical_finding_key(finding))
            .or_default()
            .push(finding.clone());
    }

    let mut final_findings: Vec<RunbookFinalFinding> = groups
        .into_iter()
        .map(|(canonical_key, mut group)| {
            group.sort_by_key(finding_rank);
            group.reverse();
            let primary = group
                .first()
                .cloned()
                .expect("dedupe group always has at least one finding");
            let duplicates = group
                .iter()
                .skip(1)
                .map(|finding| finding.id.clone())
                .collect::<Vec<_>>();
            RunbookFinalFinding {
                id: String::new(),
                original_id: primary.id.clone(),
                candidate_id: primary.candidate_id.clone(),
                severity: primary.severity.clone(),
                title: primary.title.clone(),
                code_path: primary.code_path.clone(),
                location: finding_location(&primary),
                confidence: primary.confidence.clone(),
                evidence_state: primary.evidence_state.clone(),
                verification_status: verification_status(&primary).to_string(),
                detail: primary.detail.clone(),
                payload: primary.payload.clone(),
                duplicates,
                canonical_key,
                timestamp: primary.timestamp.clone(),
            }
        })
        .collect();

    final_findings.sort_by_key(final_finding_rank);
    final_findings.reverse();
    for (idx, finding) in final_findings.iter_mut().enumerate() {
        finding.id = format!("VULN-{:03}", idx + 1);
    }

    let summary = RunbookDedupeSummary {
        raw_findings: findings.len(),
        final_findings: final_findings.len(),
        duplicates: findings.len().saturating_sub(final_findings.len()),
        verified: final_findings
            .iter()
            .filter(|finding| finding.verification_status == "verified")
            .count(),
        source_backed: final_findings
            .iter()
            .filter(|finding| finding.verification_status == "source-backed")
            .count(),
        needs_poc: final_findings
            .iter()
            .filter(|finding| finding.verification_status == "needs-poc")
            .count(),
    };

    (final_findings, summary)
}
