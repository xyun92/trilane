fn collapse_final_findings(findings: Vec<RunbookFinalFinding>) -> Vec<RunbookFinalFinding> {
    let mut groups: BTreeMap<String, Vec<RunbookFinalFinding>> = BTreeMap::new();
    for finding in findings {
        groups
            .entry(canonical_final_key(&finding))
            .or_default()
            .push(finding);
    }

    groups
        .into_iter()
        .map(|(canonical_key, mut group)| {
            group.sort_by_key(final_finding_rank);
            group.reverse();
            let mut primary = group
                .first()
                .cloned()
                .expect("final dedupe group always has at least one finding");
            for duplicate in group.iter().skip(1) {
                if primary.code_path.trim().is_empty() && !duplicate.code_path.trim().is_empty() {
                    primary.code_path = duplicate.code_path.clone();
                }
                if (primary.location.trim().is_empty() || primary.location == "-")
                    && !duplicate.location.trim().is_empty()
                {
                    primary.location = duplicate.location.clone();
                }
                if primary.payload.trim().is_empty() && !duplicate.payload.trim().is_empty() {
                    primary.payload = duplicate.payload.clone();
                }
                if primary.detail.trim().is_empty() && !duplicate.detail.trim().is_empty() {
                    primary.detail = duplicate.detail.clone();
                } else if !duplicate.detail.trim().is_empty()
                    && !primary.detail.contains(duplicate.detail.trim())
                {
                    primary.detail = format!(
                        "{}\n\nDuplicate evidence: {}",
                        primary.detail.trim(),
                        duplicate.detail.trim()
                    );
                }
                primary.duplicates.extend(duplicate.duplicates.clone());
                primary.duplicates.push(duplicate.original_id.clone());
            }
            primary.duplicates.sort();
            primary.duplicates.dedup();
            primary.canonical_key = canonical_key;
            primary
        })
        .collect()
}

fn should_keep_final_finding(finding: &RunbookFinalFinding) -> bool {
    if matches!(
        finding.verification_status.as_str(),
        "blocked" | "discarded" | "merged"
    ) {
        return false;
    }
    if is_summary_echo(finding) {
        return false;
    }
    if is_candidate_only_without_anchor(finding) {
        return false;
    }
    if has_blocked_or_mitigated_semantics(finding) {
        return false;
    }
    if has_polluted_payload_without_exploit(finding) {
        return false;
    }
    if has_unauthenticated_middleware_gap(
        &finding.title,
        &finding.code_path,
        &finding.location,
        &finding.detail,
    ) {
        return false;
    }
    true
}

fn should_keep_explicit_final_finding(finding: &RunbookFinalFinding) -> bool {
    if matches!(
        finding.verification_status.as_str(),
        "blocked" | "discarded" | "merged"
    ) {
        return false;
    }
    if is_summary_echo(finding) || looks_like_placeholder_title(&finding.title) {
        return false;
    }
    !is_candidate_only_without_anchor(finding)
}

fn normalize_final_finding_quality(finding: &mut RunbookFinalFinding) {
    normalize_overclaimed_info_disclosure(finding);
    let has_anchor = !finding.code_path.trim().is_empty()
        || (!finding.location.trim().is_empty() && finding.location != "-");
    let has_payload = !finding.payload.trim().is_empty();
    let has_runtime = has_runtime_or_repro(&format!("{}\n{}", finding.detail, finding.payload));
    if matches!(
        finding.verification_status.as_str(),
        "publishable" | "weaponized"
    ) && !(has_anchor && has_payload && has_runtime)
    {
        finding.verification_status = if has_anchor {
            "verified".to_string()
        } else {
            "needs-poc".to_string()
        };
        finding.evidence_state = finding.verification_status.clone();
    }
}

fn is_candidate_only_without_anchor(finding: &RunbookFinalFinding) -> bool {
    finding.candidate_id.is_some()
        && finding.code_path.trim().is_empty()
        && (finding.location.trim().is_empty() || finding.location.starts_with("CAND-"))
}

fn has_blocked_or_mitigated_semantics(finding: &RunbookFinalFinding) -> bool {
    if matches!(
        finding.verification_status.as_str(),
        "blocked" | "discarded" | "merged"
    ) {
        return true;
    }
    let text = format!(
        "{}\n{}\n{}\n{}",
        finding.title, finding.detail, finding.payload, finding.confidence
    )
    .to_ascii_lowercase();
    contains_any(
        &text,
        &[
            "not exploitable",
            "cannot reproduce",
            "did not reproduce",
            "exploit failed",
            "false positive",
            "blocked by",
            "parser limitation mitigates",
            "mitigates full",
            "limited xxe",
            "limited impact",
        ],
    )
}

fn has_polluted_payload_without_exploit(finding: &RunbookFinalFinding) -> bool {
    let text = format!(
        "{}\n{}\n{}",
        finding.title.trim(),
        finding.payload.trim(),
        finding.detail.trim()
    );
    if text.trim().is_empty() {
        return false;
    }
    let lower = text.to_ascii_lowercase();
    if contains_any(
        &lower,
        &[
            "stored xss payload accepted",
            "api allows storing xss payloads",
        ],
    ) && finding.code_path.trim().is_empty()
    {
        return true;
    }
    let source_lines = text
        .lines()
        .filter(|line| {
            let line = line.trim_start();
            line.starts_with("import ")
                || line.starts_with("const ")
                || line.starts_with("let ")
                || line.starts_with("export ")
        })
        .count();
    source_lines >= 2
        && !contains_any(
            &lower,
            &[
                "curl ", "http://", "https://", "get /", "post /", "put /", "delete /", "payload:",
            ],
        )
}

fn normalize_overclaimed_info_disclosure(finding: &mut RunbookFinalFinding) {
    let text = format!(
        "{}\n{}\n{}",
        finding.title, finding.detail, finding.code_path
    )
    .to_ascii_lowercase();
    if contains_any(&text, &["admin endpoint", "admin endpoints", "/rest/admin"])
        && contains_any(
            &text,
            &[
                "configuration",
                "application-version",
                "application-configuration",
            ],
        )
        && contains_any(&text, &["exposes", "leaking", "returns"])
    {
        finding.title = "Public admin metadata/configuration disclosure".to_string();
        finding.severity = "low".to_string();
        if matches!(
            finding.verification_status.as_str(),
            "publishable" | "weaponized"
        ) {
            finding.verification_status = "verified".to_string();
            finding.evidence_state = "verified".to_string();
        }
    }
}

fn is_summary_echo(finding: &RunbookFinalFinding) -> bool {
    finding.code_path.trim().is_empty()
        && finding.candidate_id.is_none()
        && finding.payload.trim().is_empty()
        && (finding.location == "stage5"
            || finding.detail.trim_start().starts_with("## FINDING")
            || finding.detail.trim_start().starts_with("### FINDING"))
}

fn matching_claim<'a>(
    finding: &RunbookFinalFinding,
    claims: &'a [RunbookClaim],
) -> Option<&'a RunbookClaim> {
    if let Some(candidate_id) = finding.candidate_id.as_deref() {
        if let Some(claim) = claims.iter().find(|claim| claim.id == candidate_id) {
            return Some(claim);
        }
    }
    claims.iter().find(|claim| {
        claim.fingerprint == finding.canonical_key
            || (!claim.code_path.trim().is_empty() && claim.code_path == finding.code_path)
    })
}

fn claim_location(claim: &RunbookClaim) -> String {
    if !claim.code_path.trim().is_empty() {
        claim.code_path.clone()
    } else if !claim.target.trim().is_empty() {
        claim.target.clone()
    } else {
        claim.category.clone()
    }
}

fn claim_detail(claim: &RunbookClaim) -> String {
    let mut lines = Vec::new();
    if !claim.root_cause.trim().is_empty() {
        lines.push(format!("Root cause: {}", claim.root_cause));
    }
    if !claim.precondition.trim().is_empty() {
        lines.push(format!("Precondition: {}", claim.precondition));
    }
    if !claim.impact.trim().is_empty() {
        lines.push(format!("Impact: {}", claim.impact));
    }
    if !claim.positive_evidence.trim().is_empty() {
        lines.push(format!("Evidence: {}", claim.positive_evidence));
    }
    if !claim.negative_evidence.trim().is_empty() {
        lines.push(format!("Control: {}", claim.negative_evidence));
    }
    lines.join("\n")
}

fn confidence_from_claim(claim: &RunbookClaim) -> &'static str {
    match &claim.status {
        ClaimStatus::Publishable | ClaimStatus::Weaponized => "high",
        ClaimStatus::Verified | ClaimStatus::Corroborated => "medium",
        _ => "low",
    }
}

fn verification_status_from_claim(claim: &RunbookClaim) -> &'static str {
    if has_blocking_control(claim) {
        return "blocked";
    }
    if has_unauthenticated_middleware_gap(
        &claim.title,
        &claim.code_path,
        &claim.root_cause,
        &claim.positive_evidence,
    ) {
        return "needs-poc";
    }
    let has_source = !claim.code_path.trim().is_empty() || !claim.root_cause.trim().is_empty();
    let has_payload = !claim.payload.trim().is_empty();
    let has_positive =
        !claim.positive_evidence.trim().is_empty() || !claim.impact.trim().is_empty();
    let has_control = !claim.negative_evidence.trim().is_empty();
    let has_runtime = has_runtime_or_repro(&format!(
        "{}\n{}\n{}",
        claim.positive_evidence, claim.negative_evidence, claim.payload
    ));
    match &claim.status {
        ClaimStatus::Publishable
            if has_source && has_payload && has_positive && has_control && has_runtime =>
        {
            "publishable"
        }
        ClaimStatus::Publishable | ClaimStatus::Weaponized
            if has_source && has_payload && has_runtime =>
        {
            "weaponized"
        }
        ClaimStatus::Publishable | ClaimStatus::Weaponized | ClaimStatus::Verified
            if has_source && has_positive =>
        {
            "verified"
        }
        ClaimStatus::Publishable | ClaimStatus::Weaponized | ClaimStatus::Verified => "needs-poc",
        ClaimStatus::Blocked => "blocked",
        ClaimStatus::Corroborated => "runtime-signal",
        ClaimStatus::Anchored => "source-backed",
        ClaimStatus::Armed | ClaimStatus::Running => "needs-poc",
        ClaimStatus::Seed => "signal",
        ClaimStatus::Discarded => "discarded",
        ClaimStatus::Merged => "merged",
    }
}
