pub fn scan_progress_from_runbook(state: &RunbookState) -> Option<crate::ScanProgress> {
    if state.status == RunbookStatus::Idle {
        return None;
    }
    let idx = stage_index(&state.current_stage).unwrap_or(0);
    let stage = state.stages.get(idx)?;
    let progress = if state.status == RunbookStatus::Completed {
        1.0
    } else {
        0.35 + ((stage.evidence_count.min(6) as f32) * 0.1)
    }
    .min(0.95);

    Some(crate::ScanProgress {
        stage: stage.id.clone(),
        stage_name: format!("{} {}", stage.code, stage.name),
        progress,
        message: stage.summary.clone(),
        findings_count: state.stats.confirmed,
    })
}

fn default_stages() -> Vec<RunbookStage> {
    [
        ("stage0", "S0", "Gate", ""),
        ("stage1", "S1", "Recon", ""),
        ("stage2", "S2", "Audit", ""),
        ("stage3", "S3", "FoA", ""),
        ("stage4", "S4", "Fuzz", ""),
        ("stage5", "S5", "Verify", ""),
    ]
    .into_iter()
    .map(|(id, code, name, label)| RunbookStage {
        id: id.to_string(),
        code: code.to_string(),
        name: name.to_string(),
        label: label.to_string(),
        status: StageStatus::Pending,
        summary: "waiting for agent signal".to_string(),
        evidence_count: 0,
        candidate_count: 0,
        findings_count: 0,
        updated_at: now(),
    })
    .collect()
}

fn default_coverage(_audit_mode: &AuditMode) -> Vec<RunbookCoverage> {
    let categories: &[(&str, &str)] = &[
        ("auth", "Authentication bypass"),
        ("authz", "Authorization and IDOR"),
        ("session", "Session/token lifecycle"),
        ("injection", "SQL/NoSQL/template/command injection"),
        ("xss", "Reflected/stored/DOM XSS"),
        ("cors_headers_tls", "CORS, browser trust, and header posture"),
        ("ssrf_redirect", "SSRF and open redirect"),
        ("file_upload_xxe", "Upload parsers and XXE"),
        ("traversal_lfi", "Path traversal and local file read"),
        (
            "state_invariant_abuse",
            "State-machine and invariant abuse",
        ),
        (
            "anti_automation_bypass",
            "Anti-automation and recovery-control bypass",
        ),
        ("rate_limit", "Rate limiting and brute force"),
        ("secrets_config", "Secrets, keys, and config exposure"),
        (
            "observability_leak",
            "Metrics, logs, docs, and diagnostics exposure",
        ),
        ("crypto", "Crypto and password storage"),
    ];

    categories
        .iter()
        .copied()
        .map(|(id, label)| RunbookCoverage {
            id: format!("coverage-{id}"),
            category: id.to_string(),
            label: label.to_string(),
            mapped_count: 0,
            total_hint: None,
            status: CoverageStatus::Pending,
            updated_at: now(),
        })
        .collect()
}

fn classify_stage(text: &str, output: Option<&str>) -> &'static str {
    let haystack = format!(
        "{}\n{}",
        text.to_ascii_lowercase(),
        output.unwrap_or_default().to_ascii_lowercase()
    );
    if contains_any(
        &haystack,
        &[
            "runbook% s5",
            "triad",
            "validator",
            "clean sandbox",
            "validate",
        ],
    ) {
        "stage5"
    } else if contains_any(
        &haystack,
        &[
            "runbook% s4",
            "fuzz",
            "hypothesis",
            "afl",
            "jazzer",
            "mutation",
        ],
    ) {
        "stage4"
    } else if contains_any(
        &haystack,
        &[
            "runbook% s3",
            "report",
            "summary",
            "finding:",
            "findings",
            "foa",
            "snapshot",
        ],
    ) {
        "stage3"
    } else if contains_any(
        &haystack,
        &[
            "runbook% s2",
            "curl ",
            "union select",
            "or 1=1",
            "xss",
            "ssrf",
            "xxe",
            "jwt",
            "admin",
            "password",
            "vulnerab",
            "exploit",
            "poc",
            "injection",
            "cwe",
        ],
    ) {
        "stage2"
    } else if contains_any(
        &haystack,
        &[
            "runbook% s1",
            "route",
            "routes/",
            "source",
            "sink",
            "grep",
            " rg ",
            "semgrep",
            "server.ts",
            "package.json",
            "battlefield",
            "recon",
        ],
    ) {
        "stage1"
    } else {
        "stage0"
    }
}

fn runbook_marker_stage(line: &str) -> Option<&'static str> {
    let lower = line.to_ascii_lowercase();
    if lower.contains("runbook% s5") {
        Some("stage5")
    } else if lower.contains("runbook% s4") {
        Some("stage4")
    } else if lower.contains("runbook% s3") {
        Some("stage3")
    } else if lower.contains("runbook% s2") {
        Some("stage2")
    } else if lower.contains("runbook% s1") {
        Some("stage1")
    } else if lower.contains("runbook% s0") {
        Some("stage0")
    } else {
        None
    }
}

fn infer_finding_from_command(
    command: &str,
    output: &str,
) -> Option<(&'static str, &'static str, String)> {
    let haystack = format!(
        "{}\n{}",
        command.to_ascii_lowercase(),
        output.to_ascii_lowercase()
    );
    if haystack.contains("union select") && haystack.contains("\"status\": \"success\"") {
        Some((
            "critical",
            "Union SQL injection",
            "UNION SELECT returned structured application data".to_string(),
        ))
    } else if haystack.contains("or 1=1") && haystack.contains("authentication") {
        Some((
            "critical",
            "SQL injection login bypass",
            "Login response returned authentication material for injected predicate".to_string(),
        ))
    } else if haystack.contains("api/users")
        && haystack.contains("\"role\"")
        && haystack.contains("admin")
        && haystack.contains("success")
    {
        Some((
            "critical",
            "Mass assignment admin registration",
            "User creation accepted role=admin".to_string(),
        ))
    } else if haystack.contains("change-password") && haystack.contains("200") {
        Some((
            "high",
            "Password change without current password",
            "Change-password endpoint returned HTTP 200".to_string(),
        ))
    } else if haystack.contains("createhash") && haystack.contains("md5") {
        Some((
            "high",
            "Weak MD5 password hashing",
            "Source uses crypto.createHash('md5')".to_string(),
        ))
    } else if haystack.contains("begin rsa private key") {
        Some((
            "critical",
            "Hardcoded JWT private key",
            "Source contains an embedded RSA private key".to_string(),
        ))
    } else if haystack.contains("<iframe") && haystack.contains("javascript:alert") {
        Some((
            "high",
            "Stored XSS payload accepted",
            "Product API accepted javascript iframe payload".to_string(),
        ))
    } else {
        None
    }
}

fn stage_index(stage: &str) -> Option<usize> {
    match stage {
        "stage0" => Some(0),
        "stage1" => Some(1),
        "stage2" => Some(2),
        "stage3" => Some(3),
        "stage4" => Some(4),
        "stage5" => Some(5),
        _ => None,
    }
}

fn command_title(command: &str) -> String {
    let first = first_line(command);
    if first.len() <= 90 {
        first
    } else {
        truncate(&first, 90)
    }
}

fn first_line(text: &str) -> String {
    text.lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("agent activity")
        .trim()
        .to_string()
}

fn contains_any(text: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| text.contains(needle))
}

fn same_domain(left: &str, right: &str) -> bool {
    normalize_id(left) == normalize_id(right)
}

fn hypothesis_floor(surfaces: usize, active_domains: usize) -> usize {
    if surfaces < 5 && active_domains < 5 {
        return 0;
    }
    let surface_floor = surfaces.saturating_mul(3).div_ceil(2);
    let domain_floor = if active_domains >= 10 {
        active_domains.saturating_mul(3)
    } else {
        active_domains.saturating_mul(2)
    };
    surface_floor.max(domain_floor).min(80)
}

fn text_matches_surface(values: &[&str], surface: &RunbookSurface) -> bool {
    let target = surface.target.trim().to_ascii_lowercase();
    let label = surface.label.trim().to_ascii_lowercase();
    if target.is_empty() && label.is_empty() {
        return true;
    }
    values.iter().any(|value| {
        let value = value.trim().to_ascii_lowercase();
        if value.is_empty() {
            return false;
        }
        (!target.is_empty() && (value.contains(&target) || target.contains(&value)))
            || (!label.is_empty() && (value.contains(&label) || label.contains(&value)))
    })
}

fn looks_like_report(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    contains_any(
        &lower,
        &[
            "finding:",
            "confirmed finding",
            "severity:",
            "confidence:",
            "findings",
            "critical",
            "按严重等级",
            "漏洞",
        ],
    )
}

fn looks_like_stage5_summary_echo(stage: &str, text: &str) -> bool {
    stage == "stage5"
        && text
            .lines()
            .next()
            .map(|line| {
                let lower = line.trim().to_ascii_lowercase();
                lower.starts_with("## finding ") || lower.starts_with("### finding ")
            })
            .unwrap_or(false)
}

fn strip_marker(line: &str) -> &str {
    line.split_once('%')
        .map(|(_, value)| value.trim())
        .unwrap_or(line)
}

fn normalize_marker_line(line: &str) -> String {
    let trimmed = line.trim();
    let without_quote = trimmed.trim_start_matches('>').trim();
    let without_bullet = without_quote
        .strip_prefix("- ")
        .or_else(|| without_quote.strip_prefix("* "))
        .unwrap_or(without_quote)
        .trim();
    without_bullet.trim_matches('`').trim().to_string()
}
