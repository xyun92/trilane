fn required_s2_lanes() -> [&'static str; 5] {
    [
        "identity_engine",
        "injection_engine",
        "ingress_engine",
        "logic_engine",
        "config_engine",
    ]
}

fn s2_lane_report_complete(lane: &RunbookLane) -> bool {
    lane.status == "done" && lane.report_seen
}

fn normalize_lane_status(status: &str) -> &'static str {
    match status.trim().to_ascii_lowercase().as_str() {
        "done" | "completed" | "complete" | "success" | "succeeded" => "done",
        "failed" | "failure" | "error" | "errored" => "failed",
        "queued" | "pending" => "queued",
        "retrying" | "backoff" | "rate_limited" | "rate-limited" => "retrying",
        "running" | "started" | "spawned" | "in_progress" | "in-progress" => "running",
        _ => "running",
    }
}

fn marker_value(line: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=");
    let start = line.find(&needle)? + needle.len();
    let rest = &line[start..];
    let keys = [
        " id=",
        " lane=",
        " category=",
        " area=",
        " feature=",
        " family=",
        " endpoints=",
        " source_files=",
        " files=",
        " routes=",
        " target=",
        " title=",
        " status=",
        " count=",
        " claims=",
        " candidates=",
        " mapped=",
        " total=",
        " result=",
        " reason=",
        " must=",
        " check=",
        " attack=",
        " obligation=",
        " priority=",
        " cve_prior=",
        " note=",
        " summary=",
        " error=",
        " severity=",
        " code_path=",
        " thread_id=",
        " thread=",
        " evidence=",
        " payload=",
        " poc=",
        " confidence=",
        " exploit=",
        " cwe=",
        " label=",
        " kind=",
        " status=",
        " level=",
        " fingerprint=",
        " root_cause=",
        " precondition=",
        " impact=",
        " positive=",
        " negative=",
        " merge_into=",
        " merged_into=",
        " surface=",
        " lane_id=",
        " bridge=",
        " bridge_keys=",
        " claim=",
        " claim_id=",
        " atoms=",
        " atom_ids=",
        " verify_plan=",
        " plan=",
        " score=",
    ];
    let end = keys
        .iter()
        .filter_map(|candidate| rest.find(candidate))
        .min()
        .unwrap_or(rest.len());
    let value = rest[..end]
        .trim()
        .trim_matches('`')
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim_matches('`')
        .trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn field_from_block(block: &[String], key: &str) -> Option<String> {
    let needle = format!("{key}:").to_ascii_lowercase();
    block.iter().find_map(|line| {
        let cleaned = clean_markdown_field_line(line);
        let lower = cleaned.to_ascii_lowercase();
        if lower.starts_with(&needle) {
            Some(
                cleaned[needle.len()..]
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'')
                    .to_string(),
            )
        } else {
            let bold_needle = format!("**{key}:**").to_ascii_lowercase();
            lower.starts_with(&bold_needle).then(|| {
                cleaned[bold_needle.len()..]
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'')
                    .to_string()
            })
        }
    })
}

fn clean_markdown_field_line(line: &str) -> &str {
    let trimmed = line.trim();
    let without_bullet = trimmed
        .strip_prefix("- ")
        .or_else(|| trimmed.strip_prefix("* "))
        .unwrap_or(trimmed);
    let without_number = without_bullet
        .trim_start_matches(|ch: char| ch.is_ascii_digit())
        .trim_start_matches(['.', ')'])
        .trim();
    if without_number.is_empty() {
        without_bullet
    } else {
        without_number
    }
}

fn is_finding_heading(line: &str) -> bool {
    finding_heading_title(line).is_some()
}

fn finding_heading_title(line: &str) -> Option<&str> {
    let cleaned = line
        .trim()
        .trim_start_matches('#')
        .trim()
        .trim_start_matches(|ch: char| ch == '-' || ch == '*' || ch.is_ascii_digit())
        .trim_start_matches(['.', ')'])
        .trim();
    let lower = cleaned.to_ascii_lowercase();
    if lower.starts_with("findings") || lower.starts_with("finding%") {
        return None;
    }
    if let Some((_, value)) = cleaned.split_once(':') {
        if lower.starts_with("finding:") && !value.trim().is_empty() {
            return Some(value.trim());
        }
    }
    let rest = lower.strip_prefix("finding")?.trim_start();
    if rest.is_empty() || rest.starts_with('s') {
        return None;
    }
    let title_start = cleaned
        .char_indices()
        .find_map(|(idx, ch)| {
            (idx > "finding".len()
                && (ch == '-' || ch == '—' || ch == ':' || ch.is_ascii_alphabetic()))
            .then_some((idx, ch))
        })
        .map(|(idx, ch)| {
            if ch == '-' || ch == '—' || ch == ':' {
                idx + ch.len_utf8()
            } else {
                idx
            }
        })
        .unwrap_or("finding".len());
    let title = cleaned[title_start..]
        .trim()
        .trim_start_matches(|ch: char| ch.is_ascii_digit())
        .trim_start_matches(['.', ')', '-', '—', ':'])
        .trim();
    if title.is_empty() {
        None
    } else {
        Some(title)
    }
}

fn infer_severity(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    if lower.contains("critical") {
        "critical".to_string()
    } else if lower.contains("high") {
        "high".to_string()
    } else if lower.contains("medium") {
        "medium".to_string()
    } else if lower.contains("low") {
        "low".to_string()
    } else {
        "info".to_string()
    }
}

fn infer_category(text: &str) -> String {
    infer_coverage_category(text).unwrap_or_else(|| "api".to_string())
}

fn infer_coverage_category(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let category = if contains_any(
        &lower,
        &["authz", "idor", "permission", "privilege", "role"],
    ) {
        "authz"
    } else if contains_any(&lower, &["session", "httponly", "cookie", "localstorage"]) {
        "session"
    } else if contains_any(&lower, &["auth", "jwt", "session", "password", "login"]) {
        "auth"
    } else if contains_any(&lower, &["xss", "dom", "sanitize", "innerhtml"]) {
        "xss"
    } else if contains_any(&lower, &["xxe", "upload", "xml", "multipart", "parser"]) {
        "file_upload_xxe"
    } else if contains_any(&lower, &["traversal", "lfi", "../", "file read", "path"]) {
        "traversal_lfi"
    } else if contains_any(
        &lower,
        &["sql", "nosql", "template", "command", "injection", "rce"],
    ) {
        "injection"
    } else if contains_any(&lower, &["ssrf", "redirect", "url", "egress"]) {
        "ssrf_redirect"
    } else if contains_any(&lower, &["secret", "key", "config", "token"]) {
        "secrets_config"
    } else if contains_any(
        &lower,
        &[
            "directory listing",
            "exposed",
            "disclosure",
            "metrics",
            "swagger",
            "logs",
            "debug",
            "diagnostic",
            "docs",
        ],
    ) {
        "observability_leak"
    } else if contains_any(&lower, &["cors", "header", "tls", "hsts", "helmet"]) {
        "cors_headers_tls"
    } else if contains_any(&lower, &["rate", "brute", "limit"]) {
        "rate_limit"
    } else if contains_any(&lower, &["crypto", "md5", "hash", "cipher"]) {
        "crypto"
    } else if contains_any(
        &lower,
        &[
            "captcha",
            "security question",
            "security answer",
            "reset",
            "recovery",
            "anti automation",
            "anti-automation",
            "bot",
        ],
    ) {
        "anti_automation_bypass"
    } else if contains_any(
        &lower,
        &[
            "basket", "coupon", "checkout", "order", "price", "wallet", "payment", "negative",
            "deluxe", "invariant",
        ],
    ) {
        "state_invariant_abuse"
    } else if contains_any(&lower, &["/api", "api/", "/rest", "rest/", "route"]) {
        "api"
    } else {
        return None;
    };
    Some(category.to_string())
}

fn coverage_signal_label(text: &str) -> String {
    first_line(text)
}

fn extract_payload_from_text(primary: &str, secondary: &str) -> String {
    let mut payload_lines = Vec::new();
    for line in format!("{primary}\n{secondary}").lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_ascii_lowercase();
        if trimmed.is_empty() {
            continue;
        }
        if lower.starts_with("payload:")
            || lower.starts_with("exploit:")
            || lower.starts_with("poc:")
            || contains_any(
                &lower,
                &[
                    "curl ",
                    "http://",
                    "https://",
                    "union select",
                    " or 1=1",
                    "$where",
                    "<script",
                    "javascript:",
                    "../",
                    "<!doctype",
                    "{{",
                ],
            )
        {
            payload_lines.push(trimmed.to_string());
        }
        if payload_lines.len() >= 8 {
            break;
        }
    }
    truncate(&payload_lines.join("\n"), 900)
}

fn evidence_gate(code_path: &str, evidence: &str, confidence: &str) -> &'static str {
    let mut score = 0;
    if !evidence.trim().is_empty() {
        score += 1;
    }
    if !code_path.trim().is_empty() {
        score += 1;
    }
    if confidence.eq_ignore_ascii_case("high") {
        score += 1;
    }
    match score {
        0 | 1 => "signal",
        2 => "exploit+source",
        _ => "triad-ready",
    }
}

fn verification_weight(line: &str) -> usize {
    let lower = line.to_ascii_lowercase();
    [
        "exploit=",
        "root_cause=",
        "code_path=",
        "control=",
        "negative=",
        "validator=",
    ]
    .iter()
    .filter(|needle| lower.contains(**needle))
    .count()
    .max(1)
}

fn normalize_id(value: &str) -> String {
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

fn truncate(text: &str, max_chars: usize) -> String {
    let mut value: String = text.chars().take(max_chars).collect();
    if text.chars().count() > max_chars {
        value.push_str("\n...[truncated]");
    }
    value
}

fn empty_dash(value: &str) -> &str {
    if value.trim().is_empty() {
        "-"
    } else {
        value
    }
}

fn prefer_longer(existing: &str, incoming: &str, max_chars: usize) -> String {
    if incoming.trim().len() > existing.trim().len() {
        truncate(incoming, max_chars)
    } else {
        truncate(existing, max_chars)
    }
}

fn append_compact(existing: &str, incoming: &str, max_chars: usize) -> String {
    let incoming = incoming.trim();
    if incoming.is_empty() {
        return truncate(existing, max_chars);
    }
    if existing.contains(incoming) {
        return truncate(existing, max_chars);
    }
    if existing.trim().is_empty() {
        truncate(incoming, max_chars)
    } else {
        truncate(&format!("{}\n{}", existing.trim(), incoming), max_chars)
    }
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}
