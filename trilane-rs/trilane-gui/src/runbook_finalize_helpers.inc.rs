fn has_runtime_or_repro(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    contains_any(
        &lower,
        &[
            "200 ok",
            "http 200",
            "runtime proof",
            "returned",
            "response",
            "success",
            "confirmed",
            "accepted",
            "challenge",
            "repro",
            "curl ",
            "baseline",
            "negative control",
            "control-passed",
            "impact-proven",
            "reproducible",
        ],
    )
}

fn has_unauthenticated_middleware_gap(
    title: &str,
    code_path: &str,
    location: &str,
    detail: &str,
) -> bool {
    let text = format!("{title}\n{code_path}\n{location}\n{detail}").to_ascii_lowercase();
    let claims_unauthenticated = contains_any(
        &text,
        &[
            "unauthenticated",
            "no authentication",
            "without authentication",
            "no auth",
        ],
    );
    if !claims_unauthenticated {
        return false;
    }
    if contains_any(
        &text,
        &[
            "application-configuration",
            "application-version",
            "full configuration",
            "metadata/configuration disclosure",
        ],
    ) {
        return false;
    }
    let route_only_anchor = contains_any(&text, &["server.ts:", "app.post", "app.get", "app.put"]);
    let has_chain_proof = contains_any(
        &text,
        &[
            "middleware chain",
            "route stack",
            "parent middleware",
            "preceding app.use",
            "no preceding middleware",
            "no parent middleware",
            "no app.use",
        ],
    );
    route_only_anchor && !has_chain_proof
}

fn evidence_state_from_claim(claim: &RunbookClaim) -> &'static str {
    match verification_status_from_claim(claim) {
        "publishable" | "weaponized" | "verified" => claim.evidence_level.as_marker(),
        "blocked" => "blocked-by-control",
        "runtime-signal" => "runtime-signal",
        "source-backed" => "source-backed",
        "needs-poc" => "needs-poc",
        value => value,
    }
}

fn severity_from_claim(claim: &RunbookClaim) -> &'static str {
    let haystack = format!(
        "{}\n{}\n{}",
        claim.title, claim.impact, claim.positive_evidence
    )
    .to_ascii_lowercase();
    if contains_any(
        &haystack,
        &["rce", "takeover", "admin", "credential", "exfil"],
    ) {
        "critical"
    } else if contains_any(&haystack, &["bypass", "idor", "ssrf", "injection", "xss"]) {
        "high"
    } else {
        "medium"
    }
}

fn same_category(canonical_key: &str, category: &str) -> bool {
    canonical_key
        .split_once(':')
        .map(|(prefix, _)| {
            prefix == category
                || prefix == "auth" && category == "injection"
                || prefix == "injection" && category == "auth"
        })
        .unwrap_or(false)
}

fn finding_rank(finding: &RunbookFinding) -> (usize, usize, usize, usize, usize) {
    (
        verification_rank(verification_status(finding)),
        severity_rank(&finding.severity),
        usize::from(!finding.code_path.trim().is_empty()),
        usize::from(!finding.payload.trim().is_empty()),
        finding.detail.len(),
    )
}

fn final_finding_rank(finding: &RunbookFinalFinding) -> (usize, usize, usize, String) {
    (
        severity_rank(&finding.severity),
        verification_rank(&finding.verification_status),
        finding.duplicates.len(),
        finding.title.clone(),
    )
}

fn canonical_finding_key(finding: &RunbookFinding) -> String {
    semantic_family_key(
        &format!(
            "{}\n{}\n{}\n{}",
            finding.title, finding.code_path, finding.detail, finding.payload
        ),
        &finding.code_path,
        finding.candidate_id.as_deref(),
    )
}

fn canonical_final_key(finding: &RunbookFinalFinding) -> String {
    semantic_family_key(
        &format!(
            "{}\n{}\n{}\n{}\n{}",
            finding.title, finding.code_path, finding.location, finding.detail, finding.payload
        ),
        if finding.code_path.trim().is_empty() {
            &finding.location
        } else {
            &finding.code_path
        },
        finding.candidate_id.as_deref(),
    )
}

fn canonical_claim_key(claim: &RunbookClaim) -> String {
    semantic_family_key(
        &format!(
            "{}\n{}\n{}\n{}\n{}\n{}\n{}",
            claim.title,
            claim.category,
            claim.target,
            claim.code_path,
            claim.root_cause,
            claim.positive_evidence,
            claim.payload
        ),
        if claim.code_path.trim().is_empty() {
            &claim.root_cause
        } else {
            &claim.code_path
        },
        Some(&claim.id),
    )
}

fn semantic_family_key(surface: &str, location: &str, candidate_id: Option<&str>) -> String {
    let full_surface = surface.to_ascii_lowercase();
    let title = full_surface.lines().next().unwrap_or_default();
    let primary_surface = format!("{title}\n{}", location.to_ascii_lowercase());
    let surface = if looks_like_placeholder_title(title) {
        full_surface.as_str()
    } else {
        primary_surface.as_str()
    };
    let key =
        if contains_any(surface, &["sql", "sqli"]) && contains_any(surface, &["login", "auth"]) {
            "injection:login-sqli"
        } else if contains_any(surface, &["mass assignment", "role", "admin"])
            && contains_any(
                surface,
                &["registration", "/api/users", "api/users", "user creation"],
            )
        {
            "authz:admin-role-registration"
        } else if contains_any(surface, &["union", "search", "product"])
            && contains_any(surface, &["sql", "sqli"])
        {
            "injection:product-search-sqli"
        } else if contains_any(
            surface,
            &["password change", "change-password", "current password"],
        ) {
            "auth:change-password-without-current"
        } else if contains_any(surface, &["security answer", "hmac"]) {
            "auth:security-answer-hardcoded-hmac"
        } else if contains_any(surface, &["jwt", "token"]) && surface.contains("password hash") {
            "session:jwt-password-hash-leak"
        } else if contains_any(surface, &["md5", "weak hash", "password hashing"]) {
            "crypto:md5-password-hashing"
        } else if contains_any(surface, &["username", "ssti", "server-side template"])
            && contains_any(surface, &["eval", "rce", "#{"])
        {
            "injection:username-ssti-rce"
        } else if contains_any(surface, &["trackorder", "track order", "order id"])
            && contains_any(surface, &["reflected", "xss"])
        {
            "xss:track-order-reflected-xss"
        } else if contains_any(
            surface,
            &["$where", "nosql", "order tracking", "all orders"],
        ) {
            "injection:order-tracking-nosql"
        } else if contains_any(
            surface,
            &["true-client-ip", "http-header", "header-based xss"],
        ) {
            "xss:true-client-ip-header-xss"
        } else if contains_any(surface, &["review"])
            && contains_any(surface, &["mass", "update", "nosql", "$where"])
        {
            "authz:review-update-abuse"
        } else if contains_any(surface, &["review", "author", "forged product review"]) {
            "authz:forged-product-review"
        } else if contains_any(surface, &["directory listing", "/ftp", "ftp/"]) {
            "info:ftp-directory-listing"
        } else if surface.contains("swagger") {
            "info:swagger-exposed"
        } else if surface.contains("metrics") || surface.contains("prometheus") {
            "info:metrics-exposed"
        } else if surface.contains("config") {
            "info:config-exposed"
        } else if surface.contains("log") {
            "info:logs-exposed"
        } else if surface.contains("ssrf")
            || contains_any(surface, &["profile image", "profileimageurl"])
        {
            "ssrf:profile-image-url-fetch"
        } else if surface.contains("redirect") {
            "redirect:open-redirect"
        } else if contains_any(surface, &["zip slip", "arbitrary file write"]) {
            "traversal:zip-slip"
        } else if surface.contains("yaml") {
            "file:yaml-deserialization"
        } else if surface.contains("xxe") || surface.contains("xml") {
            "file:xxe-upload"
        } else if contains_any(
            surface,
            &["pug", "layout", "local file read", "lfi", "data erasure"],
        ) {
            "traversal:pug-layout-lfi"
        } else if surface.contains("cors") {
            "cors:permissive-cors"
        } else if contains_any(surface, &["content-security-policy", "csp", "xssfilter"]) {
            "headers:missing-csp"
        } else if contains_any(surface, &["strict-transport-security", "hsts"]) {
            "headers:missing-hsts"
        } else if contains_any(surface, &["rate limit", "brute force"]) {
            "rate:missing-rate-limit"
        } else if surface.contains("deluxe") {
            "business:free-deluxe-membership"
        } else if surface.contains("basket") || surface.contains("idor") {
            "authz:basket-idor"
        } else if surface.contains("coupon") {
            "business:coupon-abuse"
        } else if contains_any(surface, &["negative order", "negative total"]) {
            "business:negative-order-total"
        } else if contains_any(surface, &["totp", "2fa", "fa secret"]) {
            "auth:totp-secret-plaintext"
        } else if contains_any(surface, &["unsigned jwt", "algorithm \"none\"", "alg none"]) {
            "session:jwt-none-algorithm"
        } else if contains_any(
            surface,
            &["hs256", "algorithm confusion", "forged signed jwt"],
        ) {
            "session:jwt-algorithm-confusion"
        } else if contains_any(surface, &["jwt", "rsa private", "private key"]) {
            "secrets:jwt-private-key"
        } else if contains_any(
            surface,
            &["encryptionkeys", "jwt public key", "premium.key"],
        ) {
            "secrets:public-encryption-keys"
        } else if contains_any(
            surface,
            &["hardcoded weak credentials", "admin123", "support password"],
        ) {
            "secrets:hardcoded-credentials"
        } else if surface.contains("cookie") && surface.contains("secret") {
            "secrets:cookie-secret"
        } else if surface.contains("alchemy") {
            "secrets:alchemy-key"
        } else if contains_any(surface, &["api key", "apikey", "leaked api key"]) {
            "secrets:leaked-api-key"
        } else if contains_any(surface, &["security question", "enumeration"]) {
            "auth:security-question-enumeration"
        } else if contains_any(surface, &["wallet balance", "userid parameter"]) {
            "business:wallet-balance-userid"
        } else if contains_any(surface, &["bot factory", "chatbot", "botutils"]) {
            "business:chatbot-handler-surface"
        } else if contains_any(surface, &["order pdf", "publicly accessible"]) {
            "info:public-order-pdfs"
        } else {
            let location = if location.trim().is_empty() || location.trim() == "-" {
                candidate_id.unwrap_or("")
            } else {
                location
            };
            return format!(
                "{}:{}:{}",
                infer_category(surface),
                normalize_path_key(location),
                normalize_id(surface.lines().next().unwrap_or_default())
            );
        };
    key.to_string()
}

fn verification_status(finding: &RunbookFinding) -> &'static str {
    let haystack = format!(
        "{}\n{}\n{}",
        finding.detail, finding.payload, finding.evidence_state
    )
    .to_ascii_lowercase();
    let has_source = !finding.code_path.trim().is_empty();
    let has_poc = !finding.payload.trim().is_empty()
        || contains_any(
            &haystack,
            &[
                "curl ",
                "http://",
                "https://",
                "status 200",
                "returned",
                "success",
                "challenge",
                "exploit",
                "proof",
                "poc",
            ],
        );
    if has_source && has_poc {
        "verified"
    } else if has_source {
        "source-backed"
    } else {
        "needs-poc"
    }
}

fn verification_rank(status: &str) -> usize {
    match status {
        "publishable" => 6,
        "weaponized" => 5,
        "verified" => 4,
        "runtime-signal" | "corroborated" => 3,
        "source-backed" | "anchored" => 2,
        "needs-poc" | "armed" | "running" => 1,
        _ => 0,
    }
}

fn severity_rank(severity: &str) -> usize {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn finding_location(finding: &RunbookFinding) -> String {
    if !finding.code_path.trim().is_empty() {
        finding.code_path.clone()
    } else if let Some(candidate_id) = finding.candidate_id.as_deref() {
        candidate_id.to_string()
    } else {
        finding.stage.clone()
    }
}

fn infer_category(text: &str) -> &'static str {
    if contains_any(text, &["authz", "idor", "permission", "privilege", "role"]) {
        "authz"
    } else if contains_any(text, &["session", "httponly", "cookie", "localstorage"]) {
        "session"
    } else if contains_any(text, &["auth", "jwt", "password", "login"]) {
        "auth"
    } else if contains_any(text, &["xss", "dom", "sanitize", "innerhtml"]) {
        "xss"
    } else if contains_any(text, &["xxe", "upload", "xml", "multipart", "parser"]) {
        "file_upload_xxe"
    } else if contains_any(text, &["traversal", "lfi", "../", "file read", "path"]) {
        "traversal_lfi"
    } else if contains_any(
        text,
        &["sql", "nosql", "template", "command", "injection", "rce"],
    ) {
        "injection"
    } else if contains_any(text, &["ssrf", "redirect", "url", "egress"]) {
        "ssrf_redirect"
    } else if contains_any(text, &["secret", "key", "config", "token"]) {
        "secrets_config"
    } else if contains_any(
        text,
        &[
            "directory listing",
            "exposed",
            "disclosure",
            "metrics",
            "swagger",
            "debug",
            "docs",
            "logs",
            "diagnostic",
        ],
    ) {
        "observability_leak"
    } else if contains_any(text, &["cors", "header", "tls", "hsts", "helmet"]) {
        "cors_headers_tls"
    } else if contains_any(text, &["rate", "brute", "limit"]) {
        "rate_limit"
    } else if contains_any(text, &["crypto", "md5", "hash", "cipher"]) {
        "crypto"
    } else if contains_any(
        text,
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
        text,
        &[
            "basket", "coupon", "checkout", "order", "price", "wallet", "payment", "negative",
            "deluxe", "invariant",
        ],
    ) {
        "state_invariant_abuse"
    } else {
        "api"
    }
}

fn normalize_path_key(path: &str) -> String {
    let trimmed = path
        .split_whitespace()
        .next()
        .unwrap_or(path)
        .trim_matches(|ch: char| ch == '`' || ch == ',' || ch == ';');
    let without_line = trimmed
        .split(':')
        .next()
        .filter(|value| !value.is_empty())
        .unwrap_or(trimmed);
    normalize_id(without_line)
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

fn contains_any(text: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| text.contains(needle))
}
