fn phase_context(phase: &WorkflowPhase, state: &RunbookState, objective: &str) -> String {
    if phase.id == "s5_final_revision" {
        return format!(
            "\nFINAL_REVISION_CONTRACT%\n\
             - Output-only correction pass. Do not call tools, inspect source, run commands, or start a new audit.\n\
             - REVIEW_CONTEXT is advisory. Critically apply only ledger-supported corrections to the already-adjudicated S5 PoC bundle.\n\
             - Emit exactly one RUNBOOK% S5 Final Revision line, then the replacement canonical POC% set.\n\
             - Preserve recall: do not collapse the replacement set to only the highest-confidence/core PoCs.\n\
             - Accept drop/merge only for same-family duplicates, ledger contradictions, out-of-scope items, placeholders, or non-security observations.\n\
             - For missing live proof, weak replay, or uncertain impact, downgrade/rewrite to generated-not-verified or needs-poc instead of deleting.\n\
             - Do not invent PoCs beyond REVIEW% add_check items with an evidence_ref already present in RUNBOOK_CONTEXT.\n\
             - The backend treats this POC% set as the replacement final set; ordinary markdown tables are ignored for counting.\n\n\
             RUNBOOK_CONTEXT%\n{}\n\nREVIEW_CONTEXT%\n{}\n",
            compact_claim_packet(state, /*max_items*/ 120),
            compact_s5_review_packet(state, /*max_items*/ 80),
        );
    }
    if phase.stage_code == "S1" {
        return format!(
            "\nSCANNER_CONTEXT%\n{}\n",
            crate::source_scanner::scanner_packet(objective, None, 80)
        );
    }
    if !matches!(phase.stage_code, "S3" | "S4" | "S5") {
        return String::new();
    }
    if phase.stage_code == "S3" {
        return format!(
            "\nRUNBOOK_CONTEXT%\n{}\n",
            compact_s3_claim_pool(state, /*max_items*/ 160)
        );
    }
    if phase.stage_code == "S4" {
        return format!(
            "\nRUNBOOK_CONTEXT%\n{}\n",
            compact_s4_handoff_packet(state, &phase.id, /*max_items*/ 120)
        );
    }
    format!(
        "\nRUNBOOK_CONTEXT%\n{}\n",
        compact_claim_packet(state, /*max_items*/ 120)
    )
}

fn cve_prior_contract() -> &'static str {
    "CVE_PRIOR%\n\
     - Use this generic empirical prior as a coverage checklist, not as target-specific answers.\n\
     - Identity: authentication bypass, missing authorization, BOLA/IDOR, privilege escalation, weak session/JWT/cookie lifecycle.\n\
     - Injection/Browser trust: SQL/NoSQL/template/command injection, unsafe eval/sandbox, XSS in rendered/header/media/browser sinks, CORS/header trust flaws.\n\
     - Files/Parsers/Egress: upload parser abuse, XXE/YAML/deserialization, archive/path traversal, LFI/file write, SSRF and open redirect.\n\
     - Logic/Automation: state-invariant abuse, coupon/payment/wallet/order/review/export workflow bypass, recovery/reset/security-question/CAPTCHA/rate-limit bypass.\n\
     - Config/Observability/Crypto: hardcoded secrets, public config/docs/logs/metrics/debug/static files, weak hashes, JWT/key/signature/cookie issues.\n\
     - S2 rule: use this only to seed high-value CLAIM% candidates; proof, rejection, controls, and final findings belong to S4/S5."
}

fn s2_lane_batch(
    phase: &WorkflowPhase,
    objective: &str,
    state: &RunbookState,
    is_repair: bool,
) -> WorkflowLaneBatch {
    let mut lanes = if is_repair {
        state.s2_missing_lanes()
    } else if state.s2_required_lanes_complete() && !state.s2_quick_hits_finished() {
        vec![quick_hits_lane_id().to_string()]
    } else {
        s2_core_lane_ids()
            .iter()
            .map(|lane| (*lane).to_string())
            .collect::<Vec<_>>()
    };
    if lanes.is_empty() {
        if !state.s2_required_lanes_complete() {
            lanes = state.s2_missing_lanes();
        } else if !state.s2_quick_hits_finished() {
            lanes = vec![quick_hits_lane_id().to_string()];
        }
    }
    WorkflowLaneBatch {
        phase_id: phase.id.to_string(),
        stage_id: phase.stage_id.to_string(),
        title: phase.title.to_string(),
        lanes: lanes
            .into_iter()
            .map(|lane_id| {
                let mut s1_ledger = compact_s1_lane_ledger(state, &lane_id, /*max_surfaces*/ 40);
                s1_ledger.push_str("\n\nSCANNER_CONTEXT%\n");
                s1_ledger.push_str(&crate::source_scanner::scanner_packet(
                    objective,
                    Some(&lane_id),
                    if lane_id == quick_hits_lane_id() { 40 } else { 32 },
                ));
                if lane_id == quick_hits_lane_id() && state.s2_required_lanes_complete() {
                    s1_ledger.push_str("\n\nCORE_LANE_CONTEXT%\n");
                    s1_ledger.push_str(&compact_claim_packet(state, /*max_items*/ 60));
                }
                WorkflowLaneSpec {
                    title: s2_lane_title(&lane_id).to_string(),
                    prompt: s2_lane_prompt(&lane_id, objective, &s1_ledger, is_repair),
                    lane_id,
                }
            })
            .collect(),
        is_repair,
    }
}

fn s2_core_lane_ids() -> [&'static str; 5] {
    [
        "identity_engine",
        "injection_engine",
        "ingress_engine",
        "logic_engine",
        "config_engine",
    ]
}

fn quick_hits_lane_id() -> &'static str {
    "quick_hits_engine"
}

fn s2_lane_title(lane_id: &str) -> &'static str {
    match lane_id {
        "identity_engine" => "Identity Engine",
        "injection_engine" => "Injection Engine",
        "ingress_engine" => "Ingress Engine",
        "logic_engine" => "Logic Engine",
        "config_engine" => "Config Engine",
        "quick_hits_engine" => "Quick Hits Engine",
        _ => "Unknown lane",
    }
}

fn s2_lane_task(lane_id: &str) -> &'static str {
    match lane_id {
        "identity_engine" => {
            "Engine categories: auth, authz, session. Audit login, registration, password change, 2FA/TOTP, JWT/session/cookie lifecycle, role assignment, object ownership, IDOR/BOLA, admin gates, continue-code/hashids/token helpers, account metadata, and auth boundary confusion."
        }
        "injection_engine" => {
            "Engine categories: injection, xss, cors_headers_tls. Audit SQL/NoSQL/template/command injection, unsafe eval/vm/sandbox behavior, reflected/stored/DOM/header XSS, sanitizer boundaries, browser render sinks, document.write-style DOM flows, CORS exposure, header posture, and browser trust context."
        }
        "ingress_engine" => {
            "Engine categories: file_upload_xxe, traversal_lfi, ssrf_redirect. Audit upload handlers, MIME/extension/null-byte bypasses, parser abuse, XXE/YAML/deserialization, zip/path traversal, LFI/template layout/file read/write, SSRF, server-side fetchers, redirects, robots/static manifests, and static file ingress."
        }
        "logic_engine" => {
            "Engine categories: state_invariant_abuse, anti_automation_bypass, rate_limit. Audit basket/cart/quantity/export ownership, data export/erasure scope, review/feedback authorship, wallet/coupon/payment/deluxe/order invariants, reset/recovery/security-question/CAPTCHA flaws, brute force, throttling, and state-machine bypasses."
        }
        "config_engine" => {
            "Engine categories: secrets_config, observability_leak, crypto. Audit hardcoded secrets, test credentials, API keys, TOTP seeds, exposed keys/config/logs/docs/metrics/debug routes, weak crypto/hash choices, JWT key/algorithm handling, and exploitable disclosure impact."
        }
        "quick_hits_engine" => {
            "Engine categories: residual cross-lane low-hanging fruit mapped back into the existing TriLane taxonomy. Read SOURCE_PACKET and CORE_LANE_CONTEXT first. Run only the fixed quick-hit edge checklist plus any unclosed high-value S1 obligation in the packet. Do not do broad exploration. New residual claims must use QH-CAND-* ids and must be emitted as CLAIM% lines, not prose."
        }
        _ => "Audit the assigned domain and emit machine-readable evidence.",
    }
}

fn s2_lane_prompt(lane_id: &str, objective: &str, s1_ledger: &str, is_repair: bool) -> String {
    let repair = if is_repair {
        "\nWORKFLOW_REPAIR% This lane was missing or incomplete in the previous S2 batch. Emit a complete lane ledger now.\n"
    } else {
        ""
    };
    format!(
        "AUDIT_MODE% TRILANE\n\
         WORKFLOW% id=trilane-workflow phase=s2_parallel_semantic_audit stage=S2 lane={lane_id} repair={is_repair}\n\
         LANE% id={lane_id} title=\"{}\"\n\
         USER_OBJECTIVE%\n{}\n\
         {repair}\n\
         S1_LEDGER%\n{}\n\n\
         {}\n\n\
         LANE_TASK%\n{}\n\n\
         {}\n\
         AGENT_RULES%\n{}\n\n\
         OUTPUT_CONTRACT%\n\
         - You are a workflow-owned child lane. Do not write final PoCs.\n\
         - S2 is candidate discovery only. The only machine-readable marker you may emit is CLAIM%.\n\
         - Consume SOURCE_PACKET% and SCANNER_PACKET% first as lane-specific task packets, not as full-history transcripts. Follow S1 READ_TARGET% items assigned to this lane, then stop or broaden only once inside your assigned domain if a high-value candidate is obvious.\n\
         - Micro-verify by reading only the decisive source window: confirm source->sink reachability, identify the guard/control if visible, and drop obvious false positives silently. Do not send HTTP, run live probes, repair exploit payloads, or construct final PoCs.\n\
         - Emit every credible CLAIM% candidate in your assigned lane. If no credible candidate exists, end the turn without emitting a marker.\n\
         - CLAIM% format: CLAIM% id=<lane-prefix>-<n> category=<taxonomy> target=<sink-file:line-or-route> severity=<critical|high|medium|low> confidence=<low|medium|high> title=<short> reason=<source->sink-short-proof> impact=<short> next=poc:<stable-poc-unit>.\n\
         - Use lane-specific ids: identity uses ID-*, injection uses INJ-CAND-* / XSS-CAND-* / CORS-CAND-*, ingress uses ING-*, logic uses LOGIC-CAND-*, config uses CONFIG-CAND-*, quick_hits uses QH-CAND-*.\n\
         - Do not emit any non-CLAIM machine-readable marker in S2. Do not write proof, rejection, duplicate, merge, atom, candidate, coverage, probe, control, finding, summary, or lane-completion rows.\n\
         - Do not dedupe, emit rejected rows, write controls, write PoCs, or write summaries in S2. S3 merges by PoC unit, S4 verifies, and S5 produces final PoCs/findings.\n\
         - Keep visible prose minimal. Prefer rg/sed source reads and compact CLAIM% lines; do not narrate routine planning with phrases like \"Let me\", \"I need\", or \"Now I\".\n",
        s2_lane_title(lane_id),
        objective.trim(),
        s1_ledger,
        cve_prior_contract(),
        s2_lane_task(lane_id),
        s2_quick_hits_checklist(lane_id),
        stage_agent_rules("S2", "s2_parallel_semantic_audit")
    )
}

fn s2_quick_hits_checklist(lane_id: &str) -> &'static str {
    if lane_id != quick_hits_lane_id() {
        return "";
    }
    "QUICK_HITS_CHECKLIST%\n\
	     - Check only these residual edges unless SOURCE_PACKET% shows an unclosed high-value obligation: JWT none/HS256/key confusion, 2FA/TOTP plaintext, reset-password HMAC/answer flow, whoami/JSONP/password-hash leak, image CAPTCHA answer/skip, accounting/order-history token gates, verbose error/debug exposure, Swagger/config/version/docs exposure, hardcoded API keys/secrets, and one missed IDOR/mass-assignment/business invariant.\n\
	     - Emit only new residual CLAIM% lines. Do not emit any other machine-readable row.\n\
	     - No exploratory prose or self-debate. Use bounded rg/sed source reads as needed, then decide from SOURCE_PACKET% and CORE_LANE_CONTEXT.\n\
	     - Emit every credible QH-CAND-* claim. If the checklist adds nothing credible, end the turn without a marker.\n\n"
}

fn s5_review_lane_batch(
    phase: &WorkflowPhase,
    objective: &str,
    state: &RunbookState,
    is_repair: bool,
) -> WorkflowLaneBatch {
    WorkflowLaneBatch {
        phase_id: phase.id.to_string(),
        stage_id: phase.stage_id.to_string(),
        title: phase.title.to_string(),
        lanes: vec![WorkflowLaneSpec {
            lane_id: "poc_bundle_review".to_string(),
            title: "S5 advisory PoC bundle review".to_string(),
            prompt: s5_review_lane_prompt(objective, state, is_repair),
        }],
        is_repair,
    }
}

fn s5_review_lane_prompt(objective: &str, state: &RunbookState, is_repair: bool) -> String {
    let repair = if is_repair {
        "\nWORKFLOW_REPAIR% The previous review lane failed or did not return REVIEW_REPORT%. Re-read only RUNBOOK_CONTEXT and FINAL_POC_BUNDLE_DRAFT, then emit the missing REVIEW%/REVIEW_REPORT% ledger now. Do not run tools.\n"
    } else {
        ""
    };
    format!(
        "AUDIT_MODE% TRILANE\n\
         WORKFLOW% id=trilane-workflow phase=s5_adversarial_review stage=S5 lane=poc_bundle_review repair={is_repair}\n\
         LANE% id=poc_bundle_review title=\"S5 advisory PoC bundle review\"\n\
         USER_OBJECTIVE%\n{}\n\
         {repair}\n\
         RUNBOOK_CONTEXT%\n{}\n\n\
         FINAL_POC_BUNDLE_DRAFT%\n{}\n\n\
         AGENT_RULES%\n{}\n\n\
         REVIEW_TASK%\n\
         Review the draft PoC bundle after S5 adjudication. You are a bounded advisory PoC reviewer, not a new auditor and not the final decision-maker. Do not run tools, inspect source files, perform fresh probing, do a broad new scan, or rewrite the bundle yourself. Focus only on duplicate PoCs, missing replay steps, weak expected signals, unsupported severity inflation, unsafe cleanup/side effects, source-backed entries incorrectly marked verified, missing high-value families already supported by RUNBOOK_CONTEXT, and unclear evidence references. Favor recall-preserving advice: when evidence is incomplete but source/root-cause impact is plausible, recommend generated-not-verified or needs-poc instead of drop.\n\n\
         OUTPUT_CONTRACT%\n\
         - Emit compact machine-readable review comments only: REVIEW% action=<keep|merge|drop|downgrade|upgrade|add_check|rewrite> target=<VULN-id-or-claim-id-or-family> reason=<short> evidence_ref=<claim-or-finding-id> confidence=<high|medium|low>.\n\
         - High-confidence REVIEW% comments must be directly actionable by the main agent without extra source reads.\n\
         - Use REVIEW% action=drop only for same-family duplicates, ledger-contradicted claims, out-of-scope items, placeholders, or non-security observations.\n\
         - Do not recommend dropping solely because a PoC lacks live proof or full negative-control evidence; recommend generated-not-verified or needs-poc instead.\n\
         - Do not recommend dropping a family merely because one attempted payload path failed when the same root cause still supports a concrete replay.\n\
         - Do not create new PoCs unless they are already supported by RUNBOOK_CONTEXT evidence; cite that claim or finding id in evidence_ref.\n\
         - Do not include markdown sections, vulnerability tables, exploit writeups, shell commands, or source snippets.\n\
         - Finish with exactly one REVIEW_REPORT% lane=poc_bundle_review status=done comments=<n> critical=<n> note=<short> line.\n",
        objective.trim(),
        compact_claim_packet(state, /*max_items*/ 120),
        truncate_chars(&state.final_report_markdown(), 45_000),
        stage_agent_rules("S5", "s5_adversarial_review"),
    )
}

fn compact_s5_review_packet(state: &RunbookState, max_items: usize) -> String {
    let mut lines = Vec::new();
    let mut has_review_marker = false;
    for lane in &state.lanes {
        if lane.lane_id == "poc_bundle_review" {
            lines.push(format!(
                "SUBAGENT% lane={} status={} claims={} thread_id={} note={}",
                lane.lane_id, lane.status, lane.claim_count, lane.thread_id, lane.summary
            ));
        }
    }
    for evidence in &state.evidence {
        let haystack = format!("{}\n{}", evidence.title, evidence.detail).to_ascii_lowercase();
        if haystack.contains("review%") || haystack.contains("review_report%") {
            lines.push(evidence.detail.replace('\n', " "));
            has_review_marker = true;
        }
        if lines.len() >= max_items {
            break;
        }
    }
    if !has_review_marker {
        lines.push("REVIEW_REPORT% lane=poc_bundle_review status=missing comments=0 critical=0 note=no review comments captured".to_string());
    }
    lines.join("\n")
}

fn has_s5_final_revision_marker(state: &RunbookState) -> bool {
    state.evidence.iter().any(|evidence| {
        let haystack = format!(
            "{}\n{}",
            evidence.title.to_ascii_lowercase(),
            evidence.detail.to_ascii_lowercase()
        );
        haystack.contains("runbook% s5 final revision")
            || haystack.contains("runbook% s5 reviewer-applied")
            || haystack.contains("review_applied%")
    })
}

fn truncate_chars(text: &str, max_chars: usize) -> String {
    let mut truncated: String = text.chars().take(max_chars).collect();
    if text.chars().count() > max_chars {
        truncated.push_str("\n...[truncated]");
    }
    truncated
}

fn s2_lane_categories(lane_id: &str) -> &'static [&'static str] {
    match lane_id {
        "identity_engine" => &["auth", "authz", "session"],
        "injection_engine" => &["injection", "xss", "cors_headers_tls"],
        "ingress_engine" => &["file_upload_xxe", "traversal_lfi", "ssrf_redirect"],
        "logic_engine" => &["state_invariant_abuse", "anti_automation_bypass", "rate_limit"],
        "config_engine" => &["secrets_config", "observability_leak", "crypto"],
        "quick_hits_engine" => &[
            "auth",
            "authz",
            "session",
            "injection",
            "xss",
            "cors_headers_tls",
            "file_upload_xxe",
            "traversal_lfi",
            "ssrf_redirect",
            "state_invariant_abuse",
            "anti_automation_bypass",
            "rate_limit",
            "secrets_config",
            "observability_leak",
            "crypto",
        ],
        _ => &[],
    }
}

fn s2_lane_keywords(lane_id: &str) -> &'static [&'static str] {
    match lane_id {
        "identity_engine" => &[
            "auth", "login", "password", "reset", "session", "jwt", "token", "cookie", "user",
            "account", "2fa", "totp", "verify", "security-question", "admin",
        ],
        "injection_engine" => &[
            "sql", "nosql", "query", "search", "eval", "template", "xss", "cors", "header",
            "profile", "review", "track-order", "video", "subtitle",
        ],
        "ingress_engine" => &[
            "upload", "file", "zip", "xml", "yaml", "redirect", "url", "ssrf", "ftp", "layout",
            "download", "manifest", "static",
        ],
        "logic_engine" => &[
            "wallet", "coupon", "payment", "order", "basket", "review", "feedback", "export",
            "captcha", "security", "deluxe", "quantity", "erasure",
        ],
        "config_engine" => &[
            "secret", "key", "config", "metrics", "log", "debug", "swagger", "openapi", "crypto",
            "hash", "jwt", "cookie", "support",
        ],
        "quick_hits_engine" => &[
            "sql",
            "query",
            "eval",
            "jsonp",
            "callback",
            "cors",
            "jwt",
            "secret",
            "key",
            "metrics",
            "swagger",
            "api-docs",
            "logs",
            "static",
            "upload",
            "redirect",
            "ssrf",
            "wallet",
            "coupon",
            "payment",
            "order",
            "basket",
            "review",
            "export",
            "captcha",
            "security",
            "rate",
        ],
        _ => &[],
    }
}

fn s2_cross_lane_seed_keywords(lane_id: &str) -> &'static [&'static str] {
    match lane_id {
        "identity_engine" => &[
            "middleware", "owner", "ownership", "role", "continue", "hashids", "2fa", "totp",
            "change-password", "reset-password",
        ],
        "injection_engine" => &[
            "jsonp", "callback", "subtitle", "video", "render", "header", "browser", "profileimage",
        ],
        "ingress_engine" => &[
            "quarantine", "ftp", "manifest", "static", "backup", "layout", "archive", "parser",
        ],
        "logic_engine" => &[
            "checkout", "campaign", "clock", "memory", "feedback", "author", "wallet", "coupon",
            "basket", "order", "deluxe",
        ],
        "config_engine" => &[
            "swagger", "api-docs", "metrics", "logs", "support", "debug", "captcha", "premium",
            "encryptionkeys", "jwt.pub",
        ],
        "quick_hits_engine" => &[
            "swagger",
            "api-docs",
            "metrics",
            "logs",
            "support",
            "debug",
            "captcha",
            "premium",
            "encryptionkeys",
            "jwt.pub",
            "checkout",
            "wallet",
            "coupon",
            "basket",
            "order",
        ],
        _ => &[],
    }
}

fn s2_lane_text_matches(lane_id: &str, parts: &[&str]) -> bool {
    let haystack = parts
        .iter()
        .filter(|part| !part.trim().is_empty())
        .map(|part| part.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(" ");
    s2_lane_categories(lane_id)
        .iter()
        .any(|category| haystack.contains(category))
        || s2_lane_keywords(lane_id)
            .iter()
            .any(|keyword| haystack.contains(keyword))
}

fn s1_read_target_matches_lane(
    lane_id: &str,
    kind: &str,
    category: &str,
    label: &str,
    target: &str,
) -> bool {
    if kind != "read_target" {
        return false;
    }
    let haystack = [category, label, target]
        .iter()
        .filter(|part| !part.trim().is_empty())
        .map(|part| part.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(" ");
    lane_id == quick_hits_lane_id()
        || haystack.contains(&format!("lane={lane_id}"))
        || haystack.contains("lane=any")
        || s2_lane_text_matches(lane_id, &[category, kind, label, target])
}

fn s2_cross_lane_seed_matches(lane_id: &str, parts: &[&str]) -> bool {
    let haystack = parts
        .iter()
        .filter(|part| !part.trim().is_empty())
        .map(|part| part.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(" ");
    s2_cross_lane_seed_keywords(lane_id)
        .iter()
        .any(|keyword| haystack.contains(keyword))
}

fn compact_s1_lane_ledger(state: &RunbookState, lane_id: &str, max_surfaces: usize) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "OBJECTIVE% {}\nS1_SCOPE% lane={} surfaces_total={} coverage={}/{} candidates={} claims={}",
        state.objective.trim(),
        lane_id,
        state.surfaces.len(),
        state.stats.coverage_mapped,
        state.stats.coverage_total,
        state.candidates.len(),
        state.claims.len()
    ));
    lines.push(compact_s2_source_packet(state, lane_id));
    let lane_categories = s2_lane_categories(lane_id);
    for coverage in state.coverage.iter().filter(|coverage| {
        coverage.status != crate::runbook::CoverageStatus::Pending
            && lane_categories
                .iter()
                .any(|category| coverage.category == *category)
    }) {
        lines.push(format!(
            "COVERAGE% category={} mapped={} total={} label={}",
            marker_token(&coverage.category, 48),
            coverage.mapped_count,
            coverage.total_hint.unwrap_or(0),
            marker_text(&coverage.label, 120)
        ));
    }

    let mut relevant_surfaces = state
        .surfaces
        .iter()
        .filter(|surface| {
            s1_read_target_matches_lane(
                lane_id,
                &surface.kind,
                &surface.category,
                &surface.label,
                &surface.target,
            ) || s2_lane_text_matches(
                    lane_id,
                    &[
                        &surface.category,
                        &surface.kind,
                        &surface.label,
                        &surface.target,
                    ],
                )
        })
        .collect::<Vec<_>>();
    relevant_surfaces.sort_by_key(|surface| usize::from(surface.kind != "read_target"));
    relevant_surfaces.truncate(max_surfaces);
    let fallback_surfaces = relevant_surfaces.is_empty();
    let surfaces = if fallback_surfaces {
        state.surfaces.iter().take(max_surfaces).collect::<Vec<_>>()
    } else {
        relevant_surfaces
    };
    for surface in surfaces {
        if surface.kind == "read_target" {
            lines.push(format!(
                "READ_TARGET% category={} target={} label={}",
                marker_token(&surface.category, 48),
                marker_target(&surface.target, &surface.label, 160),
                marker_text(&surface.label, 260)
            ));
        } else {
            lines.push(format!(
                "SURFACE% kind={} category={} target={} label={}",
                marker_token(&surface.kind, 48),
                marker_token(&surface.category, 48),
                marker_target(&surface.target, &surface.label, 120),
                marker_text(&surface.label, 120)
            ));
        }
    }
    for candidate in state
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.stage == "stage1"
                && s2_lane_text_matches(
                    lane_id,
                    &[&candidate.category, &candidate.target, &candidate.title],
                )
        })
        .take(max_surfaces / 2)
    {
        lines.push(format!(
            "OBLIGATION% id={} category={} target={} must={} evidence=s1_candidate_status:{:?}",
            marker_text(&candidate.id, 48),
            marker_token(&candidate.category, 48),
            marker_target(&candidate.target, &candidate.title, 120),
            marker_text(&candidate.title, 180),
            candidate.status
        ));
    }
    let mut shared_candidates = state
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.stage == "stage1"
                && !matches!(
                    candidate.status,
                    CandidateStatus::Rejected
                        | CandidateStatus::Duplicate
                        | CandidateStatus::OutOfScope
                )
                && !s2_lane_text_matches(
                    lane_id,
                    &[&candidate.category, &candidate.target, &candidate.title],
                )
                && s2_cross_lane_seed_matches(
                    lane_id,
                    &[&candidate.category, &candidate.target, &candidate.title],
                )
        })
        .collect::<Vec<_>>();
    shared_candidates.sort_by_key(|candidate| {
        (
            candidate.evidence_count,
            usize::from(candidate.source_confirmed),
            candidate.verification_count,
        )
    });
    shared_candidates.reverse();
    let mut shared_seed_count = 0;
    for candidate in shared_candidates.into_iter().take(max_surfaces / 8) {
        lines.push(format!(
            "OBLIGATION% id={} category={} target={} must={} evidence=s1_cross_lane_seed:evidence_count={}:source_confirmed={}",
            marker_text(&candidate.id, 48),
            marker_token(&candidate.category, 48),
            marker_target(&candidate.target, &candidate.title, 120),
            marker_text(&candidate.title, 180),
            candidate.evidence_count,
            candidate.source_confirmed
        ));
        shared_seed_count += 1;
    }
    if fallback_surfaces {
        lines.push("S1_SCOPE% fallback=global_surface_sample".to_string());
    } else if state.surfaces.len() > max_surfaces {
        lines.push(format!(
            "SURFACE_TRUNCATED% omitted={}",
            state.surfaces.len() - max_surfaces
        ));
    }
    if shared_seed_count > 0 {
        lines.push(format!("S1_SCOPE% cross_lane_seeded={shared_seed_count}"));
    }
    lines.join("\n")
}

fn compact_s2_source_packet(state: &RunbookState, lane_id: &str) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "SOURCE_PACKET% lane={} source=stage1-runbook mode=packet_first",
        lane_id
    ));

    let mut candidates = state
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.stage == "stage1"
                && !matches!(
                    candidate.status,
                    CandidateStatus::Rejected
                        | CandidateStatus::Duplicate
                        | CandidateStatus::OutOfScope
                )
                && (lane_id == quick_hits_lane_id()
                    || s2_lane_text_matches(
                        lane_id,
                        &[&candidate.category, &candidate.target, &candidate.title],
                    )
                    || s2_cross_lane_seed_matches(
                        lane_id,
                        &[&candidate.category, &candidate.target, &candidate.title],
                    ))
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|candidate| {
        (
            usize::from(candidate.source_confirmed),
            candidate.verification_count,
            candidate.evidence_count,
        )
    });
    candidates.reverse();

    for candidate in candidates {
        lines.push(format!(
            "SOURCE_FACT% id={} category={} target={} status={:?} evidence={} verified={} source={} hint={} title={}",
            marker_text(&candidate.id, 48),
            marker_token(&candidate.category, 48),
            marker_target(&candidate.target, &candidate.title, 120),
            candidate.status,
            candidate.evidence_count,
            candidate.verification_count,
            candidate.source_confirmed,
            source_read_hint(&marker_target(&candidate.target, &candidate.title, 120)),
            marker_text(&candidate.title, 220)
        ));
    }

    let mut source_surfaces = state
        .surfaces
        .iter()
        .filter(|surface| {
            s1_read_target_matches_lane(
                lane_id,
                &surface.kind,
                &surface.category,
                &surface.label,
                &surface.target,
            ) || lane_id == quick_hits_lane_id()
                || s2_lane_text_matches(
                    lane_id,
                    &[&surface.category, &surface.kind, &surface.label, &surface.target],
                )
        })
        .collect::<Vec<_>>();
    source_surfaces.sort_by_key(|surface| usize::from(surface.kind != "read_target"));
    let mut surface_count = 0;
    for surface in source_surfaces {
        if surface.kind == "read_target" {
            lines.push(format!(
                "READ_TARGET% category={} target={} label={}",
                marker_token(&surface.category, 48),
                marker_target(&surface.target, &surface.label, 160),
                marker_text(&surface.label, 320)
            ));
        } else {
            lines.push(format!(
                "SOURCE_ROUTE% kind={} category={} target={} label={}",
                marker_token(&surface.kind, 48),
                marker_token(&surface.category, 48),
                marker_target(&surface.target, &surface.label, 120),
                marker_text(&surface.label, 120)
            ));
        }
        surface_count += 1;
    }

    if lines.len() == 1 {
        lines.push("SOURCE_PACKET_EMPTY% reason=no-stage1-lane-facts".to_string());
    } else {
        lines.push(format!(
            "SOURCE_PACKET_SUMMARY% facts={} routes={}",
            lines
                .iter()
                .filter(|line| line.starts_with("SOURCE_FACT%"))
                .count(),
            surface_count
        ));
    }
    lines.join("\n")
}

fn source_read_hint(target: &str) -> String {
    let hint = target
        .split_whitespace()
        .find(|part| part.contains(':') || part.contains('/'))
        .unwrap_or(target);
    format!("line_window:{}", marker_text(hint, 96))
}

fn poc_next_for_claim(claim: &crate::runbook_claims::RunbookClaim) -> String {
    format!(
        "poc:{}",
        crate::runbook_claims::derive_poc_unit(
            &claim.category,
            &claim.title,
            &claim.target,
            &claim.precondition,
        )
    )
}

fn marker_text(text: &str, max_chars: usize) -> String {
    let normalized = text.split_whitespace().collect::<Vec<_>>().join(" ");
    truncate_chars(&normalized, max_chars).replace('\n', " ")
}

fn marker_token(text: &str, max_chars: usize) -> String {
    marker_text(text, max_chars)
        .split_whitespace()
        .next()
        .unwrap_or("unknown")
        .to_string()
}

fn marker_target(target: &str, fallback: &str, max_chars: usize) -> String {
    let clean = marker_text(target, max_chars);
    if !clean.is_empty() && clean != "unmapped-feature" {
        return clean;
    }
    fallback
        .split_whitespace()
        .find(|part| part.contains(':') || part.contains('/'))
        .map(|part| marker_text(part, max_chars))
        .filter(|part| !part.is_empty())
        .unwrap_or_else(|| "unmapped-feature".to_string())
}

fn compact_claim_packet(state: &RunbookState, max_items: usize) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "MERGE_PACKET% lanes={}/{} surfaces={} candidates={} claims={} findings={} publishable={} probed={} rejected={} needs_verify={}",
        state.s2_completed_lane_count(),
        s2_core_lane_ids().len(),
        state.surfaces.len(),
        state.candidates.len(),
        state.claims.len(),
        state.findings.len(),
        state.stats.publishable_claims,
        state.stats.probed,
        state.stats.rejected,
        state.stats.needs_verify,
    ));
    for claim in state.claims.iter().take(max_items) {
        lines.push(format!(
            "CLAIM% id={} category={} target={} status={} level={} severity={} title={} root_cause={} reason={} impact={} payload={} next={}",
            marker_text(&claim.id, 48),
            marker_token(&claim.category, 48),
            marker_target(&claim.target, &claim.title, 120),
            claim.status.as_marker(),
            claim.evidence_level.as_marker(),
            claim.severity.as_deref().unwrap_or("unknown"),
            marker_text(&claim.title, 160),
            marker_text(&claim.root_cause, 180),
            marker_text(&claim.positive_evidence, 180),
            marker_text(&claim.impact, 160),
            marker_text(&claim.payload, 120),
            marker_text(&poc_next_for_claim(claim), 120)
        ));
    }
    if state.claims.len() > max_items {
        lines.push(format!(
            "CLAIM_TRUNCATED% omitted={}",
            state.claims.len() - max_items
        ));
    }
    for candidate in state.candidates.iter().take(max_items / 2) {
        lines.push(format!(
            "CANDIDATE% id={} category={} target={} status={:?} title={}",
            marker_text(&candidate.id, 48),
            marker_token(&candidate.category, 48),
            marker_target(&candidate.target, &candidate.title, 120),
            candidate.status,
            marker_text(&candidate.title, 160)
        ));
    }
    for atom in state.attack_atoms.iter().take(max_items / 2) {
        lines.push(format!(
            "ATTACK_ATOM% id={} lane={} kind={} category={} target={} label={} bridge_keys={} claim={} confidence={}",
            marker_text(&atom.id, 48),
            marker_token(&atom.lane_id, 48),
            marker_token(&atom.kind, 48),
            marker_token(&atom.category, 48),
            marker_target(&atom.target, &atom.label, 120),
            marker_text(&atom.label, 120),
            marker_text(&atom.bridge_keys.join(","), 120),
            marker_text(atom.claim_id.as_deref().unwrap_or(""), 48),
            marker_text(&atom.confidence, 32)
        ));
    }
    for chain in state.chain_candidates.iter().take(max_items / 4) {
        lines.push(format!(
            "CHAIN_CANDIDATE% id={} status={} score={} atoms={} bridge_keys={} title={} impact={} verify_plan={}",
            chain.id,
            chain.status,
            chain.score,
            chain.atom_ids.join(","),
            chain.bridge_keys.join(","),
            chain.title,
            chain.impact,
            chain.verify_plan
        ));
    }
    lines
        .into_iter()
        .map(|line| line.replace('\n', " "))
        .collect::<Vec<_>>()
        .join("\n")
}

fn compact_s3_claim_pool(state: &RunbookState, max_items: usize) -> String {
    let mut claims = state
        .claims
        .iter()
        .filter(|claim| {
            claim.stage == "stage2" && claim_status_is_live(claim.status.as_marker())
        })
        .collect::<Vec<_>>();
    if claims.is_empty() {
        claims = state
            .claims
            .iter()
            .filter(|claim| {
                claim_status_is_live(claim.status.as_marker()) && claim_id_is_lane_claim(&claim.id)
            })
            .collect::<Vec<_>>();
    }

    let mut lines = Vec::new();
    lines.push(format!(
        "MERGE_PACKET% mode=s3_claim_pool source=stage2 claims={} included={} surfaces={} note=s3_consumes_claims_only",
        state.claims.len(),
        claims.len().min(max_items),
        state.surfaces.len(),
    ));
    for claim in claims.into_iter().take(max_items) {
        lines.push(format!(
            "CLAIM% id={} category={} target={} status={} level={} severity={} title={} reason={} impact={} next={}",
            marker_text(&claim.id, 48),
            marker_token(&claim.category, 48),
            marker_target(&claim.target, &claim.title, 140),
            claim.status.as_marker(),
            claim.evidence_level.as_marker(),
            claim.severity.as_deref().unwrap_or("unknown"),
            marker_text(&claim.title, 180),
            marker_text(&claim.positive_evidence, 200),
            marker_text(&claim.impact, 180),
            marker_text(&poc_next_for_claim(claim), 160),
        ));
    }
    lines
        .into_iter()
        .map(|line| line.replace('\n', " "))
        .collect::<Vec<_>>()
        .join("\n")
}

fn compact_s4_handoff_packet(state: &RunbookState, phase_id: &str, max_items: usize) -> String {
    let has_stage3_claims = state.claims.iter().any(|claim| {
        claim.stage == "stage3"
            && claim_status_is_live(claim.status.as_marker())
            && claim_id_is_lane_claim(&claim.id)
    });
    let claims = state
        .claims
        .iter()
        .filter(|claim| {
            claim_status_is_live(claim.status.as_marker())
                && claim_id_is_lane_claim(&claim.id)
                && (!has_stage3_claims || matches!(claim.stage.as_str(), "stage3" | "stage4"))
                && s4_claim_matches_phase(phase_id, &claim.category)
        })
        .collect::<Vec<_>>();

    let mut lines = Vec::new();
    lines.push(format!(
        "MERGE_PACKET% mode=s4_handoff phase={} source=stage3 claims={} included={} surfaces={} note=s4_consumes_canonical_claims_only",
        phase_id,
        state.claims.len(),
        claims.len().min(max_items),
        state.surfaces.len(),
    ));
    for claim in claims.into_iter().take(max_items) {
        lines.push(format!(
            "CLAIM% id={} category={} target={} status={} level={} severity={} title={} reason={} impact={} next={} payload={}",
            marker_text(&claim.id, 48),
            marker_token(&claim.category, 48),
            marker_target(&claim.target, &claim.title, 140),
            claim.status.as_marker(),
            claim.evidence_level.as_marker(),
            claim.severity.as_deref().unwrap_or("unknown"),
            marker_text(&claim.title, 180),
            marker_text(&claim.positive_evidence, 220),
            marker_text(&claim.impact, 180),
            marker_text(&poc_next_for_claim(claim), 160),
            marker_text(&claim.payload, 160),
        ));
    }
    for chain in state
        .chain_candidates
        .iter()
        .filter(|chain| {
            chain.stage == "stage3"
                && !matches!(chain.status.as_str(), "low_value" | "rejected" | "invalid")
        })
        .take(max_items / 5)
    {
        lines.push(format!(
            "CHAIN_CANDIDATE% id={} status={} score={} atoms={} bridge_keys={} title={} impact={} verify_plan={}",
            marker_text(&chain.id, 48),
            marker_token(&chain.status, 48),
            chain.score,
            marker_text(&chain.atom_ids.join(","), 140),
            marker_text(&chain.bridge_keys.join(","), 120),
            marker_text(&chain.title, 160),
            marker_text(&chain.impact, 180),
            marker_text(&chain.verify_plan, 220)
        ));
    }
    lines
        .into_iter()
        .map(|line| line.replace('\n', " "))
        .collect::<Vec<_>>()
        .join("\n")
}

fn s4_claim_matches_phase(phase_id: &str, category: &str) -> bool {
    let category = marker_token(category, 48);
    s4_phase_categories(phase_id).contains(&category.as_str())
}

fn s4_phase_categories(phase_id: &str) -> &'static [&'static str] {
    match phase_id {
        "s4_auth_authz_session_controls" => {
            &["auth", "authz", "session", "rate_limit", "anti_automation_bypass"]
        }
        "s4_injection_xss_controls" => &["injection", "xss", "cors_headers_tls"],
        "s4_files_ssrf_business_controls" => &[
            "file_upload_xxe",
            "traversal_lfi",
            "ssrf_redirect",
            "state_invariant_abuse",
            "secrets_config",
            "crypto",
            "observability_leak",
        ],
        "s4_regression_sweep" => &[
            "auth",
            "authz",
            "session",
            "rate_limit",
            "anti_automation_bypass",
            "injection",
            "xss",
            "cors_headers_tls",
            "file_upload_xxe",
            "traversal_lfi",
            "ssrf_redirect",
            "state_invariant_abuse",
            "secrets_config",
            "crypto",
            "observability_leak",
        ],
        _ => &[],
    }
}

fn claim_status_is_live(status: &str) -> bool {
    !matches!(status, "merged" | "discarded" | "blocked")
}

fn claim_id_is_lane_claim(id: &str) -> bool {
    matches!(
        id,
        value if value.starts_with("ID-")
            || value.starts_with("INJ-CAND-")
            || value.starts_with("XSS-CAND-")
            || value.starts_with("CORS-CAND-")
            || value.starts_with("ING-")
            || value.starts_with("LOGIC-CAND-")
            || value.starts_with("CONFIG-CAND-")
            || value.starts_with("QH-CAND-")
    )
}
