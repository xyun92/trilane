fn phase_context(phase: &WorkflowPhase, state: &RunbookState) -> String {
    if phase.id == "s5_final_revision" {
        return format!(
            "\nFINAL_REVISION_CONTRACT%\n\
             - Output-only correction pass. Do not call tools, inspect source, run commands, or start a new audit.\n\
             - REVIEW_CONTEXT is advisory. Critically apply only ledger-supported corrections to the already-adjudicated S5 draft.\n\
             - Emit exactly one RUNBOOK% S5 Final Revision line, then the replacement canonical FINDING% set.\n\
             - Preserve recall: do not collapse the replacement set to only the highest-confidence/core findings.\n\
             - Accept drop/merge only for same-family duplicates, ledger contradictions, out-of-scope items, placeholders, or non-security observations.\n\
             - For missing live proof, weak payloads, or uncertain impact, downgrade/rewrite to source-backed or needs-poc instead of deleting.\n\
             - Do not invent findings beyond REVIEW% add_check items with an evidence_ref already present in RUNBOOK_CONTEXT.\n\
             - The backend treats this FINDING% set as the replacement final set; ordinary markdown tables are ignored for counting.\n\n\
             RUNBOOK_CONTEXT%\n{}\n\nREVIEW_CONTEXT%\n{}\n",
            compact_claim_packet(state, /*max_items*/ 120),
            compact_s5_review_packet(state, /*max_items*/ 80),
        );
    }
    if !matches!(phase.stage_code, "S3" | "S4" | "S5") {
        return String::new();
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
     - Obligation rule: when a feature matches a prior family, emit OBLIGATION% first; close it with CLAIM%/PROBE%/CONTROL%/REJECTED%/COVERAGE% not_applicable."
}

fn s2_lane_batch(
    phase: &WorkflowPhase,
    objective: &str,
    state: &RunbookState,
    is_repair: bool,
) -> WorkflowLaneBatch {
    let mut lanes = if is_repair {
        state.s2_missing_lanes()
    } else {
        s2_lane_ids()
            .iter()
            .map(|lane| (*lane).to_string())
            .collect::<Vec<_>>()
    };
    if lanes.is_empty() {
        lanes = s2_lane_ids()
            .iter()
            .map(|lane| (*lane).to_string())
            .collect::<Vec<_>>();
    }
    WorkflowLaneBatch {
        phase_id: phase.id.to_string(),
        stage_id: phase.stage_id.to_string(),
        title: phase.title.to_string(),
        lanes: lanes
            .into_iter()
            .map(|lane_id| {
                let s1_ledger = compact_s1_lane_ledger(state, &lane_id, /*max_surfaces*/ 56);
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

pub fn s2_lane_ids() -> [&'static str; 6] {
    [
        "identity_engine",
        "injection_engine",
        "ingress_engine",
        "logic_engine",
        "config_engine",
        "quick_hits_engine",
    ]
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
            "Engine categories: cross-lane low-hanging fruit mapped back into the existing TriLane taxonomy. Run a short rg-first recovery pass for high-yield missed families: raw SQL/query interpolation, eval/vm/template sinks, res.jsonp/callback and DOM/browser sinks, wildcard CORS/header gaps, exposed /metrics/docs/logs/config/static files, JWT alg/key confusion, hardcoded secrets/weak hashes, mass assignment, IDOR in basket/order/payment/review/export, coupon/wallet/payment invariant abuse, reset/security-answer/CAPTCHA/rate-limit gaps, upload/parser/traversal, SSRF, and open redirect substring/allowlist bypasses. Keep it lightweight and ledger-first; do not repeat every trace from the five deep lanes."
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
         OUTPUT_CONTRACT%\n\
         - You are a workflow-owned child lane. Do not write the final report.\n\
         - Read focused source files/routes for this lane. Prefer rg over broad cat.\n\
         - Emit many compact markers, not prose-only summaries.\n\
         - Use FEATURE%, OBLIGATION%, SURFACE%, CANDIDATE%, CLAIM%, PROBE%, CONTROL%, REJECTED%, DUPLICATE%, MERGE%, and provisional FINDING% when evidence supports it.\n\
         - Also emit ATTACK_ATOM% for reusable exploit facts: kind=<surface|guard|primitive|secret|invariant|sink|side_effect> category=<domain> target=<route/file/object> label=<short> bridge_keys=<comma-list> claim=<claim-id> evidence=<short> confidence=<signal|medium|high>.\n\
         - Close every relevant S1 OBLIGATION% in your lane: upgrade to CLAIM%, disprove with REJECTED%, or emit COVERAGE% not_applicable with evidence.\n\
         - The S1 ledger may include a few cross-lane weak-signal OBLIGATION% seeds. Do not discard them solely because the taxonomy looks adjacent; inspect the nearest helper/route/middleware file first, then reject with evidence if they truly do not belong.\n\
         - For every high-value claim include source/root cause, route or file:line, exploit primitive, expected impact, and a negative-control idea.\n\
         - Preserve recall: do not keep only top 5 findings; emit all credible candidates in this lane.\n\
         - Scheduler SUBAGENT% completion does not count as your lane report; a core lane that ends without a non-empty LANE_REPORT% is incomplete and will be repaired.\n\
         - Finish with exactly one LANE_REPORT% lane={lane_id} status=done claims=<n> candidates=<n> note=<short> line.\n",
        s2_lane_title(lane_id),
        objective.trim(),
        s1_ledger,
        cve_prior_contract(),
        s2_lane_task(lane_id)
    )
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
            lane_id: "final_report_review".to_string(),
            title: "S5 advisory final report review".to_string(),
            prompt: s5_review_lane_prompt(objective, state, is_repair),
        }],
        is_repair,
    }
}

fn s5_review_lane_prompt(objective: &str, state: &RunbookState, is_repair: bool) -> String {
    let repair = if is_repair {
        "\nWORKFLOW_REPAIR% The previous review lane failed or did not return REVIEW_REPORT%. Re-read only RUNBOOK_CONTEXT and FINAL_REPORT_DRAFT, then emit the missing REVIEW%/REVIEW_REPORT% ledger now. Do not run tools.\n"
    } else {
        ""
    };
    format!(
        "AUDIT_MODE% TRILANE\n\
         WORKFLOW% id=trilane-workflow phase=s5_adversarial_review stage=S5 lane=final_report_review repair={is_repair}\n\
         LANE% id=final_report_review title=\"S5 advisory final report review\"\n\
         USER_OBJECTIVE%\n{}\n\
         {repair}\n\
         RUNBOOK_CONTEXT%\n{}\n\n\
         FINAL_REPORT_DRAFT%\n{}\n\n\
         REVIEW_TASK%\n\
         Review the draft report after S5 adjudication. You are a bounded advisory report reviewer, not a new auditor and not the final decision-maker. Do not run tools, inspect source files, perform fresh probing, do a broad new scan, or rewrite the report yourself. Focus only on duplicate finding families, clear false positives, unsupported severity inflation, missing high-value families already supported by RUNBOOK_CONTEXT, and unclear exploit/evidence wording. Favor recall-preserving advice: when evidence is incomplete but source/root-cause impact is plausible, recommend downgrade/rewrite/needs-poc rather than drop.\n\n\
         OUTPUT_CONTRACT%\n\
         - Emit compact machine-readable review comments only: REVIEW% action=<keep|merge|drop|downgrade|upgrade|add_check|rewrite> target=<VULN-id-or-claim-id-or-family> reason=<short> evidence_ref=<claim-or-finding-id> confidence=<high|medium|low>.\n\
         - High-confidence REVIEW% comments must be directly actionable by the main agent without extra source reads.\n\
         - Use REVIEW% action=drop only for same-family duplicates, ledger-contradicted claims, out-of-scope items, placeholders, or non-security observations.\n\
         - Do not recommend dropping solely because a finding lacks live proof, a polished payload, or full negative-control evidence; recommend downgrade/rewrite/needs-poc instead.\n\
         - Do not recommend dropping a family merely because one attempted payload path failed when the same root cause still supports a plausible weaker finding.\n\
         - Do not create new findings unless they are already supported by RUNBOOK_CONTEXT evidence; cite that claim or finding id in evidence_ref.\n\
         - Do not include markdown report sections, vulnerability tables, exploit writeups, shell commands, or source snippets.\n\
         - Finish with exactly one REVIEW_REPORT% lane=final_report_review status=done comments=<n> critical=<n> note=<short> line.\n",
        objective.trim(),
        compact_claim_packet(state, /*max_items*/ 120),
        truncate_chars(&state.final_report_markdown(), 45_000),
    )
}

fn compact_s5_review_packet(state: &RunbookState, max_items: usize) -> String {
    let mut lines = Vec::new();
    let mut has_review_marker = false;
    for lane in &state.lanes {
        if lane.lane_id == "final_report_review" {
            lines.push(format!(
                "LANE_REPORT% lane={} status={} claims={} thread_id={} note={}",
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
        lines.push("REVIEW_REPORT% lane=final_report_review status=missing comments=0 critical=0 note=no review comments captured".to_string());
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
    let lane_categories = s2_lane_categories(lane_id);
    for coverage in state.coverage.iter().filter(|coverage| {
        coverage.status != crate::runbook::CoverageStatus::Pending
            && lane_categories
                .iter()
                .any(|category| coverage.category == *category)
    }) {
        lines.push(format!(
            "COVERAGE% category={} mapped={} total={} label={}",
            coverage.category,
            coverage.mapped_count,
            coverage.total_hint.unwrap_or(0),
            coverage.label
        ));
    }

    let relevant_surfaces = state
        .surfaces
        .iter()
        .filter(|surface| {
            s2_lane_text_matches(
                lane_id,
                &[&surface.category, &surface.kind, &surface.label, &surface.target],
            )
        })
        .take(max_surfaces)
        .collect::<Vec<_>>();
    let fallback_surfaces = relevant_surfaces.is_empty();
    let surfaces = if fallback_surfaces {
        state.surfaces.iter().take(max_surfaces).collect::<Vec<_>>()
    } else {
        relevant_surfaces
    };
    for surface in surfaces {
        lines.push(format!(
            "SURFACE% kind={} category={} target={} label={}",
            surface.kind, surface.category, surface.target, surface.label
        ));
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
            candidate.id, candidate.category, candidate.target, candidate.title, candidate.status
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
            candidate.id,
            candidate.category,
            candidate.target,
            candidate.title,
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

fn compact_claim_packet(state: &RunbookState, max_items: usize) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "MERGE_PACKET% lanes={}/{} surfaces={} candidates={} claims={} findings={} publishable={} probed={} rejected={} needs_verify={}",
        state.s2_completed_lane_count(),
        s2_lane_ids().len(),
        state.surfaces.len(),
        state.candidates.len(),
        state.claims.len(),
        state.findings.len(),
        state.stats.publishable_claims,
        state.stats.probed,
        state.stats.rejected,
        state.stats.needs_verify,
    ));
    for lane in &state.lanes {
        lines.push(format!(
            "LANE_REPORT% lane={} status={} claims={} thread_id={} note={}",
            lane.lane_id, lane.status, lane.claim_count, lane.thread_id, lane.summary
        ));
    }
    for claim in state.claims.iter().take(max_items) {
        lines.push(format!(
            "CLAIM% id={} category={} target={} status={} level={} severity={} title={} root_cause={} impact={} payload={}",
            claim.id,
            claim.category,
            claim.target,
            claim.status.as_marker(),
            claim.evidence_level.as_marker(),
            claim.severity.as_deref().unwrap_or("unknown"),
            claim.title,
            claim.root_cause,
            claim.impact,
            claim.payload
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
            candidate.id, candidate.category, candidate.target, candidate.status, candidate.title
        ));
    }
    for atom in state.attack_atoms.iter().take(max_items / 2) {
        lines.push(format!(
            "ATTACK_ATOM% id={} lane={} kind={} category={} target={} label={} bridge_keys={} claim={} confidence={}",
            atom.id,
            atom.lane_id,
            atom.kind,
            atom.category,
            atom.target,
            atom.label,
            atom.bridge_keys.join(","),
            atom.claim_id.as_deref().unwrap_or(""),
            atom.confidence
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
