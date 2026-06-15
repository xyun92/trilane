use std::collections::BTreeMap;

const CHAIN_SYNTHESIS_MIN_SCORE: u16 = 55;
const CHAIN_SYNTHESIS_MAX_ATOMS_PER_BRIDGE: usize = 12;

impl RunbookState {
    fn extract_attack_atom_marker(&mut self, stage: &str, line: &str) {
        let label = marker_value(line, "label")
            .or_else(|| marker_value(line, "title"))
            .or_else(|| marker_value(line, "target"))
            .unwrap_or_else(|| strip_marker(line).to_string());
        let target = marker_value(line, "target").unwrap_or_else(|| label.clone());
        let kind = marker_value(line, "kind").unwrap_or_else(|| infer_atom_kind(&label, &target));
        let category = marker_value(line, "category").unwrap_or_else(|| infer_category(&label));
        let evidence = marker_value(line, "evidence")
            .or_else(|| marker_value(line, "reason"))
            .unwrap_or_else(|| strip_marker(line).to_string());
        let bridges = marker_value(line, "bridge_keys")
            .or_else(|| marker_value(line, "bridge"))
            .map(|value| split_marker_list(&value))
            .unwrap_or_else(|| infer_bridge_keys(&format!("{label}\n{target}\n{evidence}")));
        self.upsert_attack_atom(AttackAtomSeed {
            id: marker_value(line, "id"),
            stage,
            lane_id: marker_value(line, "lane")
                .or_else(|| marker_value(line, "lane_id"))
                .unwrap_or_default(),
            kind,
            category,
            target,
            label,
            claim_id: marker_value(line, "claim").or_else(|| marker_value(line, "claim_id")),
            bridge_keys: bridges,
            evidence,
            confidence: marker_value(line, "confidence").unwrap_or_else(|| "medium".to_string()),
        });
    }

    fn extract_chain_candidate_marker(&mut self, stage: &str, line: &str) {
        let title = marker_value(line, "title")
            .or_else(|| marker_value(line, "target"))
            .unwrap_or_else(|| strip_marker(line).to_string());
        let atom_ids = marker_value(line, "atom_ids")
            .or_else(|| marker_value(line, "atoms"))
            .map(|value| split_marker_list(&value))
            .unwrap_or_default();
        let bridge_keys = marker_value(line, "bridge_keys")
            .or_else(|| marker_value(line, "bridge"))
            .map(|value| split_marker_list(&value))
            .unwrap_or_else(|| infer_bridge_keys(&title));
        let score = marker_value(line, "score")
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or_else(|| score_chain_candidate(&title, &bridge_keys, atom_ids.len()));
        self.upsert_chain_candidate(ChainCandidateSeed {
            id: marker_value(line, "id"),
            stage,
            title,
            status: marker_value(line, "status").unwrap_or_else(|| "candidate".to_string()),
            impact: marker_value(line, "impact").unwrap_or_default(),
            atom_ids,
            bridge_keys,
            verify_plan: marker_value(line, "verify_plan")
                .or_else(|| marker_value(line, "plan"))
                .unwrap_or_default(),
            score,
        });
    }

    fn extract_chain_verify_marker(&mut self, stage: &str, line: &str) {
        let id = marker_value(line, "id").unwrap_or_else(|| "unlinked-chain".to_string());
        let status = marker_value(line, "status").unwrap_or_else(|| "verified".to_string());
        let result = marker_value(line, "result")
            .or_else(|| marker_value(line, "evidence"))
            .unwrap_or_else(|| strip_marker(line).to_string());
        if let Some(chain) = self
            .chain_candidates
            .iter_mut()
            .find(|chain| chain.id == id)
        {
            chain.stage = stage.to_string();
            chain.status = normalize_chain_status(&status);
            chain.updated_at = now();
        }
        self.record_evidence(stage, "chain_verify", id, truncate(&result, 700));
        self.touch();
    }

    fn synthesize_attack_graph(&mut self, stage: &str) {
        self.materialize_claim_atoms(stage);
        self.materialize_surface_obligation_atoms(stage);
        self.synthesize_chain_candidates(stage);
    }

    fn materialize_claim_atoms(&mut self, stage: &str) {
        let claims = self.claims.clone();
        for claim in claims
            .iter()
            .filter(|claim| !matches!(claim.status, ClaimStatus::Discarded | ClaimStatus::Merged))
            .take(MAX_ATTACK_ATOMS)
        {
            let text = format!(
                "{}\n{}\n{}\n{}\n{}\n{}",
                claim.category,
                claim.title,
                claim.target,
                claim.code_path,
                claim.root_cause,
                claim.impact
            );
            let bridge_keys = infer_bridge_keys(&text);
            if bridge_keys.is_empty() {
                continue;
            }
        self.upsert_attack_atom(AttackAtomSeed {
                id: Some(format!("ATOM-{}", normalize_id(&claim.id))),
                stage,
                lane_id: lane_for_category(&claim.category).to_string(),
                kind: infer_atom_kind(&claim.title, &claim.target),
                category: claim.category.clone(),
                target: first_non_empty_owned(&[&claim.code_path, &claim.target]),
                label: claim.title.clone(),
                claim_id: Some(claim.id.clone()),
                bridge_keys,
                evidence: first_non_empty_owned(&[&claim.positive_evidence, &claim.root_cause]),
                confidence: confidence_from_claim_status(&claim.status).to_string(),
            });
        }
    }

    fn materialize_surface_obligation_atoms(&mut self, stage: &str) {
        let surfaces = self.surfaces.clone();
        for surface in surfaces.iter().take(MAX_SURFACES) {
            let text = format!(
                "{}\n{}\n{}\n{}",
                surface.kind, surface.category, surface.label, surface.target
            );
            let bridge_keys = infer_bridge_keys(&text);
            if bridge_keys.is_empty() || !surface_needs_cross_lane_obligation(&text) {
                continue;
            }
            self.upsert_attack_atom(AttackAtomSeed {
                id: Some(format!("ATOM-{}", normalize_id(&surface.id))),
                stage,
                lane_id: lane_for_category(&surface.category).to_string(),
                kind: infer_atom_kind(&surface.label, &surface.target),
                category: surface.category.clone(),
                target: surface.target.clone(),
                label: surface.label.clone(),
                claim_id: None,
                bridge_keys,
                evidence: "surface-derived cross-lane obligation".to_string(),
                confidence: "signal".to_string(),
            });
        }
    }

    fn synthesize_chain_candidates(&mut self, stage: &str) {
        let mut by_bridge: BTreeMap<String, Vec<RunbookAttackAtom>> = BTreeMap::new();
        for atom in &self.attack_atoms {
            for bridge in &atom.bridge_keys {
                by_bridge
                    .entry(bridge.clone())
                    .or_default()
                    .push(atom.clone());
            }
        }

        let mut seeds = Vec::new();
        for (bridge, mut atoms) in by_bridge {
            atoms.sort_by_key(atom_rank);
            atoms.reverse();
            atoms.truncate(CHAIN_SYNTHESIS_MAX_ATOMS_PER_BRIDGE);
            for left_index in 0..atoms.len() {
                for right_index in left_index + 1..atoms.len() {
                    let left = &atoms[left_index];
                    let right = &atoms[right_index];
                    if left.id == right.id || left.lane_id == right.lane_id {
                        continue;
                    }
                    let Some(chain) = build_chain_seed(stage, &bridge, left, right) else {
                        continue;
                    };
                    if chain.score >= CHAIN_SYNTHESIS_MIN_SCORE {
                        seeds.push(chain);
                    }
                }
            }
        }
        seeds.sort_by_key(|seed| seed.score);
        seeds.reverse();
        seeds.truncate(MAX_CHAIN_CANDIDATES);
        for seed in seeds {
            self.upsert_chain_candidate(seed);
        }
    }

    fn upsert_attack_atom(&mut self, seed: AttackAtomSeed<'_>) -> String {
        let mut bridge_keys = seed
            .bridge_keys
            .into_iter()
            .map(|key| normalize_bridge_key(&key))
            .filter(|key| !key.is_empty())
            .collect::<Vec<_>>();
        bridge_keys.sort();
        bridge_keys.dedup();
        let id = seed.id.unwrap_or_else(|| {
            format!(
                "ATOM-{}-{}-{}",
                normalize_id(&seed.kind),
                normalize_id(&seed.category),
                normalize_id(&seed.target)
            )
        });
        let category = self.canonical_coverage_category(&seed.category);
        if let Some(atom) = self.attack_atoms.iter_mut().find(|atom| atom.id == id) {
            atom.stage = seed.stage.to_string();
            if !seed.lane_id.trim().is_empty() {
                atom.lane_id = seed.lane_id;
            }
            atom.kind = seed.kind;
            atom.category = category;
            atom.target = truncate(&seed.target, 180);
            atom.label = truncate(&seed.label, 160);
            if seed.claim_id.is_some() {
                atom.claim_id = seed.claim_id;
            }
            atom.bridge_keys = merge_string_sets(&atom.bridge_keys, &bridge_keys);
            atom.evidence = append_compact(&atom.evidence, &seed.evidence, 700);
            atom.confidence = stronger_confidence(&atom.confidence, &seed.confidence);
            atom.updated_at = now();
        } else {
            self.attack_atoms.push(RunbookAttackAtom {
                id: id.clone(),
                stage: seed.stage.to_string(),
                lane_id: seed.lane_id,
                kind: seed.kind,
                category,
                target: truncate(&seed.target, 180),
                label: truncate(&seed.label, 160),
                claim_id: seed.claim_id,
                bridge_keys,
                evidence: truncate(&seed.evidence, 700),
                confidence: seed.confidence,
                updated_at: now(),
            });
            if self.attack_atoms.len() > MAX_ATTACK_ATOMS {
                self.attack_atoms.remove(0);
            }
        }
        self.touch();
        id
    }

    fn upsert_chain_candidate(&mut self, seed: ChainCandidateSeed<'_>) -> String {
        let mut atom_ids = seed.atom_ids;
        atom_ids.sort();
        atom_ids.dedup();
        let mut bridge_keys = seed
            .bridge_keys
            .into_iter()
            .map(|key| normalize_bridge_key(&key))
            .filter(|key| !key.is_empty())
            .collect::<Vec<_>>();
        bridge_keys.sort();
        bridge_keys.dedup();
        let id = seed.id.unwrap_or_else(|| {
            format!(
                "CHAIN-{}-{}",
                normalize_id(&bridge_keys.join("-")),
                normalize_id(&atom_ids.join("-"))
            )
        });
        if let Some(chain) = self
            .chain_candidates
            .iter_mut()
            .find(|chain| chain.id == id)
        {
            chain.stage = seed.stage.to_string();
            chain.title = truncate(&seed.title, 180);
            chain.status = normalize_chain_status(&seed.status);
            chain.impact = prefer_longer(&chain.impact, &seed.impact, 260);
            chain.atom_ids = merge_string_sets(&chain.atom_ids, &atom_ids);
            chain.bridge_keys = merge_string_sets(&chain.bridge_keys, &bridge_keys);
            if !seed.verify_plan.trim().is_empty() {
                chain.verify_plan = truncate(&seed.verify_plan, 400);
            }
            chain.score = chain.score.max(seed.score);
            chain.updated_at = now();
        } else {
            self.chain_candidates.push(RunbookChainCandidate {
                id: id.clone(),
                stage: seed.stage.to_string(),
                title: truncate(&seed.title, 180),
                status: normalize_chain_status(&seed.status),
                impact: truncate(&seed.impact, 260),
                atom_ids,
                bridge_keys,
                verify_plan: truncate(&seed.verify_plan, 400),
                score: seed.score,
                updated_at: now(),
            });
            self.chain_candidates.sort_by_key(|chain| chain.score);
            self.chain_candidates.reverse();
            if self.chain_candidates.len() > MAX_CHAIN_CANDIDATES {
                self.chain_candidates.truncate(MAX_CHAIN_CANDIDATES);
            }
        }
        self.touch();
        id
    }
}

struct AttackAtomSeed<'a> {
    id: Option<String>,
    stage: &'a str,
    lane_id: String,
    kind: String,
    category: String,
    target: String,
    label: String,
    claim_id: Option<String>,
    bridge_keys: Vec<String>,
    evidence: String,
    confidence: String,
}

struct ChainCandidateSeed<'a> {
    id: Option<String>,
    stage: &'a str,
    title: String,
    status: String,
    impact: String,
    atom_ids: Vec<String>,
    bridge_keys: Vec<String>,
    verify_plan: String,
    score: u16,
}

fn build_chain_seed<'a>(
    stage: &'a str,
    bridge: &str,
    left: &RunbookAttackAtom,
    right: &RunbookAttackAtom,
) -> Option<ChainCandidateSeed<'a>> {
    if !is_bridgeable_pair(left, right) {
        return None;
    }
    let title = format!("{} -> {}", left.label, right.label);
    let impact = infer_chain_impact(bridge, left, right);
    let score = score_chain_candidate(&title, &[bridge.to_string()], 2)
        .saturating_add(atom_rank(left) as u16)
        .saturating_add(atom_rank(right) as u16)
        .min(100);
    Some(ChainCandidateSeed {
        id: None,
        stage,
        title,
        status: "candidate".to_string(),
        impact,
        atom_ids: vec![left.id.clone(), right.id.clone()],
        bridge_keys: vec![bridge.to_string()],
        verify_plan: format!(
            "Verify in an isolated workflow: establish '{}' first, snapshot state, then attempt '{}' and roll back or use disposable accounts/objects.",
            left.label, right.label
        ),
        score,
    })
}

fn is_bridgeable_pair(left: &RunbookAttackAtom, right: &RunbookAttackAtom) -> bool {
    let left_kind = left.kind.as_str();
    let right_kind = right.kind.as_str();
    matches!(
        (left_kind, right_kind),
        ("secret", "primitive")
            | ("primitive", "secret")
            | ("secret", "side_effect")
            | ("side_effect", "secret")
            | ("guard", "primitive")
            | ("primitive", "guard")
            | ("invariant", "primitive")
            | ("primitive", "invariant")
            | ("surface", "primitive")
            | ("primitive", "surface")
            | ("sink", "primitive")
            | ("primitive", "sink")
    )
}

fn infer_chain_impact(
    bridge: &str,
    left: &RunbookAttackAtom,
    right: &RunbookAttackAtom,
) -> String {
    let text = format!("{bridge}\n{}\n{}", left.label, right.label).to_ascii_lowercase();
    if contains_any(&text, &["jwt", "token", "admin", "role"]) {
        "Privilege escalation or authentication bypass through chained trust material.".to_string()
    } else if contains_any(&text, &["wallet", "coupon", "payment", "order"]) {
        "Business state invariant abuse through chained workflow primitives.".to_string()
    } else if contains_any(&text, &["upload", "file", "path", "lfi", "zip"]) {
        "File-system impact through parser or path handling plus a secondary sink.".to_string()
    } else if contains_any(&text, &["xss", "render", "header", "profile"]) {
        "Browser trust or account action chain through a render sink.".to_string()
    } else {
        "Cross-lane exploit chain candidate with multi-step security impact.".to_string()
    }
}

fn infer_atom_kind(label: &str, target: &str) -> String {
    let text = format!("{label}\n{target}").to_ascii_lowercase();
    if contains_any(&text, &["secret", "key", "salt", "token", "jwt", "credential"]) {
        "secret"
    } else if contains_any(&text, &["auth", "guard", "middleware", "owner", "role"]) {
        "guard"
    } else if contains_any(&text, &["wallet", "coupon", "payment", "order", "price", "quantity"]) {
        "invariant"
    } else if contains_any(&text, &["eval", "sink", "render", "fetch", "redirect", "write", "read"]) {
        "sink"
    } else if contains_any(&text, &["bypass", "injection", "xss", "ssrf", "traversal", "idor"]) {
        "primitive"
    } else {
        "surface"
    }
    .to_string()
}

fn infer_bridge_keys(text: &str) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    let mut keys = Vec::new();
    for (needle, key) in [
        ("jwt", "token"),
        ("token", "token"),
        ("hashids", "token"),
        ("continue", "token"),
        ("key", "secret"),
        ("secret", "secret"),
        ("salt", "secret"),
        ("role", "identity"),
        ("admin", "identity"),
        ("user", "identity"),
        ("basket", "object"),
        ("order", "object"),
        ("wallet", "money"),
        ("coupon", "money"),
        ("payment", "money"),
        ("price", "money"),
        ("upload", "file"),
        ("zip", "file"),
        ("path", "file"),
        ("lfi", "file"),
        ("layout", "file"),
        ("xss", "browser"),
        ("render", "browser"),
        ("header", "browser"),
        ("profile", "browser"),
        ("middleware", "guard"),
        ("auth", "guard"),
        ("rate", "guard"),
    ] {
        if lower.contains(needle) {
            keys.push(key.to_string());
        }
    }
    keys.sort();
    keys.dedup();
    keys
}

fn surface_needs_cross_lane_obligation(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    contains_any(
        &lower,
        &[
            "wallet",
            "coupon",
            "payment",
            "order",
            "checkout",
            "upload",
            "yaml",
            "zip",
            "xml",
            "swagger",
            "openapi",
            "metrics",
            "debug",
            "config",
            "key",
            "token",
            "jwt",
            "2fa",
            "captcha",
            "security-question",
        ],
    )
}

fn lane_for_category(category: &str) -> &'static str {
    match category {
        "auth" | "authz" | "session" | "rate_limit" => "identity_engine",
        "injection" | "xss" | "cors_headers_tls" => "injection_engine",
        "file_upload_xxe" | "traversal_lfi" | "ssrf_redirect" => "ingress_engine",
        "state_invariant_abuse" | "anti_automation_bypass" => "logic_engine",
        "secrets_config" | "observability_leak" | "crypto" => "config_engine",
        _ => "unknown",
    }
}

fn split_marker_list(value: &str) -> Vec<String> {
    value
        .split([',', '|', ';'])
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

fn merge_string_sets(existing: &[String], incoming: &[String]) -> Vec<String> {
    let mut merged = existing
        .iter()
        .chain(incoming.iter())
        .map(|value| value.to_string())
        .filter(|value| !value.trim().is_empty())
        .collect::<Vec<_>>();
    merged.sort();
    merged.dedup();
    merged
}

fn normalize_bridge_key(value: &str) -> String {
    normalize_id(value).replace('-', "_")
}

fn normalize_chain_status(value: &str) -> String {
    match normalize_id(value).as_str() {
        "verified" | "verify" | "confirmed" | "passed" => "verified",
        "rejected" | "discarded" | "failed" | "blocked" => "rejected",
        "planned" | "candidate" | "hint" | "needs-poc" | "needs_poc" => "candidate",
        _ => "candidate",
    }
    .to_string()
}

fn score_chain_candidate(title: &str, bridge_keys: &[String], atom_count: usize) -> u16 {
    let lower = title.to_ascii_lowercase();
    let mut score = 35u16.saturating_add((atom_count as u16).saturating_mul(8));
    for key in bridge_keys {
        score = score.saturating_add(match key.as_str() {
            "token" | "secret" | "identity" | "money" => 14,
            "file" | "guard" | "object" => 10,
            "browser" => 8,
            _ => 4,
        });
    }
    if contains_any(&lower, &["admin", "forg", "bypass", "wallet", "rce", "takeover"]) {
        score = score.saturating_add(12);
    }
    score.min(100)
}

fn atom_rank(atom: &RunbookAttackAtom) -> usize {
    let confidence = match atom.confidence.as_str() {
        "high" | "verified" | "publishable" => 40,
        "medium" | "source-backed" => 24,
        _ => 12,
    };
    let kind = match atom.kind.as_str() {
        "secret" | "primitive" | "invariant" => 25,
        "guard" | "sink" => 18,
        _ => 8,
    };
    confidence + kind + atom.bridge_keys.len()
}

fn confidence_from_claim_status(status: &ClaimStatus) -> &'static str {
    match status {
        ClaimStatus::Publishable | ClaimStatus::Weaponized | ClaimStatus::Verified => "high",
        ClaimStatus::Corroborated | ClaimStatus::Anchored | ClaimStatus::Armed => "medium",
        ClaimStatus::Running | ClaimStatus::Seed => "signal",
        ClaimStatus::Blocked | ClaimStatus::Discarded | ClaimStatus::Merged => "low",
    }
}

fn stronger_confidence(left: &str, right: &str) -> String {
    if confidence_rank(right) >= confidence_rank(left) {
        right.to_string()
    } else {
        left.to_string()
    }
}

fn confidence_rank(value: &str) -> usize {
    match value {
        "high" | "verified" | "publishable" => 3,
        "medium" | "source-backed" => 2,
        "signal" | "low" => 1,
        _ => 1,
    }
}

fn first_non_empty_owned(values: &[&str]) -> String {
    values
        .iter()
        .find(|value| !value.trim().is_empty())
        .map(|value| (*value).to_string())
        .unwrap_or_default()
}
