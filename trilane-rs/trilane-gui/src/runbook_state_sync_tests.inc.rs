#[test]
fn backticked_s5_final_revision_markers_are_the_explicit_final_set() {
    let mut state = RunbookState::default();
    state.start_turn("test target", AuditMode::Lab);
    state.record_agent_message(
        "SURFACE% kind=endpoint category=injection target=/rest/user/login label=login route\n\
         CANDIDATE% id=INJ-CAND-01 category=injection target=/rest/user/login title=Login SQL injection\n\
         RUNBOOK% S3 Summary: merged findings\nRUNBOOK% S4 Fuzz: variant probes complete\n\
         PROBE% id=INJ-CAND-01 result=control returned expected responses\n\
         CONTROL% id=INJ-CAND-01 negative=baseline rejected invalid input\n\
         `RUNBOOK% S5 Final Revision`\n\
         `FINDING% id=F-001 severity=medium code_path=lib/insecurity.ts:73 confidence=high title=MD5 password hashing evidence=source returned MD5 hash payload=hashcat -m 0 hashes.txt`\n\
         `FINDING% id=F-002 severity=medium code_path=lib/insecurity.ts:74 confidence=high title=Hardcoded HMAC key evidence=source returned static HMAC key payload=node hmac.js`\n\
         `FINDING% id=F-003 severity=medium code_path=lib/insecurity.ts:151 confidence=high title=deluxeToken HMAC key reuse evidence=source returned reusable token material payload=node deluxe.js`",
    );
    state.complete();
    assert_eq!(state.status, RunbookStatus::Completed);
    assert_eq!(state.final_findings.len(), 3);
    assert!(state
        .final_findings
        .iter()
        .any(|finding| finding.title == "Hardcoded HMAC key"));
}

#[test]
fn obligation_markers_materialize_candidates_claims_and_coverage() {
    let mut state = RunbookState::default();
    state.start_turn("test target", AuditMode::Lab);
    state.record_agent_message(
        "FEATURE% kind=capability category=auth feature=password-reset target=routes/resetPassword.ts label=password reset\n\
         OBLIGATION% id=AUTH-OBL-01 category=auth feature=password-reset target=routes/resetPassword.ts must=check reset oracle, token entropy, and account enumeration evidence=reset flow discovered in source\n\
         OBLIGATION% id=AUTH-OBL-02 category=authz feature=data-export target=routes/dataExport.ts must=check cross-user export and ownership enforcement evidence=export flow discovered in source",
    );

    assert!(state
        .surfaces
        .iter()
        .any(|surface| surface.kind == "capability" && surface.label == "password reset"));
    assert!(state
        .candidates
        .iter()
        .any(|candidate| candidate.id == "AUTH-OBL-01"));
    assert!(state
        .claims
        .iter()
        .any(|claim| claim.id == "AUTH-OBL-02" && claim.title.contains("data-export")));
    assert!(state
        .evidence
        .iter()
        .any(|evidence| evidence.kind == "obligation" && evidence.title == "AUTH-OBL-01"));
    assert!(state.coverage.iter().any(|coverage| coverage.category == "auth"));
    assert!(state.coverage.iter().any(|coverage| coverage.category == "authz"));
}

#[test]
fn feature_marker_category_stops_before_inventory_fields() {
    let mut state = RunbookState::default();
    state.start_turn("test target", AuditMode::Lab);
    state.record_agent_message(
        "FEATURE% id=F-AUTH family=identity category=auth endpoints=5 source_files=routes/login.ts,routes/2fa.ts label=Authentication surface",
    );

    let surface = state
        .surfaces
        .iter()
        .find(|surface| surface.label == "Authentication surface")
        .expect("feature surface");
    assert_eq!(surface.category, "auth");
}

#[test]
fn explicit_s5_final_set_keeps_source_backed_exposure_families() {
    let mut state = RunbookState::default();
    state.start_turn("test target", AuditMode::Lab);
    state.record_agent_message(
        "FEATURE% kind=capability category=observability_leak feature=metrics target=server.ts:718 label=metrics endpoint\n\
         SURFACE% kind=endpoint category=observability_leak target=/metrics label=metrics route\n\
         CANDIDATE% id=METRICS-01 category=observability_leak target=/metrics title=Prometheus metrics endpoint exposed without authentication\n\
         RUNBOOK% S3 Summary: merged findings\nRUNBOOK% S4 Fuzz: variant probes complete\n\
         PROBE% id=METRICS-01 result=GET /metrics returned 200 and Prometheus process metrics\n\
         CONTROL% id=METRICS-01 negative=authenticated and unauthenticated requests both return the same metrics document\n\
         `RUNBOOK% S5 Final Revision`\n\
         `FINDING% id=F-01 severity=high code_path=server.ts:369 confidence=high title=Unauthenticated Product Modification via Commented-Out Auth evidence=PUT /api/Products/1 without auth returned 200 and server.ts shows commented-out isAuthorized payload=PUT /api/Products/1 {\"name\":\"HACKED\"}`\n\
         `FINDING% id=F-02 severity=medium code_path=server.ts:718 confidence=high title=Prometheus Metrics Endpoint Exposed Without Authentication evidence=GET /metrics returned 200 payload=GET /metrics`\n\
         `FINDING% id=F-03 severity=medium code_path=server.ts:607 confidence=high title=Continue Code Generate and Restore Without Authentication evidence=GET /rest/continue-code returned restorable code payload=GET /rest/continue-code`",
    );
    state.complete();

    assert_eq!(state.status, RunbookStatus::Completed);
    assert_eq!(state.final_findings.len(), 3);
    assert!(state
        .final_findings
        .iter()
        .any(|finding| finding.title.contains("Prometheus Metrics Endpoint")));
    assert!(state
        .final_findings
        .iter()
        .any(|finding| finding.title.contains("Continue Code Generate")));
}

#[test]
fn evidence_signal_counter_is_cumulative_not_cache_size() {
    let mut state = RunbookState::default();
    state.start_turn("test target", AuditMode::Lab);

    for index in 0..95 {
        state.record_reasoning(&format!("trace signal {index}"));
    }

    assert!(state.evidence.len() <= 80);
    assert!(state.stats.evidence_signals > state.evidence.len());
}
