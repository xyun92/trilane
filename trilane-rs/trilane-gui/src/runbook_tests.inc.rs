    #[test]
    fn command_evidence_records_finding_without_driving_stage() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Safe);
        state.record_command(
            "curl -s -G --data-urlencode \"q=x')) UNION SELECT 1\" http://localhost:3000/rest/products/search",
            Some("{\"status\": \"success\", \"data\": []}"),
            "Completed",
            Some(0),
        );

        assert_eq!(state.current_stage, "stage0");
        assert_eq!(state.findings.len(), 1);
        assert_eq!(state.findings[0].title, "Union SQL injection");
    }

    #[test]
    fn stage_activation_does_not_regress_after_workflow_moves_forward() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Lab);
        state.record_workflow_phase("stage4", "S4 targeted controls");
        state.record_command(
            "curl -s http://localhost:3000/rest/products/search?q=' UNION SELECT exploit",
            Some("HTTP 200 response confirms SQLi probe"),
            "Completed",
            Some(0),
        );
        state.record_agent_message(
            "RUNBOOK% S3 Summary: report-like text with SQLi exploit evidence\n\
             FINDING% id=INJ-01 severity=critical code_path=routes/search.ts:23 confidence=high title=Search SQL injection evidence=probe returned rows payload=' UNION SELECT",
        );

        assert_eq!(state.current_stage, "stage4");
        assert!(state
            .stages
            .iter()
            .any(|stage| stage.id == "stage2" && stage.status == StageStatus::Done));
        assert!(state
            .stages
            .iter()
            .any(|stage| stage.id == "stage3" && stage.status == StageStatus::Done));
        assert!(state
            .stages
            .iter()
            .any(|stage| stage.id == "stage4" && stage.status == StageStatus::Active));
    }

    #[test]
    fn trilane_hook_signals_do_not_advance_scan_stage_without_workflow() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Lab);
        state.record_workflow_phase("stage2", "S2 concurrent audit");

        state.record_agent_message(
            "RUNBOOK% S4 Fuzz: premature prose from model\n\
             FINDING: report-shaped text\n\
             SEVERITY: critical\n\
             CODE_PATH: routes/search.ts:23\n\
             CONFIDENCE: high",
        );
        state.record_command(
            "curl -s http://localhost:3000/rest/products/search?q=' UNION SELECT exploit",
            Some("RUNBOOK% S5 Verify should not move the Scan stage"),
            "Completed",
            Some(0),
        );

        assert_eq!(state.current_stage, "stage2");
        assert!(state
            .stages
            .iter()
            .any(|stage| stage.id == "stage2" && stage.status == StageStatus::Active));
        assert!(state
            .stages
            .iter()
            .any(|stage| stage.id == "stage4" && stage.status == StageStatus::Pending));
    }

    #[test]
    fn subagent_lane_markers_drive_s2_completion() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Lab);
        state.record_workflow_phase("stage2", "S2 concurrent audit");

        state.record_agent_message(
            "SUBAGENT% lane=identity_engine status=done claims=4 candidates=5 thread_id=t1\n\
             SUBAGENT% lane=injection_engine status=done claims=6 candidates=8 thread_id=t2\n\
             SUBAGENT% lane=ingress_engine status=done claims=3 candidates=4 thread_id=t3\n\
             SUBAGENT% lane=logic_engine status=done claims=5 candidates=6 thread_id=t4\n\
             SUBAGENT% lane=config_engine status=done claims=2 candidates=3 thread_id=t5",
        );

        assert!(state.s2_required_lanes_complete());
        assert_eq!(state.s2_completed_lane_count(), 5);
        assert_eq!(state.s2_missing_lanes(), Vec::<String>::new());
        assert_eq!(state.lanes.len(), 5);
    }

    #[test]
    fn normalized_subagent_markers_drive_s2_completion() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Lab);
        state.record_workflow_phase("stage2", "S2 concurrent audit");

        state.record_agent_message(
            "SUBAGENT% lane=identity_engine status=done claims=4 candidates=5 note=identity complete\n\
             SUBAGENT% lane=injection_engine status=done claims=6 candidates=8 note=injection complete\n\
             **SUBAGENT% lane=ingress_engine status=done claims=3 candidates=4 note=file lanes complete**\n\
             SUBAGENT% lane=logic_engine status=done claims=5 candidates=6 note=logic lanes complete\n\
             SUBAGENT% lane=config_engine status=done claims=2 candidates=3 note=config lanes complete",
        );

        assert!(state.s2_required_lanes_complete());
        assert_eq!(state.s2_completed_lane_count(), 5);
        assert_eq!(state.s2_missing_lanes(), Vec::<String>::new());
        assert_eq!(state.lanes.len(), 5);
    }

    #[test]
    fn s1_obligation_fields_do_not_pollute_category_or_target() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Lab);
        state.record_workflow_phase("stage1", "S1 source map");

        state.record_agent_message(
            "OBLIGATION% id=CAND-38 category=authz debt=BasketItems-IDOR source=server.ts:425 sink=appendUserId must=prove-owner-check reason=object-id-write",
        );

        let candidate = state
            .candidates
            .iter()
            .find(|candidate| candidate.id == "CAND-38")
            .expect("candidate");
        assert_eq!(candidate.category, "authz");
        assert_eq!(candidate.target, "server.ts:425");
        assert!(candidate.title.contains("prove-owner-check"));

        let claim = state
            .claims
            .iter()
            .find(|claim| claim.id == "CAND-38")
            .expect("claim");
        assert_eq!(claim.category, "authz");
        assert_eq!(claim.target, "server.ts:425");
    }

    #[test]
    fn ledger_markers_inside_inline_code_are_parsed() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Lab);
        state.record_workflow_phase("stage4", "S4 targeted controls");
        state.record_agent_message(
            "`CONTROL% id=AUTH-CAND-10 negative=\"JWT expiry limits replay window\"`\n\
             `VERIFY% id=AUTH-CAND-10 exploit=\"token map persists in memory\" root_cause=lib/insecurity.ts:73 control=\"JWT expiry provides invalidation\"`\n\
             `RUNBOOK% S4 Fuzz: lane=auth_authz_session COMPLETE`",
        );

        assert!(state
            .evidence
            .iter()
            .any(|evidence| evidence.kind == "control" && evidence.title == "AUTH-CAND-10"));
        assert!(state
            .evidence
            .iter()
            .any(|evidence| evidence.kind == "verify" && evidence.title == "AUTH-CAND-10"));
        assert!(state
            .evidence
            .iter()
            .any(|evidence| evidence.kind == "runbook" && evidence.stage == "stage4"));
    }

    #[test]
    fn report_text_records_finding_without_driving_stage() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Safe);
        state.record_agent_message(
            "FINDING: SQL injection\nSEVERITY: critical\nCODE_PATH: routes/login.ts:42\nCONFIDENCE: high",
        );

        assert_eq!(state.current_stage, "stage0");
        assert_eq!(state.findings.len(), 1);
        assert_eq!(state.stats.confirmed, 1);
        assert_eq!(state.stats.source_confirmed, 1);
    }

    #[test]
    fn markdown_severity_table_does_not_inflate_confirmed_findings() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Safe);
        state.record_agent_message(
            "| 1 | Basket IDOR | HIGH |\n| 2 | Open Redirect | HIGH |\nFINDING% id=AUTHZ-CAND-01 severity=high code_path=routes/basket.ts:10 confidence=high title=Basket IDOR evidence=other basket returned",
        );

        assert_eq!(state.findings.len(), 1);
        assert_eq!(state.stats.confirmed, 1);
    }

    #[test]
    fn open_candidates_trigger_watchdog_on_summary() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Safe);
        state.record_agent_message(
            "CANDIDATE% id=AUTHZ-CAND-01 category=authz target=/api/Baskets/2 title=Basket IDOR\nRUNBOOK% S3 Summary: 1 confirmed finding",
        );

        assert_eq!(state.stats.candidates, 1);
        assert!(state
            .evidence
            .iter()
            .any(|evidence| evidence.kind == "watchdog"));
    }

    #[test]
    fn completion_without_surface_ledger_is_error() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Safe);
        state.complete();

        assert_eq!(state.status, RunbookStatus::Error);
        assert_eq!(state.current_stage, "stage1");
    }

    #[test]
    fn completion_deduplicates_final_findings_in_stage5() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Lab);
        state.record_agent_message(
            "FINDING% id=INJ-01 severity=critical code_path=routes/login.ts:12 confidence=high title=SQL injection login bypass evidence=curl login returned admin payload=' OR 1=1 --\n\
             FINDING% id=INJ-02 severity=critical code_path=routes/login.ts:12 confidence=high title=Auth SQLi on login evidence=source and exploit proved payload=' OR 1=1 --",
        );
        state.complete();

        assert_eq!(state.final_findings.len(), 1);
        assert_eq!(state.dedupe_summary.raw_findings, 2);
        assert_eq!(state.dedupe_summary.duplicates, 1);
        assert_eq!(state.stats.confirmed, 1);
        assert_eq!(state.final_findings[0].id, "VULN-001");
        assert_eq!(state.final_findings[0].verification_status, "verified");
    }

    #[test]
    fn poc_bundle_contains_replay_and_dedupe_counts() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Safe);
        state.record_agent_message(
            "FINDING% id=AUTH-01 severity=high code_path=routes/changePassword.ts:39 confidence=high title=Password change without current password evidence=HTTP 200 accepted missing current password payload=curl -X POST /rest/user/change-password",
        );
        state.complete();

        let report = state.final_report_markdown();
        assert!(report.contains("# TriLane PoC Bundle"));
        assert!(report.contains("PoC entries: 1"));
        assert!(report.contains("curl -X POST /rest/user/change-password"));
    }

    #[test]
    fn poc_marker_materializes_generated_not_verified_entry() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Lab);
        state.record_agent_message(
            "POC% id=POC-001 finding=AUTH-01 severity=high category=auth code_path=routes/changePassword.ts target=/rest/user/change-password precondition=authenticated_user replay=curl -X POST /rest/user/change-password expected=HTTP_200_password_changed impact=account_takeover verification=generated-not-verified cleanup=none evidence_refs=ID-01,S4_SKIP-01",
        );
        state.complete();

        assert_eq!(state.final_findings.len(), 1);
        assert_eq!(
            state.final_findings[0].verification_status,
            "generated-not-verified"
        );
        assert!(state.final_findings[0]
            .payload
            .contains("curl -X POST /rest/user/change-password"));
        let report = state.final_report_markdown();
        assert!(report.contains("Generated-not-verified PoCs: 1"));
        assert!(report.contains("Replay:"));
        assert!(report.contains("verification=generated-not-verified"));
    }

    #[test]
    fn s5_dedupe_does_not_collapse_unrelated_findings_with_shared_report_terms() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Lab);
        state.record_agent_message(
            "FINDING% id=AUTH-01 severity=critical code_path=routes/login.ts:12 confidence=high title=SQL injection login bypass evidence=TriLane report mentions config metrics redirect auth payload=' OR 1=1 --\n\
             FINDING% id=INFO-01 severity=medium code_path=routes/metrics.ts:8 confidence=high title=Prometheus metrics exposed evidence=TriLane report mentions config metrics redirect auth payload=curl /metrics\n\
             FINDING% id=REDIR-01 severity=high code_path=lib/insecurity.ts:138 confidence=high title=Open redirect allowlist bypass evidence=TriLane report mentions config metrics redirect auth payload=https://allowed.example.evil/",
        );
        state.complete();

        assert_eq!(state.dedupe_summary.raw_findings, 3);
        assert_eq!(state.final_findings.len(), 3);
        assert_eq!(state.dedupe_summary.duplicates, 0);
    }

    #[test]
    fn markdown_finding_headings_are_parsed_as_findings() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Lab);
        state.record_agent_message(
            "## Final Findings\n\n\
             ### FINDING 1 - SQL injection login bypass\n\
             - Severity: critical\n\
             - Code_Path: routes/login.ts:12\n\
             - Evidence: login accepted injected predicate\n\
             - Payload: ' OR 1=1 --\n\
             - Confidence: high\n\n\
             ### FINDING 2 — Prometheus metrics exposed\n\
             **Severity:** medium\n\
             **Code_Path:** routes/metrics.ts:8\n\
             **Evidence:** /metrics returned process metrics\n\
             **Payload:** curl http://localhost:3000/metrics\n\
             **Confidence:** high",
        );

        assert_eq!(state.findings.len(), 2);
        assert_eq!(state.findings[0].title, "SQL injection login bypass");
        assert_eq!(state.findings[1].title, "Prometheus metrics exposed");
        assert_eq!(state.findings[1].code_path, "routes/metrics.ts:8");
        assert!(state.findings[1].payload.contains("/metrics"));
    }

    #[test]
    fn claim_markers_populate_asg_and_asm_ledgers() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Lab);
        state.record_agent_message(
            "SURFACE% kind=sink category=injection target=routes/search.ts:23 label=sequelize raw query\n\
             CLAIM% id=INJ-CAND-01 category=injection target=/rest/products/search status=anchored level=source title=Product search SQLi root_cause=routes/search.ts:23 impact=database exfiltration\n\
             PROBE% id=INJ-CAND-01 result=curl returned product rows\n\
             CONTROL% id=INJ-CAND-01 negative=baseline query without quote returned normal result\n\
             FINDING% id=INJ-CAND-01 severity=critical code_path=routes/search.ts:23 confidence=high title=Product search SQL injection evidence=UNION SELECT extracted rows payload=curl /rest/products/search?q=')) UNION SELECT",
        );
        state.complete();

        assert_eq!(state.surfaces.len(), 1);
        assert_eq!(state.claims.len(), 1);
        assert_eq!(state.claim_summary.publishable, 1);
        assert_eq!(state.final_findings.len(), 1);
        assert_eq!(state.final_findings[0].verification_status, "publishable");
        assert_eq!(state.final_findings[0].evidence_state, "control-passed");
    }

    #[test]
    fn attack_atoms_synthesize_bounded_cross_lane_chains() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Lab);
        state.record_agent_message(
            "ATTACK_ATOM% id=ATOM-SECRET lane=config_engine kind=secret category=secrets_config target=lib/insecurity.ts label=Hardcoded JWT private key bridge_keys=token,secret evidence=private key present confidence=high\n\
             ATTACK_ATOM% id=ATOM-FORGE lane=identity_engine kind=primitive category=session target=/rest/user/whoami label=Forge admin JWT bridge_keys=token,identity evidence=forged token accepted confidence=high\n\
             ATTACK_ATOM% id=ATOM-WALLET lane=logic_engine kind=invariant category=state_invariant_abuse target=/rest/basket/:id/order label=Negative order total changes wallet bridge_keys=money,object evidence=order total can become negative confidence=medium",
        );

        assert_eq!(state.attack_atoms.len(), 3);
        assert!(state
            .chain_candidates
            .iter()
            .any(|chain| chain.bridge_keys.iter().any(|key| key == "token")
                && chain.atom_ids.len() == 2
                && chain.score >= 55));
    }

    #[test]
    fn chain_verify_updates_status_without_creating_findings() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Lab);
        state.record_agent_message(
            "CHAIN_CANDIDATE% id=CHAIN-JWT status=candidate score=90 atoms=ATOM-SECRET,ATOM-FORGE bridge_keys=token title=Key exposure to admin JWT forgery impact=admin auth bypass verify_plan=use disposable forged token and baseline invalid signature\n\
             CHAIN_VERIFY% id=CHAIN-JWT status=verified result=forged token accepted and invalid signature rejected after cleanup",
        );

        assert_eq!(state.chain_candidates.len(), 1);
        assert_eq!(state.chain_candidates[0].status, "verified");
        assert!(state
            .evidence
            .iter()
            .any(|evidence| evidence.kind == "chain_verify"));
        assert!(state.findings.is_empty());
    }

    #[test]
    fn s5_claim_adjudication_merges_duplicate_claim_families() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Lab);
        state.record_agent_message(
            "CLAIM% id=AUTHZ-CAND-01 category=authz target=/api/BasketItems status=verified level=repro title=Basket IDOR root_cause=routes/basket.ts:42 impact=read another basket\n\
             CLAIM% id=AUTHZ-CAND-02 category=authz target=/api/BasketItems status=verified level=repro title=Basket IDOR root_cause=routes/basket.ts:42 impact=read another basket\n\
             MERGE% id=AUTHZ-CAND-02 merge_into=AUTHZ-CAND-01 reason=same root cause and endpoint\n\
             FINDING% id=AUTHZ-CAND-01 severity=high code_path=routes/basket.ts:42 confidence=high title=Basket IDOR evidence=other basket returned payload=curl /api/BasketItems/2",
        );
        state.complete();

        assert_eq!(state.claim_summary.root_claims, 1);
        assert_eq!(state.claim_summary.merged, 1);
        assert_eq!(state.final_findings.len(), 1);
    }

    #[test]
    fn s5_keeps_source_backed_claim_families_visible_without_overclaiming() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Lab);
        state.record_agent_message(
            "CLAIM% id=AUTH-CAND-01 category=auth target=/rest/user/login status=anchored level=source title=Login SQL injection root_cause=routes/login.ts:12 impact=auth bypass evidence=raw SQL concatenates email\n\
             CLAIM% id=INFO-CAND-01 category=info_disclosure target=/metrics status=anchored level=source title=Metrics endpoint exposed root_cause=routes/metrics.ts:8 impact=runtime metadata exposure evidence=route registered without auth\n\
             CLAIM% id=SEED-CAND-01 category=xss target=/search status=seed level=signal title=Possible XSS",
        );
        state.complete();

        assert_eq!(state.final_findings.len(), 2);
        assert!(state
            .final_findings
            .iter()
            .any(|finding| finding.verification_status == "source-backed"));
        assert!(state
            .final_findings
            .iter()
            .all(|finding| finding.verification_status != "publishable"));
    }

    #[test]
    fn s5_collapses_raw_and_claim_synonyms_into_one_family() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Lab);
        state.record_agent_message(
            "FINDING% id=SECRETS-01 severity=critical code_path=lib/insecurity.ts:23 confidence=high title=Full RSA private key hardcoded in source code allows JWT token forgery evidence=private key signs JWT payload=curl forge-jwt\n\
             CLAIM% id=CLM-088 category=secrets_config target=lib/insecurity.ts status=publishable level=control title=Hardcoded RSA private key in source code root_cause=lib/insecurity.ts:23 impact=JWT token forgery payload=node forge.js evidence=forged token accepted negative=baseline invalid signature rejected\n\
             FINDING% id=SECRETS-02 severity=critical code_path=lib/insecurity.ts:23 confidence=high title=Hardcoded RSA private key in source code evidence=private key present payload=node forge.js",
        );
        state.complete();

        assert_eq!(state.final_findings.len(), 1);
        assert_eq!(
            state.final_findings[0].canonical_key,
            "secrets:jwt-private-key"
        );
        assert!(state.final_findings[0].duplicates.len() >= 2);
        assert_eq!(state.dedupe_summary.duplicates, 2);
    }

    #[test]
    fn s5_blocks_claims_when_control_evidence_refutes_exploitability() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Lab);
        state.record_agent_message(
            "CLAIM% id=BUSINESS-CAND-04 category=business_logic target=routes/wallet.ts status=publishable level=control title=Wallet balance manipulation via UserId parameter root_cause=routes/wallet.ts:24-35 impact=add balance to any user's wallet payload=curl -X PUT /rest/wallet/balance evidence=addWalletBalance uses req.body.UserId negative=appendUserId overwrites UserId and card lookup prevents cross-user balance changes",
        );
        state.complete();

        assert!(state.final_findings.is_empty());
        assert_eq!(state.dedupe_summary.final_findings, 0);
    }

    #[test]
    fn s5_ignores_stage5_summary_echo_without_anchor() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Lab);
        state.record_agent_message(
            "RUNBOOK% S5 Verify: final ledger\n\
             ## FINDING 39: B2B order endpoint appears unauthenticated\n\
             This is a summary echo without code, payload, or claim id.",
        );
        state.complete();

        assert!(state.findings.is_empty());
        assert!(state.final_findings.is_empty());
    }

    #[test]
    fn s5_drops_unauthenticated_route_claim_without_middleware_chain() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Lab);
        state.record_agent_message(
            "FINDING% id=B2B-UNAUTH severity=medium code_path=server.ts:645 confidence=high title=B2B order endpoint has no authentication middleware evidence=app.post('/b2b/v2/orders', b2bOrder()) shows no auth check payload=curl -X POST /b2b/v2/orders",
        );
        state.complete();

        assert!(state.final_findings.is_empty());
        assert_eq!(state.dedupe_summary.final_findings, 0);
    }

    #[test]
    fn s5_keeps_unauthenticated_claim_when_middleware_chain_is_proven() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Lab);
        state.record_agent_message(
            "FINDING% id=PUBLIC-UNAUTH severity=high code_path=server.ts:777 confidence=high title=Public export endpoint is unauthenticated evidence=middleware chain checked: no parent middleware and no preceding app.use before app.get('/rest/export'); HTTP 200 returned sensitive data payload=curl http://localhost:3000/rest/export",
        );
        state.complete();

        assert_eq!(state.final_findings.len(), 1);
        assert_eq!(state.final_findings[0].code_path, "server.ts:777");
        assert!(state.final_findings[0].title.contains("Public export"));
    }

    #[test]
    fn s5_downgrades_weaponized_claim_without_runtime_signal() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Lab);
        state.record_agent_message(
            "CLAIM% id=YAML-CAND-01 category=files target=/file-upload status=weaponized level=source title=Unsafe YAML deserialization root_cause=routes/fileUpload.ts:124 impact=parser denial of service payload=!!js/function evidence=source uses yaml.load",
        );
        state.complete();

        assert_eq!(state.final_findings.len(), 1);
        assert_eq!(state.final_findings[0].verification_status, "verified");
    }

    #[test]
    fn s5_removes_candidate_only_final_findings_without_anchor() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Lab);
        state.record_agent_message(
            "CANDIDATE% id=CAND-04 category=authz target=/api/Users title=Mass assignment admin registration\n\
             FINDING% id=CAND-04 severity=critical confidence=medium title=Mass assignment admin registration evidence=User creation accepted role=admin payload=curl -s -X POST 'http://localhost:3000/api/Users' \\",
        );
        state.complete();

        assert!(state.final_findings.is_empty());
    }

    #[test]
    fn s5_merges_mass_assignment_admin_registration_variants() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Lab);
        state.record_agent_message(
            "FINDING% id=AUTHZ-01 severity=critical code_path=server.ts:407 confidence=high title=User registration API accepts role field allowing admin registration evidence=POST /api/Users returned role admin payload=curl -X POST /api/Users -d '{\"role\":\"admin\"}'\n\
             FINDING% id=CAND-04 severity=critical code_path=server.ts:407 confidence=medium title=Mass assignment admin registration evidence=User creation accepted role=admin payload=curl -s -X POST http://localhost:3000/api/Users",
        );
        state.complete();

        assert_eq!(state.final_findings.len(), 1);
        assert_eq!(
            state.final_findings[0].canonical_key,
            "authz:admin-role-registration"
        );
    }

    #[test]
    fn s5_removes_mitigated_or_limited_findings_from_final_table() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Lab);
        state.record_agent_message(
            "FINDING% id=XXE-01 severity=low code_path=routes/fileUpload.ts:80 confidence=low title=XML upload with external entity support though fast-xml-parser used limited XXE evidence=Parser limitation mitigates full XXE; not exploitable payload=<!DOCTYPE foo>",
        );
        state.complete();

        assert!(state.final_findings.is_empty());
    }

    #[test]
    fn s5_removes_polluted_payload_without_exploit_request() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Lab);
        state.record_agent_message(
            "FINDING% id=XSS-RAW severity=high confidence=medium title=Stored XSS payload accepted evidence=Product API accepted javascript iframe payload payload=import * as utils from '../lib/utils'\nimport * as security from '../lib/insecurity'\n'<iframe src=\"javascript:alert(`xss`)\">'",
        );
        state.complete();

        assert!(state.final_findings.is_empty());
    }

    #[test]
    fn s5_downgrades_public_admin_config_overclaim() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Lab);
        state.record_agent_message(
            "FINDING% id=INFO-ADMIN severity=medium code_path=server.ts:604 confidence=high title=Admin endpoints accessible without authentication exposes application version and full configuration evidence=GET /rest/admin/application-configuration returns full config payload=curl /rest/admin/application-configuration",
        );
        state.complete();

        assert_eq!(state.final_findings.len(), 1);
        assert_eq!(
            state.final_findings[0].title,
            "Public admin metadata/configuration disclosure"
        );
        assert_eq!(state.final_findings[0].severity, "low");
        assert_eq!(state.final_findings[0].verification_status, "verified");
    }

    #[test]
    fn trilane_mode_expands_coverage_taxonomy() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Lab);

        assert_eq!(state.audit_mode, AuditMode::Lab);
        assert!(state.coverage.iter().any(|item| item.category == "xss"));
        assert!(state
            .coverage
            .iter()
            .any(|item| item.category == "cors_headers_tls"));
        assert!(state.coverage.len() > 8);
    }

    #[test]
    fn trilane_completion_records_incomplete_gate() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Lab);
        state.record_agent_message(
            "SURFACE% kind=endpoint category=injection target=/rest/user/login label=login route\n\
             CANDIDATE% id=INJ-CAND-01 category=injection target=/rest/user/login title=Login SQL injection\n\
             FINDING% id=INJ-CAND-01 severity=critical code_path=routes/login.ts:42 confidence=high title=Login SQL injection evidence=source string concat",
        );
        state.complete();

        assert!(state
            .evidence
            .iter()
            .any(|evidence| evidence.title == "Surface-driven workflow debt"));
        assert!(state.stats.coverage_debt > 0);
        assert_eq!(state.stats.surfaces, 1);
        assert_eq!(state.stats.surface_covered, 1);
    }

    #[test]
    fn trilane_completion_without_s1_surface_ledger_is_blocked() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Lab);
        state.record_agent_message(
            "RUNBOOK% S1 Recon: compiling SURFACE%/COVERAGE% ledger from route files read.\n\
             Now emitting the full S1 surface ledger:",
        );
        state.complete();

        assert_eq!(state.status, RunbookStatus::Error);
        assert_eq!(state.current_stage, "stage1");
        assert!(state
            .stages
            .iter()
            .any(|stage| stage.id == "stage1" && stage.status == StageStatus::Blocked));
        assert!(state
            .evidence
            .iter()
            .any(|evidence| evidence.title == "S1 surface ledger missing"));
        assert!(state.final_findings.is_empty());
    }

    #[test]
    fn read_target_markers_record_s2_source_assignments() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Lab);
        state.record_agent_message(
            "RUNBOOK% S1 Recon: route and source read targets\n\
             **READ_TARGET% (S2 deep-read work orders, max 10)**\n\
             READ_TARGET% lane=identity_engine priority=high category=authz kind=endpoint-control path=routes/basket.ts lines=1-160 endpoint=/api/BasketItems object_id=body.BasketId auth_hint=middleware ownership_hint=unknown reason=object_id_write_without_obvious_owner_check question=prove_user_bid_controls_body_BasketId stop_when=owner_check_found_or_missing broaden_after=shared_basket_helper follow=middleware/auth.ts,models/Basket.ts",
        );

        let read_targets = state
            .surfaces
            .iter()
            .filter(|surface| surface.kind == "read_target")
            .collect::<Vec<_>>();
        assert_eq!(read_targets.len(), 1);
        let surface = read_targets[0];
        assert_eq!(surface.category, "authz");
        assert_eq!(surface.target, "routes/basket.ts");
        assert!(surface.label.contains("lane=identity_engine"));
        assert!(surface.label.contains("ownership_hint=unknown"));
        assert!(surface.label.contains("question=prove_user_bid_controls_body_BasketId"));
        assert!(surface.label.contains("stop_when=owner_check_found_or_missing"));
        assert!(surface.label.contains("broaden_after=shared_basket_helper"));
    }

    #[test]
    fn trilane_s2_findings_without_s5_are_blocked() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Lab);
        state.record_agent_message(
            "SURFACE% kind=endpoint category=injection target=/rest/user/login label=login route\n\
             CANDIDATE% id=INJ-CAND-01 category=injection target=/rest/user/login title=Login SQL injection\n\
             RUNBOOK% S2 Audit: all 6 lanes completed. Emitting findings.\n\
             FINDING% id=INJ-CAND-01 severity=critical code_path=routes/login.ts:42 confidence=high title=Login SQL injection evidence=source string concat payload=' OR 1=1--",
        );
        state.complete();

        assert_eq!(state.status, RunbookStatus::Error);
        assert_eq!(state.current_stage, "stage5");
        assert!(state
            .stages
            .iter()
            .any(|stage| stage.id == "stage5" && stage.status == StageStatus::Blocked));
        assert!(state
            .evidence
            .iter()
            .any(|evidence| evidence.title == "Workflow gate blocked before S5"));
        assert!(state.final_findings.is_empty());
        assert_eq!(state.stats.confirmed, 0);

        let report = state.final_report_markdown();
        assert!(report.contains("PoC entries: 0"));
        assert!(!report.contains("### VULN-001"));
    }

    #[test]
    fn trilane_s5_findings_can_finalize() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Lab);
        state.record_agent_message(
            "SURFACE% kind=endpoint category=injection target=/rest/user/login label=login route\n\
             CANDIDATE% id=INJ-CAND-01 category=injection target=/rest/user/login title=Login SQL injection\n\
             RUNBOOK% S3 Summary: merged single finding family for small target\n\
             RUNBOOK% S4 Fuzz: role and payload variants probed\n\
             PROBE% id=INJ-CAND-01 result=injected login returned admin token\n\
             CONTROL% id=INJ-CAND-01 negative=clean invalid login was rejected\n\
             RUNBOOK% S5 Verify: final adjudication ledger\n\
             ADJUDICATE% id=INJ-CAND-01 status=publishable reason=source exploit and negative control recorded\n\
             FINDING% id=INJ-CAND-01 severity=critical code_path=routes/login.ts:42 confidence=high title=Login SQL injection evidence=source string concat and control rejected clean login payload=' OR 1=1--",
        );
        state.complete();

        assert_eq!(state.status, RunbookStatus::Completed);
        assert_eq!(state.final_findings.len(), 1);
        assert_eq!(state.stats.confirmed, 1);
    }

    #[test]
    fn poc_units_keep_same_root_claims_separate() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Lab);
        state.record_agent_message(
            "CLAIM% id=ID-001 category=session target=lib/jwt.ts:10 severity=high confidence=high title=JWT none reason=source->sink: jwt verifier impact=auth_bypass next=poc:jwt-none\n\
             CLAIM% id=ID-002 category=session target=lib/jwt.ts:10 severity=high confidence=high title=JWT HS256 reason=source->sink: jwt verifier impact=auth_bypass next=poc:jwt-hs256-confusion",
        );

        assert_eq!(state.claims.len(), 2);
        assert!(state
            .claims
            .iter()
            .any(|claim| claim.precondition == "poc:jwt-none"));
        assert!(state
            .claims
            .iter()
            .any(|claim| claim.precondition == "poc:jwt-hs256-confusion"));
    }

    #[test]
    fn poc_marker_parser_preserves_replay_and_sanitizes_report() {
        let mut state = RunbookState::default();
        state.start_turn(
            "Penetration test juice-shop\nRESUME_RUN_CONTEXT%\n/Users/wuxuyun/.trilane/runs/old/stage2/runbook.json",
            AuditMode::Lab,
        );
        state.record_workflow_phase("stage4", "S4 Fuzz");
        state.record_agent_message(
            "PROBE% id=INJ-001 result=HTTP 200 returned admin token\n\
             CONTROL% id=INJ-001 negative=clean login rejected",
        );
        state.record_workflow_phase("stage5", "S5 Verify");
        state.record_agent_message(
            "POC% id=POC-001 finding=INJ-001 category=injection target=/rest/user/login severity=critical verification=verified replay=\"curl -s -H \\\"Authorization: Bearer token\\\" -d '{\\\"email\\\":\\\"a@b.c\\\",\\\"password\\\":\\\"x\\\"}' http://127.0.0.1:3000/rest/user/login\" expected=\"admin token\" cleanup=none",
        );

        let finding = state
            .findings
            .iter()
            .find(|finding| finding.candidate_id.as_deref() == Some("INJ-001"))
            .expect("poc finding");
        assert!(!finding.title.contains("POC%"));
        assert_eq!(finding.title, "injection PoC for /rest/user/login");
        assert!(finding.payload.contains("Authorization: Bearer token"));
        assert!(finding.payload.contains("\"email\":\"a@b.c\""));
        assert_eq!(finding.evidence_state, "verified");

        let report = state.final_report_markdown();
        assert!(!report.contains("RESUME_RUN_CONTEXT%"));
        assert!(!report.contains("/.trilane/runs/"));
        assert!(!report.contains("stage2/runbook.json"));
        assert!(!report.contains("### VULN-001 - POC%"));
    }

    #[test]
    fn s5_final_revision_replaces_draft_pocs_and_ignores_markdown_echoes() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Lab);
        state.record_agent_message(
            "RUNBOOK% S5 Verify: draft\n\
             POC% id=POC-001 finding=DRAFT-01 severity=high category=auth code_path=routes/old.ts:1 target=/old title=\"Old draft PoC\" replay=\"curl /old\" expected=old verification=generated-not-verified cleanup=none",
        );
        assert_eq!(state.stage5_poc_entries.len(), 1);

        state.record_agent_message(
            "RUNBOOK% S5 Final Revision\n\
             POC% id=POC-002 finding=FINAL-01 severity=critical category=auth code_path=routes/new.ts:7 target=/new title=\"Corrected canonical PoC\" replay=\"curl /new\" expected=new verification=generated-not-verified cleanup=none\n\
             ### POC-003: Markdown echo should not count\n\
             - Severity: high\n\
             - Code_Path: routes/echo.ts:9\n\
             - Evidence: report text only\n\
             - Payload: echo",
        );

        assert_eq!(state.stage5_poc_entries.len(), 1);
        assert_eq!(state.stage5_poc_entries[0].title, "Corrected canonical PoC");
        assert_eq!(state.stage5_poc_entries[0].code_path, "routes/new.ts:7");
    }

    #[test]
    fn s5_final_revision_keeps_distinct_poc_ids_with_shared_candidate() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Lab);
        let draft = (1..=20)
            .map(|idx| {
                format!(
                    "POC% id=POC-{idx:03} finding=CAND-{idx:03} severity=medium category=authz code_path=routes/old{idx}.ts target=/old/{idx} title=\"Old PoC {idx}\" replay=\"curl /old/{idx}\" expected=old-{idx} verification=generated-not-verified cleanup=none"
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        state.record_agent_message(&format!("RUNBOOK% S5 Verify\n{draft}"));

        let final_rows = (1..=39)
            .map(|idx| {
                let source = if idx <= 2 { 1 } else { idx };
                format!(
                    "POC% id=POC-{idx:03} finding=CAND-{source:03} severity=medium category=authz code_path=routes/new{idx}.ts target=/new/{idx} title=\"Final PoC {idx}\" replay=\"curl /new/{idx}\" expected=final-{idx} verification=generated-not-verified cleanup=none"
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        state.record_agent_message(&format!("RUNBOOK% S5 Final Revision\n{final_rows}"));
        state.record_agent_message(
            "RUNBOOK% S5 Final Revision complete. 39 canonical PoC families. Audit complete.",
        );
        state.complete();

        assert_eq!(state.stage5_poc_entries.len(), 39);
        assert_eq!(state.final_findings.len(), 39);
        assert!(state
            .final_findings
            .iter()
            .any(|finding| finding.original_id == "POC-001"));
        assert!(state
            .final_findings
            .iter()
            .any(|finding| finding.original_id == "POC-002"));
        assert!(!state
            .final_findings
            .iter()
            .any(|finding| finding.detail.contains("expected=old-1")));
    }

    #[test]
    fn stage5_commands_do_not_infer_new_findings() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Lab);
        state.record_workflow_phase("stage5", "S5 final adjudication");
        state.record_agent_message("RUNBOOK% S5 Verify: final adjudication");
        state.record_command(
            "curl '/search?q=' UNION SELECT 1'",
            Some(r#"{"status": "success", "data": [{"email": "a@example.test"}]}"#),
            "Completed",
            Some(0),
        );

        assert!(state.findings.is_empty());
    }

    #[test]
    fn trilane_s5_without_s4_is_blocked() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Lab);
        state.record_agent_message(
            "SURFACE% kind=endpoint category=injection target=/rest/user/login label=login route\n\
             RUNBOOK% S3 Summary: compiling merged findings ledger.\n\
             RUNBOOK% S5 Verify: starting verification pass.\n\
             CLAIM% id=INJ-CAND-01 category=injection target=/rest/user/login status=weaponized level=repro title=Login SQL injection root_cause=routes/login.ts:42 impact=auth bypass\n\
             FINDING% id=INJ-CAND-01 severity=critical code_path=routes/login.ts:42 confidence=high title=Login SQL injection evidence=source string concat payload=' OR 1=1--",
        );
        state.complete();

        assert_eq!(state.status, RunbookStatus::Error);
        assert_eq!(state.current_stage, "stage5");
        assert!(state.evidence.iter().any(|evidence| evidence.title
            == "Workflow gate blocked before S5"
            && evidence.detail.contains("RUNBOOK% S4 Fuzz")));
        assert!(state.final_findings.is_empty());
        assert_eq!(state.stats.confirmed, 0);
    }

    #[test]
    fn trilane_s4_without_s3_is_blocked() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Lab);
        state.record_agent_message(
            "SURFACE% kind=endpoint category=injection target=/rest/user/login label=login route\n\
             RUNBOOK% S2 Audit: source analysis complete\n\
             CLAIM% id=INJ-CAND-01 category=injection target=/rest/user/login status=verified level=repro title=Login SQL injection root_cause=routes/login.ts:42 impact=auth bypass\n\
             RUNBOOK% S4 Fuzz: targeted variant probing for top vulnerability families\n\
             RUNBOOK% S5 Verify: final adjudication ledger\n\
             FINDING% id=INJ-CAND-01 severity=critical code_path=routes/login.ts:42 confidence=high title=Login SQL injection evidence=source string concat payload=' OR 1=1--",
        );
        state.complete();

        assert_eq!(state.status, RunbookStatus::Error);
        assert_eq!(state.current_stage, "stage5");
        assert!(state.evidence.iter().any(|evidence| evidence.title
            == "Workflow gate blocked before S5"
            && evidence.detail.contains("RUNBOOK% S3 Summary")));
        assert!(state.final_findings.is_empty());
    }

    #[test]
    fn trilane_blanket_s4_skip_is_blocked() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Lab);
        state.record_agent_message(
            "SURFACE% kind=endpoint category=injection target=/rest/user/login label=login route\n\
             CANDIDATE% id=INJ-CAND-01 category=injection target=/rest/user/login title=Login SQL injection\n\
             RUNBOOK% S2 Audit: source analysis complete\n\
             CLAIM% id=INJ-CAND-01 category=injection target=/rest/user/login status=verified level=repro title=Login SQL injection root_cause=routes/login.ts:42 impact=auth bypass\n\
             RUNBOOK% S3 Summary: one root claim\n\
             RUNBOOK% S4 Fuzz: skipped heavy variant expansion because source is available\n\
             RUNBOOK% S5 Verify: final adjudication ledger\n\
             FINDING% id=INJ-CAND-01 severity=critical code_path=routes/login.ts:42 confidence=high title=Login SQL injection evidence=source string concat payload=' OR 1=1--",
        );
        state.complete();

        assert_eq!(state.status, RunbookStatus::Error);
        assert!(state.evidence.iter().any(|evidence| evidence.title
            == "Workflow gate blocked before S5"
            && evidence.detail.contains("weak S4")));
        assert!(state.final_findings.is_empty());
    }

    #[test]
    fn trilane_thin_hypothesis_pool_is_blocked_before_final_report() {
        let mut state = RunbookState::default();
        state.start_turn("training lab", AuditMode::Lab);
        state.record_agent_message(
            "RUNBOOK% S1 Recon: merged route/source-sink surface ledger\n\
             SURFACE% kind=endpoint category=auth target=/login label=login endpoint\n\
             SURFACE% kind=endpoint category=authz target=/basket label=basket ownership\n\
             SURFACE% kind=endpoint category=session target=/whoami label=session decode\n\
             SURFACE% kind=sink category=injection target=routes/search.ts label=raw SQL\n\
             SURFACE% kind=sink category=xss target=routes/profile.ts label=template render\n\
             SURFACE% kind=egress category=ssrf_redirect target=routes/profileImage.ts label=fetch URL\n\
             SURFACE% kind=parser category=file_upload_xxe target=routes/fileUpload.ts label=XML parser\n\
             SURFACE% kind=sink category=traversal_lfi target=routes/fileServer.ts label=file read\n\
             SURFACE% kind=source category=secrets_config target=lib/insecurity.ts label=JWT keys\n\
             SURFACE% kind=debug category=observability_leak target=/metrics label=metrics route\n\
             SURFACE% kind=guard category=rate_limit target=/login label=login throttling\n\
             SURFACE% kind=endpoint category=state_invariant_abuse target=/wallet label=wallet workflow\n\
             RUNBOOK% S2 Audit: thin lane output\n\
             CLAIM% id=INJ-CAND-01 category=injection target=/rest/products/search status=verified level=repro title=Product search SQL injection root_cause=routes/search.ts:16 impact=db read\n\
             CLAIM% id=AUTH-CAND-01 category=auth target=/rest/user/login status=verified level=repro title=Login SQL injection root_cause=routes/login.ts:30 impact=auth bypass\n\
             RUNBOOK% S3 Summary: two claims only\n\
             RUNBOOK% S4 Fuzz: payload variants probed for two claims\n\
             PROBE% id=INJ-CAND-01 result=UNION payload returned rows\n\
             CONTROL% id=INJ-CAND-01 negative=baseline query returned normal product set\n\
             RUNBOOK% S5 Verify: final adjudication ledger\n\
             FINDING% id=INJ-CAND-01 severity=critical code_path=routes/search.ts:16 confidence=high title=Product search SQL injection evidence=UNION payload worked payload=' UNION SELECT",
        );
        state.complete();

        assert_eq!(state.status, RunbookStatus::Error);
        assert!(state.stats.hypothesis_debt > 0);
        assert!(state.evidence.iter().any(|evidence| evidence.title
            == "Workflow gate blocked before S5"
            && evidence.detail.contains("hypothesis_pool=")));
        assert!(state.final_findings.is_empty());
    }

    #[test]
    fn surface_driven_gate_closes_without_fixed_candidate_floor() {
        let mut state = RunbookState::default();
        state.start_turn("small target", AuditMode::Lab);
        state.record_agent_message(
            "COVERAGE% category=auth mapped=1 total=1 target=/login\n\
             COVERAGE% category=authz mapped=0 total=0 target=not_applicable:no object routes\n\
             COVERAGE% category=session mapped=0 total=0 target=not_applicable:stateless API\n\
             COVERAGE% category=injection mapped=1 total=1 target=/login\n\
             COVERAGE% category=xss mapped=0 total=0 target=not_applicable:no browser rendering\n\
             COVERAGE% category=cors_headers_tls mapped=0 total=0 target=not_applicable:local HTTP lab\n\
             COVERAGE% category=ssrf_redirect mapped=0 total=0 target=not_applicable:no outbound fetch\n\
             COVERAGE% category=file_upload_xxe mapped=0 total=0 target=not_applicable:no upload parser\n\
             COVERAGE% category=traversal_lfi mapped=0 total=0 target=not_applicable:no file reads\n\
             COVERAGE% category=state_invariant_abuse mapped=0 total=0 target=not_applicable:no workflows\n\
             COVERAGE% category=anti_automation_bypass mapped=0 total=0 target=not_applicable:no recovery or anti-automation controls\n\
             COVERAGE% category=rate_limit mapped=1 total=1 target=/login\n\
             COVERAGE% category=secrets_config mapped=0 total=0 target=not_applicable:no exposed config\n\
             COVERAGE% category=observability_leak mapped=0 total=0 target=not_applicable:no debug routes\n\
             COVERAGE% category=crypto mapped=0 total=0 target=not_applicable:no crypto use\n\
             SURFACE% kind=endpoint category=injection target=/login label=login endpoint\n\
             CANDIDATE% id=AUTH-CAND-01 category=auth target=/login title=Login authentication bypass\n\
             REJECTED% id=AUTH-CAND-01 reason=valid credentials required and invalid baseline rejected\n\
             CANDIDATE% id=INJ-CAND-01 category=injection target=/login title=Login SQL injection\n\
             REJECTED% id=INJ-CAND-01 reason=parameterized query with bound values\n\
             CANDIDATE% id=RATE-CAND-01 category=rate_limit target=/login title=Login brute-force throttling gap\n\
             REJECTED% id=RATE-CAND-01 reason=gateway rate limit observed",
        );
        state.complete();

        assert_eq!(state.stats.surfaces, 1);
        assert_eq!(state.stats.surface_covered, 1);
        assert_eq!(state.stats.candidates, 3);
        assert_eq!(state.stats.coverage_debt, 0);
        assert!(!state
            .evidence
            .iter()
            .any(|evidence| evidence.title == "Surface-driven workflow debt"));
    }

    #[test]
    fn findings_mark_coverage_without_explicit_coverage_marker() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Lab);
        state.record_agent_message(
            "FINDING: DOM XSS via search\nSEVERITY: high\nCODE_PATH: frontend/search.ts:12\nCONFIDENCE: high",
        );

        let xss = state
            .coverage
            .iter()
            .find(|item| item.category == "xss")
            .expect("xss coverage category");
        assert_eq!(xss.mapped_count, 1);
        assert_eq!(state.stats.coverage_mapped, 1);
    }

    #[test]
    fn stop_turn_blocks_current_stage_and_running_lanes() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Lab);
        state.record_workflow_phase("stage2", "S2 audit");
        state.record_subagent_lane(RunbookLaneUpdate {
            stage: "stage2",
            lane_id: "quick_hits_engine",
            status: "running",
            claim_count: None,
            candidate_count: None,
            thread_id: Some("thread-1"),
            summary: "lane started",
        });

        state.stop_turn("stopped by user reboot");

        assert_eq!(state.status, RunbookStatus::Error);
        assert!(state
            .stages
            .iter()
            .any(|stage| stage.id == "stage2" && stage.status == StageStatus::Blocked));
        let lane = state
            .lanes
            .iter()
            .find(|lane| lane.lane_id == "quick_hits_engine")
            .expect("quick hits lane");
        assert_eq!(lane.status, "failed");
        assert_eq!(lane.summary, "stopped by user reboot");
    }

    #[test]
    fn scan_progress_uses_explicit_stage_status_over_current_stage() {
        let mut state = RunbookState::default();
        state.start_turn("test target", AuditMode::Lab);
        state.current_stage = "stage3".to_string();
        for stage in &mut state.stages {
            stage.status = match stage.id.as_str() {
                "stage0" | "stage1" => StageStatus::Done,
                "stage2" => StageStatus::Active,
                _ => StageStatus::Pending,
            };
        }

        let progress = scan_progress_from_runbook(&state).expect("scan progress");

        assert_eq!(progress.stage, "stage2");
        assert_eq!(progress.stage_name, "S2 Audit");
    }
