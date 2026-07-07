    #[test]
    fn workflow_starts_with_s0_and_ends_with_s5() {
        let mut state = RunbookState::default();
        state.start_turn("audit target", AuditMode::Lab);
        let mut workflow = TriLaneWorkflow::new("audit target".to_string());

        let WorkflowAction::Submit(first) = workflow.begin(&state) else {
            panic!("expected first prompt");
        };
        assert_eq!(first.phase_id, "s0_admission");
        assert!(first.prompt.contains("RUNBOOK% S0 Admission"));

        let final_phase = workflow.phases.last().expect("phase list is non-empty");
        assert_eq!(final_phase.id, "s5_final_revision");
        assert!(final_phase.body.contains("replacement PoC set"));
    }

    #[test]
    fn workflow_can_start_from_stage3() {
        let mut state = RunbookState::default();
        state.start_turn("audit target", AuditMode::Lab);
        let mut workflow =
            TriLaneWorkflow::new_from_stage("audit target".to_string(), "stage3")
                .expect("stage3 workflow");

        let WorkflowAction::Submit(prompt) = workflow.begin(&state) else {
            panic!("expected stage3 prompt");
        };
        assert_eq!(prompt.phase_id, "s3_merge_foa");
        assert_eq!(prompt.stage_id, "stage3");
    }

    #[test]
    fn s3_prompt_consumes_only_stage2_claim_pool() {
        let mut state = RunbookState::default();
        state.start_turn("audit target", AuditMode::Lab);
        state.current_stage = "stage1".to_string();
        state.record_agent_message(
            "CLAIM% id=OBL-01 category=auth target=routes/old.ts title=old_s1_obligation reason=s1_debt impact=unknown\n\
             CANDIDATE% id=CAND-01 category=auto target=unmapped-feature title=generic_placeholder\n\
             ATTACK_ATOM% id=ATOM-01 lane=identity_engine kind=surface category=auth target=/old label=old_atom bridge_keys=identity claim=OBL-01 confidence=signal",
        );
        state.current_stage = "stage2".to_string();
        state.record_agent_message(
            "CLAIM% id=ID-01 category=auth target=routes/changePassword.ts severity=high confidence=high title=password_change_bypass reason=missing_current_password impact=account_takeover next=authorized_vs_attacker_password_change",
        );

        let mut workflow =
            TriLaneWorkflow::new_from_stage("audit target".to_string(), "stage3")
                .expect("stage3 workflow");
        let WorkflowAction::Submit(prompt) = workflow.begin(&state) else {
            panic!("expected stage3 prompt");
        };

        assert!(prompt
            .prompt
            .contains("MERGE_PACKET% mode=s3_claim_pool"));
        assert!(prompt.prompt.contains("CLAIM% id=ID-01"));
        assert!(prompt.prompt.contains("Do not call tools"));
        assert!(prompt.prompt.contains("Reuse input claim ids exactly"));
        assert!(prompt.prompt.contains("MERGE% id=<duplicate-input-id>"));
        assert!(prompt.prompt.contains("Do not emit DUPLICATE%"));
        assert!(prompt.prompt.contains("do not invent CANON-*"));
        assert!(!prompt.prompt.contains("CLAIM% id=OBL-01"));
        assert!(!prompt.prompt.contains("CANDIDATE% id=CAND-01"));
        assert!(!prompt.prompt.contains("ATTACK_ATOM% id=ATOM-01"));
    }

    #[test]
    fn s3_summary_without_clean_handoff_does_not_advance() {
        let mut state = RunbookState::default();
        state.start_turn("audit target", AuditMode::Lab);
        state.current_stage = "stage2".to_string();
        state.record_agent_message(
            "CLAIM% id=ID-01 category=auth target=routes/login.ts severity=critical confidence=high title=login_sqli reason=raw_sql impact=auth_bypass next=s4_login_control",
        );

        let mut workflow =
            TriLaneWorkflow::new_from_stage("audit target".to_string(), "stage3")
                .expect("stage3 workflow");
        let WorkflowAction::Submit(_) = workflow.begin(&state) else {
            panic!("expected initial S3 prompt");
        };

        state.current_stage = "stage3".to_string();
        state.record_agent_message("RUNBOOK% S3 Summary: claim pool reviewed");

        let WorkflowAction::Submit(repair) = workflow.after_turn_completed(&state) else {
            panic!("expected S3 repair, not S4 advance");
        };
        assert_eq!(repair.phase_id, "s3_merge_foa");
        assert!(repair.is_repair);
        assert!(repair.prompt.contains("Do not call tools"));
        assert!(repair.prompt.contains("Reuse input ids exactly"));
    }

    #[test]
    fn s3_clean_handoff_advances_to_s4() {
        let mut state = RunbookState::default();
        state.start_turn("audit target", AuditMode::Lab);
        state.current_stage = "stage2".to_string();
        state.record_agent_message(
            "CLAIM% id=ID-01 category=auth target=routes/login.ts severity=critical confidence=high title=login_sqli reason=raw_sql impact=auth_bypass next=s4_login_control",
        );

        let mut workflow =
            TriLaneWorkflow::new_from_stage("audit target".to_string(), "stage3")
                .expect("stage3 workflow");
        let WorkflowAction::Submit(_) = workflow.begin(&state) else {
            panic!("expected initial S3 prompt");
        };

        state.current_stage = "stage3".to_string();
        state.record_agent_message(
            "RUNBOOK% S3 Summary: canonical claim families ready for S4\n\
             CLAIM% id=ID-01 category=auth target=routes/login.ts status=seed level=signal severity=critical title=login_sqli reason=raw_sql impact=auth_bypass next=s4_login_control",
        );

        let WorkflowAction::Submit(next) = workflow.after_turn_completed(&state) else {
            panic!("expected S4 prompt after clean S3 handoff");
        };
        assert_eq!(next.phase_id, "s4_auth_authz_session_controls");
    }

    #[test]
    fn s3_clean_handoff_advances_even_if_command_evidence_exists() {
        let mut state = RunbookState::default();
        state.start_turn("audit target", AuditMode::Lab);
        state.current_stage = "stage2".to_string();
        state.record_agent_message(
            "CLAIM% id=ID-01 category=auth target=routes/login.ts severity=critical confidence=high title=login_sqli reason=raw_sql impact=auth_bypass next=s4_login_control",
        );

        let mut workflow =
            TriLaneWorkflow::new_from_stage("audit target".to_string(), "stage3")
                .expect("stage3 workflow");
        let WorkflowAction::Submit(_) = workflow.begin(&state) else {
            panic!("expected initial S3 prompt");
        };

        state.current_stage = "stage3".to_string();
        state.record_command(
            "rg login routes/login.ts",
            Some("routes/login.ts: raw login handler"),
            "Completed",
            Some(0),
        );
        state.record_agent_message(
            "RUNBOOK% S3 Summary: canonical claim families ready for S4\n\
             CLAIM% id=ID-01 category=auth target=routes/login.ts status=seed level=signal severity=critical title=login_sqli reason=raw_sql impact=auth_bypass next=s4_login_control",
        );

        let WorkflowAction::Submit(next) = workflow.after_turn_completed(&state) else {
            panic!("expected S4 prompt after clean S3 handoff");
        };
        assert_eq!(next.phase_id, "s4_auth_authz_session_controls");
    }

    #[test]
    fn s4_prompt_consumes_canonical_handoff_only() {
        let mut state = RunbookState::default();
        state.start_turn("audit target", AuditMode::Lab);
        state.current_stage = "stage1".to_string();
        state.record_agent_message(
            "CLAIM% id=OBL-01 category=auth target=routes/old.ts title=old_s1_obligation reason=s1_debt impact=unknown\n\
             CANDIDATE% id=CAND-01 category=auto target=unmapped-feature title=generic_placeholder\n\
             ATTACK_ATOM% id=ATOM-01 lane=identity_engine kind=surface category=auth target=/old label=old_atom bridge_keys=identity claim=OBL-01 confidence=signal",
        );
        state.current_stage = "stage3".to_string();
        state.record_agent_message(
            "CLAIM% id=ID-01 category=auth target=routes/changePassword.ts severity=high confidence=high title=password_change_bypass reason=missing_current_password impact=account_takeover next=authorized_vs_attacker_password_change\n\
             CLAIM% id=INJ-CAND-01 category=injection target=routes/search.ts severity=critical confidence=high title=search_sqli reason=raw_sql impact=data_leak next=union_select_control",
        );

        let mut workflow =
            TriLaneWorkflow::new_from_stage("audit target".to_string(), "stage4")
                .expect("stage4 workflow");
        let WorkflowAction::Submit(prompt) = workflow.begin(&state) else {
            panic!("expected stage4 prompt");
        };

        assert!(prompt
            .prompt
            .contains("MERGE_PACKET% mode=s4_handoff phase=s4_auth_authz_session_controls"));
        assert!(prompt.prompt.contains("CLAIM% id=ID-01"));
        assert!(!prompt.prompt.contains("CLAIM% id=INJ-CAND-01"));
        assert!(!prompt.prompt.contains("CLAIM% id=OBL-01"));
        assert!(!prompt.prompt.contains("CANDIDATE% id=CAND-01"));
        assert!(!prompt.prompt.contains("ATTACK_ATOM% id=ATOM-01"));
        assert!(prompt.prompt.contains("cleanup=<read-only|restored|disposable|not-restored:reason>"));
        assert!(prompt.prompt.contains("exactly one VERIFY%, REJECTED%, or S4_SKIP%"));
    }

    #[test]
    fn s4_regression_sweep_is_late_blackbox_only() {
        let mut state = RunbookState::default();
        state.start_turn("audit target", AuditMode::Lab);
        state.current_stage = "stage3".to_string();
        state.record_agent_message(
            "CLAIM% id=ID-01 category=auth target=routes/changePassword.ts severity=high confidence=high title=password_change_bypass reason=missing_current_password impact=account_takeover next=authorized_vs_attacker_password_change",
        );

        let mut workflow =
            TriLaneWorkflow::new_from_stage("audit target".to_string(), "stage4")
                .expect("stage4 workflow");
        workflow.current = workflow
            .phases
            .iter()
            .position(|phase| phase.id == "s4_regression_sweep")
            .expect("regression sweep phase");
        let WorkflowAction::Submit(prompt) = workflow.begin(&state) else {
            panic!("expected s4 regression prompt");
        };

        assert!(prompt.prompt.contains("origin=late-blackbox"));
        assert!(prompt.prompt.contains("Do not re-probe represented families"));
        assert!(prompt
            .prompt
            .contains("MERGE_PACKET% mode=s4_handoff phase=s4_regression_sweep"));
    }

    #[test]
    fn s1_without_surface_gets_a_repair_prompt() {
        let mut state = RunbookState::default();
        state.start_turn("audit target", AuditMode::Lab);
        state.record_agent_message(
            "RUNBOOK% S0 Admission: target is reachable\nSERVICE_STATUS% reachable",
        );

        let mut workflow = TriLaneWorkflow::new("audit target".to_string());
        let _ = workflow.begin(&state);
        let WorkflowAction::Submit(s1) = workflow.after_turn_completed(&state) else {
            panic!("expected s1 prompt");
        };
        assert_eq!(s1.phase_id, "s1_route_surface");

        let WorkflowAction::Submit(repair) = workflow.after_turn_completed(&state) else {
            panic!("expected repair prompt");
        };
        assert!(repair.is_repair);
        assert_eq!(repair.phase_id, "s1_route_surface");
        assert!(repair.prompt.contains("WORKFLOW_REPAIR%"));
    }

    #[test]
    fn s1_read_targets_are_budgeted_source_assignments() {
        let workflow = TriLaneWorkflow::new("audit target".to_string());
        let s1_text = workflow
            .phases
            .iter()
            .filter(|phase| phase.stage_code == "S1")
            .map(|phase| format!("{}\n{}", phase.contract, phase.body))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(s1_text.contains("READ_TARGET_BUDGET% stage=s1 total_max=25"));
        assert!(s1_text.contains("SURFACE_BUDGET% stage=s1 total_max=90"));
        assert!(s1_text.contains("route_api_index"));
        assert!(s1_text.contains("auth_session_jwt_index"));
        assert!(s1_text.contains("object_ownership_index"));
        assert!(s1_text.contains("source_sink_index"));
        assert!(s1_text.contains("config_docs_debug_index"));
        assert!(s1_text.contains("login SQLi"));
        assert!(s1_text.contains("JWT forge or algorithm confusion"));
        assert!(s1_text.contains("basket/object ownership"));
        assert!(s1_text.contains("password reset/change"));
        assert!(s1_text.contains("2FA/security question/CAPTCHA"));
        assert!(s1_text.contains("wallet/coupon/deluxe/order/data export"));
        assert!(s1_text.contains("per_lane_max=5"));
        assert!(s1_text.contains("priority=high_only"));
        assert!(s1_text.contains("deduplicate by path+kind+category"));
        assert!(s1_text.contains("question=<source-to-sink-or-invariant-to-prove>"));
        assert!(s1_text.contains("stop_when=<fact-that-closes-or-delegates>"));
        assert!(s1_text.contains("broaden_after=<named-gap-that-justifies-extra-rg>"));
        assert!(s1_text.contains("Choose one primary lane"));
        assert!(s1_text.contains("Do not use marker names as Markdown headings"));
        assert!(s1_text.contains("emit OBLIGATION% debt instead of another READ_TARGET%"));
        assert!(s1_text.contains("category=<single-taxonomy-token>"));
        assert!(s1_text.contains("Never pack debt/source/sink/reason into category or target"));
    }

    #[test]
    fn s0_requires_service_status_marker_before_progressing() {
        let mut state = RunbookState::default();
        state.start_turn("audit target", AuditMode::Lab);
        let mut workflow = TriLaneWorkflow::new("audit target".to_string());
        let _ = workflow.begin(&state);

        state.record_agent_message("RUNBOOK% S0 Admission: source present, target pending");
        let WorkflowAction::Submit(repair) = workflow.after_turn_completed(&state) else {
            panic!("expected s0 repair prompt");
        };
        assert!(repair.is_repair);
        assert_eq!(repair.phase_id, "s0_admission");
        assert!(repair.prompt.contains("SERVICE_STATUS%"));

        state.record_agent_message("SERVICE_STATUS% started");
        let WorkflowAction::Submit(s1) = workflow.after_turn_completed(&state) else {
            panic!("expected s1 prompt after service status");
        };
        assert_eq!(s1.phase_id, "s1_route_surface");
    }

    #[test]
    fn s4_contract_rejects_blanket_skip_language() {
        let workflow = TriLaneWorkflow::new("audit target".to_string());
        let s4_text = workflow
            .phases
            .iter()
            .filter(|phase| phase.stage_code == "S4")
            .map(|phase| format!("{}\n{}", phase.contract, phase.body))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(s4_text.contains("Blanket skip is forbidden"));
        assert!(s4_text.contains("PROBE%"));
        assert!(s4_text.contains("CONTROL%"));
        assert!(s4_text.contains("S4_SKIP%"));
    }

    #[test]
    fn s4_repair_allows_additional_attempt_after_phase_progress_even_without_new_markers() {
        let mut state = RunbookState::default();
        state.start_turn("audit target", AuditMode::Lab);
        state.record_workflow_phase("stage4", "S4 targeted controls for auth/authz/session");

        let mut workflow = TriLaneWorkflow::new("audit target".to_string());
        while workflow.phases[workflow.current].id != "s4_auth_authz_session_controls" {
            workflow.current += 1;
        }
        workflow.phase_start = WorkflowCounters::from_state(&state);

        state.record_command(
            "curl -s http://127.0.0.1:5002/users/v1/login",
            Some("{\"auth_token\":\"abc\"}"),
            "Completed",
            Some(0),
        );
        let WorkflowAction::Submit(first_repair) = workflow.after_turn_completed(&state) else {
            panic!("expected first repair prompt");
        };
        assert!(first_repair.is_repair);
        assert_eq!(first_repair.phase_id, "s4_auth_authz_session_controls");

        let WorkflowAction::Submit(second_repair) = workflow.after_turn_completed(&state) else {
            panic!("expected progress-tolerant repair prompt");
        };
        assert!(second_repair.is_repair);
        assert_eq!(second_repair.phase_id, "s4_auth_authz_session_controls");
    }

    #[test]
    fn s4_probe_failure_defers_instead_of_blocking_entire_workflow() {
        let mut state = RunbookState::default();
        state.start_turn("audit target", AuditMode::Lab);
        let mut workflow = TriLaneWorkflow::new("audit target".to_string());
        while workflow.phases[workflow.current].id != "s4_auth_authz_session_controls" {
            workflow.current += 1;
        }
        let WorkflowAction::Submit(initial) = workflow.submit_current(&state, false) else {
            panic!("expected initial s4 prompt");
        };
        assert_eq!(initial.phase_id, "s4_auth_authz_session_controls");

        let WorkflowAction::Submit(repair) = workflow.after_turn_completed(&state) else {
            panic!("expected one s4 repair prompt");
        };
        assert!(repair.is_repair);
        assert_eq!(repair.phase_id, "s4_auth_authz_session_controls");

        let WorkflowAction::DeferPhase {
            phase_id,
            stage_id,
            next,
            ..
        } = workflow.after_turn_completed(&state)
        else {
            panic!("expected s4 deferral instead of hard block");
        };

        assert_eq!(phase_id, "s4_auth_authz_session_controls");
        assert_eq!(stage_id, "stage4");
        let WorkflowAction::Submit(next_prompt) = *next else {
            panic!("expected next s4 phase after deferral");
        };
        assert_eq!(next_prompt.phase_id, "s4_injection_xss_controls");
    }

    #[test]
    fn s2_is_single_backend_phase_for_workflow_scheduled_lanes() {
        let workflow = TriLaneWorkflow::new("audit target".to_string());
        let s2_phases = workflow
            .phases
            .iter()
            .filter(|phase| phase.stage_code == "S2")
            .collect::<Vec<_>>();

        assert_eq!(s2_phases.len(), 1);
        assert_eq!(s2_phases[0].id, "s2_parallel_semantic_audit");
        assert!(s2_phases[0]
            .body
            .contains("backend scheduler launches these core native child engines first"));
        assert!(s2_phases[0]
            .contract
            .contains("bounded provider-friendly concurrency"));
    }

    #[test]
    fn s2_phase_spawns_workflow_owned_lane_batch() {
        let mut state = RunbookState::default();
        state.start_turn("audit target", AuditMode::Lab);
        let mut workflow = TriLaneWorkflow::new("audit target".to_string());
        let _ = workflow.begin(&state);

        state.record_agent_message(
            "RUNBOOK% S0 Admission: target is reachable\nSERVICE_STATUS% reachable",
        );
        let WorkflowAction::Submit(s1_route) = workflow.after_turn_completed(&state) else {
            panic!("expected s1 route prompt");
        };
        assert_eq!(s1_route.phase_id, "s1_route_surface");

        state.record_agent_message(
            "SURFACE% kind=endpoint category=auth target=/rest/user/login label=login",
        );
        let WorkflowAction::Submit(s1_sink) = workflow.after_turn_completed(&state) else {
            panic!("expected s1 source/sink prompt");
        };
        assert_eq!(s1_sink.phase_id, "s1_source_sink");

        state.record_agent_message(
            "SURFACE% kind=sink category=injection target=routes/search.ts:23 label=raw_sql",
        );
        let WorkflowAction::SpawnLanes(batch) = workflow.after_turn_completed(&state) else {
            panic!("expected workflow-owned S2 lane batch");
        };

        assert_eq!(batch.phase_id, "s2_parallel_semantic_audit");
        assert_eq!(batch.lanes.len(), 5);
        assert_eq!(
            batch
                .lanes
                .iter()
                .map(|lane| lane.lane_id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "identity_engine",
                "injection_engine",
                "ingress_engine",
                "logic_engine",
                "config_engine"
            ]
        );
        assert!(batch
            .lanes
            .iter()
            .all(|lane| lane.prompt.contains("S1_LEDGER%")));
        assert!(batch
            .lanes
            .iter()
            .all(|lane| lane.prompt.contains("only machine-readable marker you may emit is CLAIM%")));
        assert!(batch
            .lanes
            .iter()
            .all(|lane| lane.prompt.contains("AGENT_RULES%")));
        assert!(batch
            .lanes
            .iter()
            .all(|lane| lane.prompt.contains("Act as a candidate lane")));
        for lane in &batch.lanes {
            for (head, tail) in [
                ("REJECTED", "%"),
                ("LANE_", "REPORT%"),
                ("PROBE", "%"),
                ("CONTROL", "%"),
                ("FINDING", "%"),
                ("ATTACK_", "ATOM%"),
                ("DUPLICATE", "%"),
                ("MERGE", "%"),
            ] {
                let forbidden = format!("{head}{tail}");
                assert!(
                    !lane.prompt.contains(&forbidden),
                    "{} prompt still contains {forbidden}",
                    lane.lane_id
                );
            }
        }
        assert!(batch
            .lanes
            .iter()
            .all(|lane| lane.prompt.contains("CVE_PRIOR%")));
        assert!(batch
            .lanes
            .iter()
            .all(|lane| lane.prompt.contains("Emit every credible CLAIM% candidate")));
    }

    #[test]
    fn s2_core_lanes_are_followed_by_residual_quick_hits() {
        let mut state = RunbookState::default();
        state.start_turn("audit target", AuditMode::Lab);

        let mut workflow = TriLaneWorkflow::new("audit target".to_string());
        while workflow.phases[workflow.current].id != "s2_parallel_semantic_audit" {
            workflow.current += 1;
        }
        let WorkflowAction::SpawnLanes(core_batch) = workflow.submit_current(&state, false) else {
            panic!("expected initial s2 core lane batch");
        };
        assert_eq!(core_batch.lanes.len(), 5);

        state.record_agent_message(
            "SUBAGENT% lane=identity_engine status=done claims=1 candidates=0 thread_id=t1 note=identity complete\n\
             CLAIM% id=IDENTITY-CAND-01 category=auth target=routes/login.ts status=anchored level=source title=\"identity finding\" root_cause=routes/login.ts impact=auth_bypass\n\
             SUBAGENT% lane=injection_engine status=done claims=1 candidates=0 thread_id=t2 note=injection complete\n\
             SUBAGENT% lane=ingress_engine status=done claims=1 candidates=0 thread_id=t3 note=ingress complete\n\
             SUBAGENT% lane=logic_engine status=done claims=1 candidates=0 thread_id=t4 note=logic complete\n\
             SUBAGENT% lane=config_engine status=done claims=1 candidates=0 thread_id=t5 note=config complete",
        );

        let WorkflowAction::SpawnLanes(quick_hits) = workflow.after_turn_completed(&state) else {
            panic!("expected residual quick_hits batch before S3");
        };

        assert!(!quick_hits.is_repair);
        assert_eq!(
            quick_hits
                .lanes
                .iter()
                .map(|lane| lane.lane_id.as_str())
                .collect::<Vec<_>>(),
            vec!["quick_hits_engine"]
        );
        assert!(quick_hits.lanes[0].prompt.contains("CORE_LANE_CONTEXT%"));
        assert!(quick_hits.lanes[0]
            .prompt
            .contains("Emit only new residual CLAIM% lines"));
    }

    #[test]
    fn s2_lanes_receive_source_packet_before_source_reads() {
        let mut state = RunbookState::default();
        state.start_turn("audit target", AuditMode::Lab);
        state.candidates.push(RunbookCandidate {
            id: "S1-OBL-03".to_string(),
            stage: "stage1".to_string(),
            category: "injection".to_string(),
            title: "routes/search.ts:29 raw SQL source=req.query.q sink=sequelize.query".to_string(),
            target: "routes/search.ts:29".to_string(),
            status: CandidateStatus::Candidate,
            severity: Some("high".to_string()),
            evidence_count: 2,
            verification_count: 0,
            source_confirmed: true,
            updated_at: "now".to_string(),
        });
        state.candidates.push(RunbookCandidate {
            id: "S1-OBL-04".to_string(),
            stage: "stage1".to_string(),
            category: "authz debt=BasketItems-IDOR source=server.ts:425".to_string(),
            title: "server.ts:425 appendUserId sink=ownership-check".to_string(),
            target: "unmapped-feature".to_string(),
            status: CandidateStatus::Candidate,
            severity: Some("high".to_string()),
            evidence_count: 2,
            verification_count: 0,
            source_confirmed: true,
            updated_at: "now".to_string(),
        });

        let mut workflow = TriLaneWorkflow::new("audit target".to_string());
        while workflow.phases[workflow.current].id != "s2_parallel_semantic_audit" {
            workflow.current += 1;
        }
        let WorkflowAction::SpawnLanes(batch) = workflow.submit_current(&state, false) else {
            panic!("expected initial s2 lane batch");
        };

        let injection = batch
            .lanes
            .iter()
            .find(|lane| lane.lane_id == "injection_engine")
            .expect("injection lane");
        assert!(injection.prompt.contains("SOURCE_PACKET% lane=injection_engine"));
        assert!(!injection.prompt.contains("max_items="));
        assert!(injection.prompt.contains("SOURCE_FACT% id=S1-OBL-03"));
        assert!(injection.prompt.contains("line_window:routes/search.ts:29"));
        assert!(injection
            .prompt
            .contains("Consume SOURCE_PACKET% and SCANNER_PACKET% first"));
        assert!(injection
            .prompt
            .contains("only machine-readable marker you may emit is CLAIM%"));
        assert!(injection.prompt.contains("SCANNER_PACKET%"));
        assert!(injection.prompt.contains("reason=<source->sink-short-proof>"));
        assert!(injection.prompt.contains("next=poc:<stable-poc-unit>"));
        assert!(injection.prompt.contains("Micro-verify"));

        let identity = batch
            .lanes
            .iter()
            .find(|lane| lane.lane_id == "identity_engine")
            .expect("identity lane");
        assert!(identity.prompt.contains("SOURCE_FACT% id=S1-OBL-04 category=authz"));
        assert!(identity.prompt.contains("target=server.ts:425"));
        assert!(identity.prompt.contains("Emit every credible CLAIM% candidate"));
        assert!(identity.prompt.contains("S4 verifies"));
        assert!(!identity.prompt.contains("category=authz debt="));
        assert!(!identity
            .prompt
            .contains("SOURCE_FACT% id=S1-OBL-04 category=authz target=unmapped-feature"));
    }

    #[test]
    fn s1_prompt_receives_scanner_context_without_new_output_schema() {
        let mut state = RunbookState::default();
        state.start_turn("Penetration test target, source code is in /no/such/root", AuditMode::Lab);
        let mut workflow = TriLaneWorkflow::new(state.objective.clone());
        let WorkflowAction::Submit(prompt) = workflow.submit_current(&state, false) else {
            panic!("expected s0 submit");
        };

        assert!(!prompt.prompt.contains("SCANNER_CONTEXT%"));

        let mut workflow = TriLaneWorkflow::new(state.objective.clone());
        while workflow.phases[workflow.current].id != "s1_route_surface" {
            workflow.current += 1;
        }
        let WorkflowAction::Submit(prompt) = workflow.submit_current(&state, false) else {
            panic!("expected s1 submit");
        };
        assert!(prompt.prompt.contains("SCANNER_CONTEXT%"));
        assert!(prompt.prompt.contains("AGENT_RULES%"));
        assert!(prompt.prompt.contains("Act as a security indexer for S2"));
        assert!(prompt.prompt.contains("SCANNER_PACKET% status=disabled"));
        assert!(prompt
            .prompt
            .contains("Convert high-value SCANNER_FACT% lines into existing READ_TARGET% or OBLIGATION% rows"));
    }

    #[test]
    fn s2_lanes_follow_s1_read_targets() {
        let mut state = RunbookState::default();
        state.start_turn("audit target", AuditMode::Lab);
        state.record_agent_message(
            "RUNBOOK% S1 Recon: route and source read targets\n\
             READ_TARGET% lane=identity_engine priority=high category=authz kind=endpoint-control path=routes/basket.ts lines=1-160 endpoint=/api/BasketItems object_id=body.BasketId auth_hint=middleware ownership_hint=unknown reason=object_id_write_without_obvious_owner_check question=prove_user_bid_controls_body_BasketId stop_when=owner_check_found_or_missing broaden_after=shared_basket_helper follow=middleware/auth.ts,models/Basket.ts",
        );

        let mut workflow = TriLaneWorkflow::new("audit target".to_string());
        while workflow.phases[workflow.current].id != "s2_parallel_semantic_audit" {
            workflow.current += 1;
        }
        let WorkflowAction::SpawnLanes(batch) = workflow.submit_current(&state, false) else {
            panic!("expected initial s2 lane batch");
        };

        let identity = batch
            .lanes
            .iter()
            .find(|lane| lane.lane_id == "identity_engine")
            .expect("identity lane");
        assert!(identity.prompt.contains("Follow S1 READ_TARGET% items"));
        assert!(identity
            .prompt
            .contains("READ_TARGET% category=authz target=routes/basket.ts"));
        assert!(identity.prompt.contains("ownership_hint=unknown"));
        assert!(identity
            .prompt
            .contains("question=prove_user_bid_controls_body_BasketId"));
        assert!(identity.prompt.contains("broaden_after=shared_basket_helper"));
    }

    #[test]
    fn quick_hits_prompt_is_a_fixed_residual_checklist() {
        let mut state = RunbookState::default();
        state.start_turn("audit target", AuditMode::Lab);
        state.record_agent_message(
            "SUBAGENT% lane=identity_engine status=done claims=1 candidates=0 note=identity complete\n\
             SUBAGENT% lane=injection_engine status=done claims=1 candidates=0 note=injection complete\n\
             SUBAGENT% lane=ingress_engine status=done claims=1 candidates=0 note=ingress complete\n\
             SUBAGENT% lane=logic_engine status=done claims=1 candidates=0 note=logic complete\n\
             SUBAGENT% lane=config_engine status=done claims=1 candidates=0 note=config complete",
        );

        let mut workflow = TriLaneWorkflow::new("audit target".to_string());
        while workflow.phases[workflow.current].id != "s2_parallel_semantic_audit" {
            workflow.current += 1;
        }
        let WorkflowAction::SpawnLanes(batch) = workflow.submit_current(&state, false) else {
            panic!("expected quick_hits batch");
        };

        assert_eq!(batch.lanes.len(), 1);
        let prompt = &batch.lanes[0].prompt;
        assert!(prompt.contains("QUICK_HITS_CHECKLIST%"));
        assert!(prompt.contains("JWT none/HS256/key confusion"));
        assert!(prompt.contains("No exploratory prose or self-debate"));
        assert!(prompt.contains("Use bounded rg/sed source reads as needed"));
        assert!(prompt.contains("Emit every credible QH-CAND-* claim"));
        assert!(prompt.contains("Emit only new residual CLAIM% lines"));
        assert!(prompt.contains("only machine-readable marker you may emit is CLAIM%"));
        assert!(prompt.contains("SOURCE_PACKET% lane=quick_hits_engine"));
        assert!(prompt.contains("SCANNER_PACKET%"));
    }

    #[test]
    fn s3_and_s4_packets_carry_poc_units() {
        let mut state = RunbookState::default();
        state.start_turn("audit target", AuditMode::Lab);
        state.record_agent_message(
            "CLAIM% id=ID-001 category=session target=lib/jwt.ts:10 severity=high confidence=high title=JWT none algorithm reason=source->sink: jwt verify accepts none impact=auth_bypass next=poc:jwt-none\n\
             CLAIM% id=ID-002 category=session target=lib/jwt.ts:10 severity=high confidence=high title=JWT HS256 confusion reason=source->sink: key confusion impact=auth_bypass next=poc:jwt-hs256-confusion",
        );

        let s3 = super::compact_s3_claim_pool(&state, 20);
        assert!(s3.contains("next=poc:jwt-none"));
        assert!(s3.contains("next=poc:jwt-hs256-confusion"));

        state.record_agent_message(
            "CLAIM% id=ID-001 category=session target=lib/jwt.ts:10 status=seed level=signal severity=high title=JWT none algorithm reason=source impact=auth_bypass next=poc:jwt-none\n\
             CLAIM% id=ID-002 category=session target=lib/jwt.ts:10 status=seed level=signal severity=high title=JWT HS256 confusion reason=source impact=auth_bypass next=poc:jwt-hs256-confusion",
        );
        let s4 = super::compact_s4_handoff_packet(&state, "s4_auth_authz_session_controls", 20);
        assert!(s4.contains("next=poc:jwt-none"));
        assert!(s4.contains("next=poc:jwt-hs256-confusion"));
    }

    #[test]
    fn s2_optional_quick_hits_empty_claim_set_does_not_block_core_lanes() {
        let mut state = RunbookState::default();
        state.start_turn("audit target", AuditMode::Lab);

        let mut workflow = TriLaneWorkflow::new("audit target".to_string());
        while workflow.phases[workflow.current].id != "s2_parallel_semantic_audit" {
            workflow.current += 1;
        }
        let WorkflowAction::SpawnLanes(_) = workflow.submit_current(&state, false) else {
            panic!("expected initial s2 lane batch");
        };

        state.record_agent_message(
            "SUBAGENT% lane=identity_engine status=done claims=2 candidates=0 note=identity complete\n\
             CLAIM% id=IDENTITY-CAND-01 category=auth target=routes/login.ts status=anchored level=source title=\"identity finding\" root_cause=routes/login.ts impact=auth_bypass\n\
             SUBAGENT% lane=injection_engine status=done claims=2 candidates=0 note=injection complete\n\
             CLAIM% id=INJECTION-CAND-01 category=injection target=routes/search.ts status=anchored level=source title=\"injection finding\" root_cause=routes/search.ts impact=data_exfiltration\n\
             SUBAGENT% lane=ingress_engine status=done claims=2 candidates=0 note=ingress complete\n\
             CLAIM% id=INGRESS-CAND-01 category=file_upload_xxe target=routes/fileUpload.ts status=anchored level=source title=\"ingress finding\" root_cause=routes/fileUpload.ts impact=file_disclosure\n\
             SUBAGENT% lane=logic_engine status=done claims=2 candidates=0 note=logic complete\n\
             CLAIM% id=LOGIC-CAND-01 category=state_invariant_abuse target=routes/deluxe.ts status=anchored level=source title=\"logic finding\" root_cause=routes/deluxe.ts impact=free_deluxe\n\
             SUBAGENT% lane=config_engine status=done claims=2 candidates=0 note=config complete\n\
             CLAIM% id=CONFIG-CAND-01 category=crypto target=lib/insecurity.ts status=anchored level=source title=\"config finding\" root_cause=lib/insecurity.ts impact=jwt_forgery\n\
             SUBAGENT% lane=quick_hits_engine status=done claims=0 candidates=0 note=quick hits empty",
        );

        let WorkflowAction::Submit(next) = workflow.after_turn_completed(&state) else {
            panic!("expected S3 prompt instead of S2 repair/block");
        };

        assert_eq!(next.phase_id, "s3_merge_foa");
    }

    #[test]
    fn s2_subagent_done_without_extra_markers_advances_to_s3() {
        let mut state = RunbookState::default();
        state.start_turn("audit target", AuditMode::Lab);

        let mut workflow = TriLaneWorkflow::new("audit target".to_string());
        while workflow.phases[workflow.current].id != "s2_parallel_semantic_audit" {
            workflow.current += 1;
        }
        let WorkflowAction::SpawnLanes(_) = workflow.submit_current(&state, false) else {
            panic!("expected initial s2 lane batch");
        };

        state.record_agent_message(
            "SUBAGENT% lane=identity_engine status=done claims=0 candidates=0 thread_id=t1\n\
             SUBAGENT% lane=injection_engine status=done claims=0 candidates=0 thread_id=t2\n\
             SUBAGENT% lane=ingress_engine status=done claims=0 candidates=0 thread_id=t3\n\
             SUBAGENT% lane=logic_engine status=done claims=0 candidates=0 thread_id=t4\n\
             SUBAGENT% lane=config_engine status=done claims=0 candidates=0 thread_id=t5\n\
             SUBAGENT% lane=quick_hits_engine status=done claims=0 candidates=0 thread_id=t6",
        );

        let WorkflowAction::Submit(next) = workflow.after_turn_completed(&state) else {
            panic!("expected S3 prompt after scheduler-owned S2 lanes");
        };

        assert_eq!(next.phase_id, "s3_merge_foa");
    }

    #[test]
    fn s2_empty_core_claim_sets_can_advance_to_s3() {
        let mut state = RunbookState::default();
        state.start_turn("audit target", AuditMode::Lab);

        let mut workflow = TriLaneWorkflow::new("audit target".to_string());
        while workflow.phases[workflow.current].id != "s2_parallel_semantic_audit" {
            workflow.current += 1;
        }
        let WorkflowAction::SpawnLanes(_) = workflow.submit_current(&state, false) else {
            panic!("expected initial s2 lane batch");
        };

        state.record_agent_message(
            "SUBAGENT% lane=identity_engine status=done claims=0 candidates=0 note=no identity findings\n\
             SUBAGENT% lane=injection_engine status=done claims=0 candidates=0 note=no injection findings\n\
             SUBAGENT% lane=ingress_engine status=done claims=0 candidates=0 note=no ingress findings\n\
             SUBAGENT% lane=logic_engine status=done claims=0 candidates=0 note=no logic findings\n\
             SUBAGENT% lane=config_engine status=done claims=0 candidates=0 note=no config findings",
        );

        let WorkflowAction::SpawnLanes(quick_hits) = workflow.after_turn_completed(&state) else {
            panic!("expected quick_hits before S3");
        };

        assert_eq!(quick_hits.lanes.len(), 1);
        assert_eq!(quick_hits.lanes[0].lane_id, "quick_hits_engine");

        state.record_agent_message(
            "SUBAGENT% lane=quick_hits_engine status=done claims=0 candidates=0 note=no residual findings",
        );
        let WorkflowAction::Submit(next) = workflow.after_turn_completed(&state) else {
            panic!("expected S3 prompt after quick_hits");
        };
        assert_eq!(next.phase_id, "s3_merge_foa");
    }

    #[test]
    fn s5_draft_poc_bundle_is_followed_by_advisory_review_lane() {
        let mut state = RunbookState::default();
        state.start_turn("audit target", AuditMode::Lab);
        let mut workflow = TriLaneWorkflow::new("audit target".to_string());

        while workflow.phases[workflow.current].id != "s5_adjudication_report" {
            workflow.current += 1;
        }

        state.record_agent_message(
            "RUNBOOK% S5 Verify\nFINDING% id=AUTH-01 severity=critical code_path=routes/login.ts confidence=high title=SQL injection evidence=raw SQL payload=' OR 1=1 --",
        );
        let WorkflowAction::SpawnLanes(batch) = workflow.after_turn_completed(&state) else {
            panic!("expected S5 review lane");
        };

        assert_eq!(batch.phase_id, "s5_adversarial_review");
        assert_eq!(batch.stage_id, "stage5");
        assert_eq!(batch.lanes.len(), 1);
        assert_eq!(batch.lanes[0].lane_id, "poc_bundle_review");
        assert!(batch.lanes[0].prompt.contains("FINAL_POC_BUNDLE_DRAFT%"));
        assert!(batch.lanes[0].prompt.contains("REVIEW_REPORT%"));
        assert!(batch.lanes[0].prompt.contains("Do not run tools"));
        assert!(batch.lanes[0].prompt.contains("bounded advisory PoC reviewer"));
        assert!(batch.lanes[0]
            .prompt
            .contains("recommend generated-not-verified or needs-poc instead"));
        assert!(batch.lanes[0]
            .prompt
            .contains("one attempted payload path failed"));
        assert!(batch.lanes[0].prompt.contains("AGENT_RULES%"));
        assert!(batch.lanes[0].prompt.contains("bounded reviewer"));
    }

    #[test]
    fn s5_review_context_is_returned_to_root_for_final_revision() {
        let mut state = RunbookState::default();
        state.start_turn("audit target", AuditMode::Lab);
        state.record_subagent_lane(crate::runbook::RunbookLaneUpdate {
            stage: "stage5",
            lane_id: "poc_bundle_review",
            status: "done",
            claim_count: Some(0),
            candidate_count: Some(0),
            thread_id: Some("thread-review"),
            summary: "review complete",
        });
        state.record_agent_message(
            "REVIEW% action=drop target=VULN-009 reason=duplicate confidence=high\nREVIEW_REPORT% lane=poc_bundle_review status=done comments=1 critical=1 note=drop duplicate",
        );

        let mut workflow = TriLaneWorkflow::new("audit target".to_string());
        while workflow.phases[workflow.current].id != "s5_adversarial_review" {
            workflow.current += 1;
        }

        let WorkflowAction::Submit(prompt) = workflow.after_turn_completed(&state) else {
            panic!("expected final revision prompt");
        };

        assert_eq!(prompt.phase_id, "s5_final_revision");
        assert!(prompt.prompt.contains("REVIEW_CONTEXT%"));
        assert!(prompt.prompt.contains("REVIEW% action=drop"));
        assert!(prompt.prompt.contains("RUNBOOK% S5 Final Revision"));
        assert!(prompt.prompt.contains("Output-only correction pass"));
        assert!(prompt.prompt.contains("REVIEW_CONTEXT is advisory"));
        assert!(prompt.prompt.contains("Preserve recall"));
        assert!(prompt
            .prompt
            .contains("replacement canonical POC% set"));
    }

    #[test]
    fn s5_review_lane_done_without_markers_advances_with_empty_review_context() {
        let mut state = RunbookState::default();
        state.start_turn("audit target", AuditMode::Lab);
        state.record_subagent_lane(crate::runbook::RunbookLaneUpdate {
            stage: "stage5",
            lane_id: "poc_bundle_review",
            status: "done",
            claim_count: Some(0),
            candidate_count: Some(0),
            thread_id: Some("thread-review"),
            summary: "review complete without markers",
        });
        state.record_agent_message(
            "RUNBOOK% S5 Verify: adversarial review of draft.\nLet me verify a few high-signal claims.",
        );

        let mut workflow = TriLaneWorkflow::new("audit target".to_string());
        while workflow.phases[workflow.current].id != "s5_adversarial_review" {
            workflow.current += 1;
        }

        let WorkflowAction::Submit(prompt) = workflow.after_turn_completed(&state) else {
            panic!("expected final revision prompt");
        };

        assert_eq!(prompt.phase_id, "s5_final_revision");
        assert!(prompt.prompt.contains("REVIEW_CONTEXT%"));
        assert!(prompt.prompt.contains(
            "REVIEW_REPORT% lane=poc_bundle_review status=missing comments=0 critical=0"
        ));
    }
