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
        assert!(final_phase.body.contains("replacement final set"));
    }

    #[test]
    fn s1_without_surface_gets_a_repair_prompt() {
        let mut state = RunbookState::default();
        state.start_turn("audit target", AuditMode::Lab);
        state.record_agent_message("RUNBOOK% S0 Admission: target is reachable");

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
            .contains("backend scheduler launches these six native child engines"));
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

        state.record_agent_message("RUNBOOK% S0 Admission: target is reachable");
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
        assert_eq!(batch.lanes.len(), 6);
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
                "config_engine",
                "edge_surface_engine"
            ]
        );
        assert!(batch
            .lanes
            .iter()
            .all(|lane| lane.prompt.contains("S1_LEDGER%")));
        assert!(batch
            .lanes
            .iter()
            .all(|lane| lane.prompt.contains("LANE_REPORT%")));
        assert!(batch
            .lanes
            .iter()
            .all(|lane| lane.prompt.contains("CVE_PRIOR%")));
        assert!(batch
            .lanes
            .iter()
            .all(|lane| lane.prompt.contains("OBLIGATION%")));
        assert!(batch
            .lanes
            .iter()
            .all(|lane| lane.prompt.contains("cross-lane weak-signal OBLIGATION% seeds")));
    }

    #[test]
    fn s2_subagent_done_without_lane_reports_can_advance_release_path() {
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
             SUBAGENT% lane=edge_surface_engine status=done claims=0 candidates=0 thread_id=t3\n\
             SUBAGENT% lane=ingress_engine status=done claims=0 candidates=0 thread_id=t4\n\
             SUBAGENT% lane=logic_engine status=done claims=0 candidates=0 thread_id=t5\n\
             SUBAGENT% lane=config_engine status=done claims=0 candidates=0 thread_id=t6\n\
             CLAIM% id=S2-CAND-01 category=injection target=routes/login.ts title=Login SQL injection",
        );

        let WorkflowAction::Submit(prompt) = workflow.after_turn_completed(&state) else {
            panic!("expected S3 prompt");
        };

        assert_eq!(prompt.phase_id, "s3_merge_foa");
        assert!(!prompt.is_repair);
    }

    #[test]
    fn s5_draft_report_is_followed_by_adversarial_review_lane() {
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
        assert_eq!(batch.lanes[0].lane_id, "final_report_review");
        assert!(batch.lanes[0].prompt.contains("FINAL_REPORT_DRAFT%"));
        assert!(batch.lanes[0].prompt.contains("REVIEW_REPORT%"));
        assert!(batch.lanes[0].prompt.contains("Do not run tools"));
        assert!(batch.lanes[0].prompt.contains("bounded advisory report reviewer"));
        assert!(batch.lanes[0]
            .prompt
            .contains("recommend downgrade/rewrite/needs-poc instead"));
        assert!(batch.lanes[0]
            .prompt
            .contains("one attempted payload path failed"));
    }

    #[test]
    fn s5_review_context_is_returned_to_root_for_final_revision() {
        let mut state = RunbookState::default();
        state.start_turn("audit target", AuditMode::Lab);
        state.record_subagent_lane(crate::runbook::RunbookLaneUpdate {
            stage: "stage5",
            lane_id: "final_report_review",
            status: "done",
            claim_count: Some(0),
            candidate_count: Some(0),
            thread_id: Some("thread-review"),
            summary: "review complete",
        });
        state.record_agent_message(
            "REVIEW% action=drop target=VULN-009 reason=duplicate confidence=high\nREVIEW_REPORT% lane=final_report_review status=done comments=1 critical=1 note=drop duplicate",
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
            .contains("failed payload variant or failed alternate exploit chain"));
    }

    #[test]
    fn s5_review_lane_done_without_markers_advances_with_empty_review_context() {
        let mut state = RunbookState::default();
        state.start_turn("audit target", AuditMode::Lab);
        state.record_subagent_lane(crate::runbook::RunbookLaneUpdate {
            stage: "stage5",
            lane_id: "final_report_review",
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
            "REVIEW_REPORT% lane=final_report_review status=missing comments=0 critical=0"
        ));
    }
