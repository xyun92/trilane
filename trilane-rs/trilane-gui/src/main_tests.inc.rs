    fn test_lane(id: &str) -> WorkflowLaneSpec {
        WorkflowLaneSpec {
            lane_id: id.to_string(),
            title: id.to_string(),
            prompt: "audit this lane".to_string(),
        }
    }

    #[test]
    fn retryable_lane_errors_cover_provider_rate_limits() {
        assert!(is_retryable_lane_error(
            "exceeded retry limit, last status: 429 Too Many Requests"
        ));
        assert!(is_retryable_lane_error("provider rate_limit was reached"));
        assert!(!is_retryable_lane_error("invalid model name"));
    }

    #[test]
    fn s2_core_lanes_require_lane_report_but_quick_hits_does_not() {
        assert!(requires_workflow_lane_report(
            "s2_parallel_semantic_audit",
            "identity_engine"
        ));
        assert!(requires_workflow_lane_report(
            "s2_parallel_semantic_audit",
            "config_engine"
        ));
        assert!(!requires_workflow_lane_report(
            "s2_parallel_semantic_audit",
            "quick_hits_engine"
        ));
        assert!(!requires_workflow_lane_report(
            "s5_adversarial_review",
            "final_report_review"
        ));
    }

    #[test]
    fn missing_lane_report_repair_prompt_is_idempotent_and_lane_scoped() {
        let prompt = missing_lane_report_repair_prompt("original prompt", "identity_engine");

        assert!(prompt.contains("WORKFLOW_LANE_REPAIR% missing_lane_report lane=identity_engine"));
        assert!(prompt.contains("Do not act as the root agent"));
        assert!(prompt.contains("LANE_REPORT% lane=identity_engine status=done"));
        assert!(prompt.contains("ORIGINAL_LANE_PROMPT%"));
        assert_eq!(
            missing_lane_report_repair_prompt(&prompt, "identity_engine"),
            prompt
        );
    }

    #[test]
    fn synthesized_missing_lane_report_marker_closes_core_lane() {
        let marker = synthesized_missing_lane_report_marker("injection_engine");
        let mut state = RunbookState::default();

        state.record_workflow_phase("stage2", "S2 concurrent 6-lane semantic audit");
        state.record_agent_message(&marker);

        let lane = state
            .lanes
            .iter()
            .find(|lane| lane.lane_id == "injection_engine")
            .expect("injection lane should be recorded");
        assert!(marker.contains("LANE_REPORT% lane=injection_engine status=done claims=0 candidates=0"));
        assert_eq!(lane.status, "done");
        assert!(lane.report_seen);
        assert_eq!(lane.claim_count, 0);
        assert_eq!(lane.candidate_count, 0);
    }

    #[test]
    fn lane_batch_tracks_retry_without_completing_batch() {
        let batch = WorkflowLaneBatch {
            phase_id: "s2_parallel_semantic_audit".to_string(),
            stage_id: "stage2".to_string(),
            title: "S2 concurrent 6-lane semantic audit".to_string(),
            lanes: vec![test_lane("auth"), test_lane("business")],
            is_repair: false,
        };
        let mut active = ActiveLaneBatch::new(&batch, /*max_concurrency*/ 1);
        active.lanes[0].mark_starting();
        active.lanes[0].thread_id = "thread-a".to_string();
        active.lanes[0].attempts = 1;

        let delay = active.retry_lane(0, "429 Too Many Requests");

        assert!(delay > Duration::from_secs(0));
        assert_eq!(active.lanes[0].status, ActiveLaneStatus::Queued);
        assert!(!active.all_complete());
        assert_eq!(active.running_count(), 0);
    }
