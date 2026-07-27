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
    fn streaming_delta_parser_keeps_s2_lane_markers() {
        assert!(is_visual_runbook_delta_marker(
            "CLAIM% id=ID-CAND-01 category=auth target=routes/login.ts"
        ));
        assert!(is_visual_runbook_delta_marker(
            "SUBAGENT% lane=identity_engine status=done claims=1 candidates=1"
        ));
        assert!(is_visual_runbook_delta_marker(
            "`DUPLICATE% id=QH-DUP-01 merge_into=CONFIG-CAND-01`"
        ));
        assert!(!is_visual_runbook_delta_marker(
            "This is ordinary reasoning prose without a marker."
        ));
    }

    #[test]
    fn lane_batch_tracks_idle_running_lanes() {
        let batch = WorkflowLaneBatch {
            phase_id: "s2_parallel_semantic_audit".to_string(),
            stage_id: "stage2".to_string(),
            title: "S2 concurrent audit".to_string(),
            lanes: vec![test_lane("identity_engine"), test_lane("config_engine")],
            is_repair: false,
        };
        let mut active = ActiveLaneBatch::new(&batch, /*max_concurrency*/ 2);
        active.lanes[0].mark_starting();
        active.lanes[0].thread_id = "thread-a".to_string();
        active.lanes[0].turn_id = Some("turn-a".to_string());
        active.lanes[0].last_activity_at = Some(Instant::now() - Duration::from_secs(700));
        active.lanes[1].mark_starting();
        active.lanes[1].thread_id = "thread-b".to_string();
        active.lanes[1].turn_id = Some("turn-b".to_string());
        active.mark_activity("thread-b", "turn-b");

        assert_eq!(
            active.idle_running_lane_indices(Instant::now(), Duration::from_secs(600)),
            vec![0]
        );
        assert_eq!(active.lane_index_by_event("wrong-thread", "turn-b"), Some(1));
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

    #[test]
    fn provider_ids_are_safe_toml_table_keys() {
        assert!(valid_provider_id("company-deepseek"));
        assert!(valid_provider_id("gateway_2"));
        assert!(!valid_provider_id("Company deepseek"));
        assert!(!valid_provider_id("provider.name"));
    }
