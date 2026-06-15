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
