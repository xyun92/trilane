fn workflow_lane_concurrency() -> usize {
    std::env::var("TRILANE_LANE_CONCURRENCY")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| (1..=5).contains(value))
        .unwrap_or(DEFAULT_WORKFLOW_LANE_CONCURRENCY)
}

fn workflow_lane_retry_delay(attempt: u8) -> Duration {
    let seconds = match attempt {
        0 | 1 => 20,
        2 => 45,
        _ => 90,
    };
    Duration::from_secs(seconds)
}

fn is_retryable_lane_error(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("429")
        || lower.contains("too many requests")
        || lower.contains("rate limit")
        || lower.contains("rate_limit")
        || lower.contains("exceeded retry limit")
        || lower.contains("temporarily unavailable")
        || lower.contains("timeout")
}

fn requires_workflow_lane_report(phase_id: &str, lane_id: &str) -> bool {
    phase_id == "s2_parallel_semantic_audit"
        && matches!(
            lane_id,
            "identity_engine" | "injection_engine" | "ingress_engine" | "logic_engine" | "config_engine"
        )
}

fn missing_lane_report_repair_prompt(original_prompt: &str, lane_id: &str) -> String {
    if original_prompt.contains("WORKFLOW_LANE_REPAIR% missing_lane_report") {
        return original_prompt.to_string();
    }
    format!(
        "AUDIT_MODE% TRILANE\n\
         WORKFLOW_LANE_REPAIR% missing_lane_report lane={lane_id}\n\
         The previous lane turn completed without a machine-readable LANE_REPORT% marker, so the scheduler could not join S2.\n\
         Stay inside lane={lane_id}. Emit compact ledger markers only for this lane. Do not act as the root agent, do not restart S0/S1, and do not write the final report.\n\
         Close with exactly one line: LANE_REPORT% lane={lane_id} status=done claims=<n> candidates=<n> note=<short>.\n\
         If no supported claim exists, emit claims=0 candidates=0 with a brief evidence-backed note.\n\n\
         ORIGINAL_LANE_PROMPT%\n\
         {original_prompt}"
    )
}

fn synthesized_missing_lane_report_marker(lane_id: &str) -> String {
    format!(
        "LANE_REPORT% lane={lane_id} status=done claims=0 candidates=0 note=scheduler_synthesized_missing_lane_report"
    )
}

fn retry_status_summary(error: &str, attempt: u8, delay: Duration) -> String {
    format!(
        "provider backoff after retryable error; attempt={attempt}/{WORKFLOW_LANE_MAX_ATTEMPTS} retry_after={}s error={}",
        delay.as_secs(),
        truncate_for_status(error, 180)
    )
}

fn truncate_for_status(value: &str, max_chars: usize) -> String {
    let value = value.trim();
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    let mut truncated = value.chars().take(max_chars).collect::<String>();
    truncated.push_str("...");
    truncated
}

fn looks_like_status_query(text: &str) -> bool {
    let normalized = text.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return false;
    }
    [
        "status",
        "progress",
        "done?",
        "finished?",
        "finished",
        "still running",
        "how far",
        "update",
        "好了吗",
        "好没",
        "进度",
        "状态",
        "还在跑",
        "跑完",
        "结束了吗",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
}

fn running_turn_status_message(runbook: &RunbookState) -> String {
    let stage = runbook
        .stages
        .iter()
        .find(|stage| stage.id == runbook.current_stage);
    let stage_label = stage
        .map(|stage| format!("{} {}", stage.code, stage.name))
        .unwrap_or_else(|| runbook.current_stage.clone());
    let stage_summary = stage
        .map(|stage| stage.summary.trim())
        .filter(|summary| !summary.is_empty())
        .unwrap_or("awaiting stage update");
    let lane_summary = runbook
        .lanes
        .iter()
        .filter(|lane| lane.stage == runbook.current_stage)
        .map(|lane| format!("{}:{}", lane.lane_id, lane.status))
        .collect::<Vec<_>>();
    let lane_text = if lane_summary.is_empty() {
        "none".to_string()
    } else {
        lane_summary.join(", ")
    };

    format!(
        "SYS% backend turn still active\nRUNBOOK% stage={} summary={}\nRUNBOOK% findings={} candidates={} root_claims={} probed={}\nRUNBOOK% lanes={}\nRUNBOOK% objective={}",
        stage_label,
        truncate_for_status(stage_summary, 180),
        runbook.stats.confirmed,
        runbook.stats.candidates,
        runbook.stats.root_claims,
        runbook.stats.probed,
        truncate_for_status(&lane_text, 220),
        truncate_for_status(&runbook.objective, 220),
    )
}

enum AgentCommand {
    SendMessage {
        text: String,
        audit_mode: AuditMode,
    },
    Approve {
        request_id: String,
        decision: String,
    },
    Shutdown,
}
