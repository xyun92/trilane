async fn update_runbook_from_item(
    app: &AppHandle,
    item: &codex_app_server_protocol::ThreadItem,
    frontend_text: &Option<String>,
) {
    mutate_runbook(app, |runbook| {
        match item {
            codex_app_server_protocol::ThreadItem::AgentMessage { text, .. } => {
                runbook.record_agent_message(text);
            }
            codex_app_server_protocol::ThreadItem::Reasoning {
                summary, content, ..
            } => {
                let text = if !content.is_empty() {
                    content.join("\n")
                } else {
                    summary.join("\n")
                };
                runbook.record_reasoning(&text);
            }
            codex_app_server_protocol::ThreadItem::CommandExecution {
                command,
                status,
                aggregated_output,
                exit_code,
                ..
            } => {
                runbook.record_command(
                    command,
                    aggregated_output.as_deref(),
                    &format!("{status:?}"),
                    *exit_code,
                );
            }
            _ => {
                if let Some(text) = frontend_text {
                    runbook.record_agent_message(text);
                }
            }
        }
    })
    .await;
}

async fn update_runbook_from_agent_delta(app: &AppHandle, item_id: &str, delta: &str) {
    let marker_lines = {
        let state = app.state::<AppState>();
        let mut buffers = state.agent_delta_marker_buffers.lock().await;
        let buffer = buffers.entry(item_id.to_string()).or_default();
        buffer.push_str(delta);
        if buffer.len() > 16_384 {
            let keep_from = buffer.len().saturating_sub(8_192);
            buffer.drain(..keep_from);
        }
        let mut completed = Vec::new();
        while let Some(newline) = buffer.find('\n') {
            let line = buffer[..newline].to_string();
            buffer.drain(..=newline);
            if is_visual_runbook_delta_marker(&line) {
                completed.push(line);
            }
        }
        completed
    };

    if marker_lines.is_empty() {
        return;
    }

    queue_runbook_marker_lines(app, marker_lines).await;
}

async fn queue_runbook_marker_lines(app: &AppHandle, marker_lines: Vec<String>) {
    if marker_lines.is_empty() {
        return;
    }

    let should_flush = {
        let state = app.state::<AppState>();
        let mut pending = state.pending_runbook_markers.lock().await;
        if pending.lines.is_empty() {
            pending.queued_at = Some(Instant::now());
        }
        pending.lines.extend(marker_lines);
        pending.lines.len() >= RUNBOOK_MARKER_FLUSH_BATCH_LINES
            || pending
                .queued_at
                .is_some_and(|queued_at| queued_at.elapsed() >= RUNBOOK_MARKER_FLUSH_INTERVAL)
    };

    if should_flush {
        flush_pending_runbook_markers(app).await;
    }
}

async fn flush_pending_runbook_markers(app: &AppHandle) {
    let marker_text = {
        let state = app.state::<AppState>();
        let mut pending = state.pending_runbook_markers.lock().await;
        if pending.lines.is_empty() {
            pending.queued_at = None;
            None
        } else {
            let joined = pending.lines.join("\n");
            pending.lines.clear();
            pending.queued_at = None;
            Some(joined)
        }
    };

    if let Some(marker_text) = marker_text {
        mutate_runbook(app, |runbook| {
            runbook.record_agent_message(&marker_text);
        })
        .await;
    }
}

async fn clear_agent_delta_buffers(app: &AppHandle) {
    let state = app.state::<AppState>();
    state.agent_delta_marker_buffers.lock().await.clear();
    let mut pending = state.pending_runbook_markers.lock().await;
    pending.lines.clear();
    pending.queued_at = None;
}

fn is_visual_runbook_delta_marker(line: &str) -> bool {
    let trimmed = line
        .trim()
        .trim_matches('`')
        .trim_matches('"')
        .trim()
        .to_ascii_lowercase();
    ["feature%", "surface%", "coverage%"]
        .iter()
        .any(|prefix| trimmed.starts_with(prefix))
}

fn frontend_item_completed_payload(
    item: &codex_app_server_protocol::ThreadItem,
) -> (String, Option<String>, Option<String>) {
    match item {
        codex_app_server_protocol::ThreadItem::AgentMessage { text, .. } => (
            "agent_message".to_string(),
            Some("assistant".to_string()),
            Some(text.clone()),
        ),
        codex_app_server_protocol::ThreadItem::CommandExecution {
            command,
            status,
            aggregated_output,
            exit_code,
            duration_ms,
            ..
        } => (
            "command_execution".to_string(),
            Some("system".to_string()),
            Some(format_command_execution(
                command,
                status,
                aggregated_output.as_deref(),
                *exit_code,
                *duration_ms,
            )),
        ),
        codex_app_server_protocol::ThreadItem::Reasoning {
            summary, content, ..
        } => {
            let text = if !content.is_empty() {
                content.join("\n")
            } else {
                summary.join("\n")
            };
            (
                "reasoning".to_string(),
                Some("system".to_string()),
                (!text.trim().is_empty()).then_some(format!("TRACE%\n{text}")),
            )
        }
        codex_app_server_protocol::ThreadItem::CollabAgentToolCall {
            tool,
            status,
            sender_thread_id,
            receiver_thread_ids,
            prompt,
            agents_states,
            ..
        } => (
            "collab_agent_tool_call".to_string(),
            Some("system".to_string()),
            Some(format_collab_agent_tool_call(
                tool,
                status,
                sender_thread_id,
                receiver_thread_ids,
                prompt.as_deref(),
                agents_states,
            )),
        ),
        _ => ("other".to_string(), None, None),
    }
}

fn format_collab_agent_tool_call(
    tool: &codex_app_server_protocol::CollabAgentTool,
    status: &codex_app_server_protocol::CollabAgentToolCallStatus,
    sender_thread_id: &str,
    receiver_thread_ids: &[String],
    prompt: Option<&str>,
    agents_states: &HashMap<String, codex_app_server_protocol::CollabAgentState>,
) -> String {
    let mut text = String::new();
    text.push_str("SUBAGENT%\n");
    text.push_str(&format!("tool={tool:?} status={status:?}\n"));
    text.push_str(&format!("sender={sender_thread_id}\n"));
    if !receiver_thread_ids.is_empty() {
        text.push_str(&format!("receivers={}\n", receiver_thread_ids.join(",")));
    }
    if !agents_states.is_empty() {
        let states = agents_states
            .iter()
            .map(|(agent_id, state)| format!("{agent_id}:{:?}", state.status))
            .collect::<Vec<_>>()
            .join(",");
        text.push_str(&format!("agents={states}\n"));
    }
    if let Some(prompt) = prompt.map(str::trim).filter(|prompt| !prompt.is_empty()) {
        text.push_str("--- prompt ---\n");
        text.push_str(&truncate_for_transcript(prompt, 1200));
    }
    text.trim_end().to_string()
}

fn format_command_execution(
    command: &str,
    status: &codex_app_server_protocol::CommandExecutionStatus,
    output: Option<&str>,
    exit_code: Option<i32>,
    duration_ms: Option<i64>,
) -> String {
    let mut text = String::new();
    text.push_str("CMD%\n$ ");
    text.push_str(command);
    text.push('\n');
    text.push_str(&format!(
        "status={status:?} exit={} duration={}ms",
        exit_code
            .map(|code| code.to_string())
            .unwrap_or_else(|| "?".to_string()),
        duration_ms
            .map(|duration| duration.to_string())
            .unwrap_or_else(|| "?".to_string())
    ));

    if let Some(output) = output {
        let output = strip_ansi_escape(output).trim().to_string();
        if !output.is_empty() {
            text.push_str("\n--- output ---\n");
            text.push_str(&truncate_for_transcript(&output, 2400));
        }
    }

    text
}

fn truncate_for_transcript(text: &str, max_chars: usize) -> String {
    let mut truncated: String = text.chars().take(max_chars).collect();
    if text.chars().count() > max_chars {
        truncated.push_str("\n...[truncated]");
    }
    truncated
}

fn strip_ansi_escape(text: &str) -> String {
    let mut stripped = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for code in chars.by_ref() {
                if code.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            stripped.push(ch);
        }
    }
    stripped
}

fn emit_fe(app: &AppHandle, event: FrontendEvent) {
    if let Err(e) = app.emit("codex-event", &event) {
        warn!("Failed to emit frontend event: {e}");
    }
}
