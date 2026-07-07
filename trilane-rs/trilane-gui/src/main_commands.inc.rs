#[tauri::command]
async fn start_agent(
    state: State<'_, AppState>,
    app: AppHandle,
    model: Option<String>,
    cwd: Option<String>,
    audit_mode: Option<String>,
) -> Result<String, String> {
    info!("Starting TriLane agent...");
    let audit_mode = AuditMode::from_wire(audit_mode.as_deref());

    // Set CODEX_HOME to ~/.trilane so TriLane reads its own config, not the user's default profile.
    let trilane_home = trilane_home();
    std::env::set_var("CODEX_HOME", trilane_home.to_string_lossy().to_string());
    info!("CODEX_HOME set to {}", trilane_home.display());
    apply_saved_provider_api_keys()?;

    // Load config WITH reading config files (not load_default which skips them)
    // This reads ~/.trilane/config.toml including custom providers
    let cli_overrides = trilane_agent_cli_overrides(&audit_mode);
    let mut config = ConfigBuilder::default()
        .codex_home(trilane_home)
        .cli_overrides(cli_overrides.clone())
        .build()
        .await
        .map_err(|e| format!("Config load failed: {e}"))?;
    let mut thread_config_overrides: Option<HashMap<String, serde_json::Value>> = None;
    if let Some(proxy_config) = mimo_adapter_config()? {
        warn!(
            "Using local MiMo protocol adapter for provider {}",
            proxy_config.provider_id
        );
        let provider_id = proxy_config.provider_id;
        let upstream_base_url = proxy_config.base_url;
        let env_key = config
            .model_provider
            .env_key
            .clone()
            .unwrap_or(proxy_config.env_key);
        let api_key = std::env::var(&env_key)
            .map_err(|_| format!("Missing API key env var for proxy: {env_key}"))?;
        let proxy_base_url =
            mimo_adapter::start(upstream_base_url, api_key, proxy_config.multimodal_model).await?;
        config.model_provider.base_url = Some(proxy_base_url.clone());
        if let Some(provider) = config.model_providers.get_mut(&config.model_provider_id) {
            provider.base_url = Some(proxy_base_url.clone());
            provider.supports_websockets = false;
        }
        config.model_provider.supports_websockets = false;

        let mut overrides = HashMap::new();
        overrides.insert(
            format!("model_providers.{provider_id}.base_url"),
            json!(proxy_base_url),
        );
        overrides.insert(
            format!("model_providers.{provider_id}.supports_websockets"),
            json!(false),
        );
        thread_config_overrides = Some(overrides);
    }
    let config = Arc::new(config);

    let state_db = codex_core::init_state_db(&config).await;

    let sop_prompt = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("sop/system_prompt_v4.md"),
    )
    .unwrap_or_else(|_| "You are TriLane, a lane-orchestrated security audit agent.".to_string());

    let arg0_paths = state.arg0_paths.clone();
    let local_runtime_paths = ExecServerRuntimePaths::from_optional_paths(
        arg0_paths.codex_self_exe.clone(),
        arg0_paths.codex_linux_sandbox_exe.clone(),
    )
    .map_err(|e| format!("Exec runtime path setup failed: {e}"))?;
    let environment_manager =
        EnvironmentManager::from_codex_home(config.codex_home.clone(), Some(local_runtime_paths))
            .await
            .map(Arc::new)
            .map_err(|e| format!("Environment manager setup failed: {e}"))?;

    let args = InProcessClientStartArgs {
        arg0_paths,
        config,
        cli_overrides,
        loader_overrides: LoaderOverrides::default(),
        strict_config: false,
        cloud_requirements: CloudRequirementsLoader::default(),
        feedback: CodexFeedback::new(),
        log_db: None,
        state_db,
        environment_manager,
        config_warnings: Vec::new(),
        session_source: SessionSource::Exec,
        enable_codex_api_key_env: true,
        client_name: "trilane".to_string(),
        client_version: "0.1.0".to_string(),
        experimental_api: true,
        opt_out_notification_methods: Vec::new(),
        channel_capacity: 8192,
    };

    let client = InProcessAppServerClient::start(args)
        .await
        .map_err(|e| format!("App-server start failed: {e}"))?;

    let cwd_str = cwd.unwrap_or_else(|| {
        std::env::current_dir()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| "/tmp".to_string())
    });

    let response: ThreadStartResponse = client
        .request_typed(ClientRequest::ThreadStart {
            request_id: RequestId::Integer(1),
            params: ThreadStartParams {
                cwd: Some(cwd_str.clone()),
                model: model.clone(),
                ephemeral: Some(true),
                config: thread_config_overrides.clone(),
                base_instructions: Some(sop_prompt.clone()),
                ..Default::default()
            },
        })
        .await
        .map_err(|e| format!("Thread start failed: {e}"))?;

    let thread_id = response.thread.id.clone();
    info!("Thread started: {} (model: {})", thread_id, response.model);

    *state.thread_id.lock().await = Some(thread_id.clone());

    let (cmd_tx, cmd_rx) = mpsc::channel::<AgentCommand>(64);
    *state.msg_tx.lock().await = Some(cmd_tx);

    let app_handle = app.clone();
    let tid = thread_id.clone();
    let runtime_config = AgentRuntimeConfig {
        model,
        cwd: cwd_str,
        base_instructions: sop_prompt,
        thread_config_overrides,
        audit_mode,
    };
    tokio::spawn(agent_event_loop(
        client,
        cmd_rx,
        app_handle,
        tid,
        runtime_config,
    ));

    Ok(thread_id)
}

#[tauri::command]
async fn send_message(
    app: AppHandle,
    state: State<'_, AppState>,
    text: String,
    audit_mode: Option<String>,
) -> Result<(), String> {
    let tx = state
        .msg_tx
        .lock()
        .await
        .as_ref()
        .cloned()
        .ok_or("Agent not started")?;

    let audit_mode = AuditMode::from_wire(audit_mode.as_deref());
    warn!("GUI send_message audit_mode={}", audit_mode.as_marker());

    let turn_in_progress = *state.turn_in_progress.lock().await;
    if turn_in_progress {
        append_chat_message(&app, "user", text.clone()).await;
        let status_message = {
            let runbook = current_runbook_snapshot(&state).await;
            if looks_like_status_query(&text) {
                running_turn_status_message(&runbook)
            } else {
                format!(
                    "SYS% backend turn still active; new objective not started\n{}",
                    running_turn_status_message(&runbook)
                )
            }
        };
        append_and_emit_system_message(&app, status_message).await;
        return Ok(());
    }

    if let Some(directive) = parse_resume_run_directive(&text) {
        let directive = directive?;
        let (mut snapshot, resume_file_context) = {
            let archive = state.transcript_log.lock().await;
            (
                archive.load_resume_state(&directive.run_id, &directive.stage_id)?,
                archive.resume_file_context(&directive.run_id, &directive.stage_id)?,
            )
        };
        let objective = resume_objective(
            &snapshot.objective,
            &directive.extra_instructions,
            &resume_file_context,
        );
        let resume_audit_mode = snapshot.audit_mode.clone();
        snapshot.status = runbook::RunbookStatus::Running;
        snapshot.current_stage = directive.stage_id.clone();
        snapshot.objective = objective.clone();
        snapshot.turn_id = None;
        {
            let mut runbook = state.runbook.lock().await;
            *runbook = snapshot.clone();
        }
        if let Err(error) = state.state_store.replace_runbook(&snapshot).await {
            warn!("Failed to replace TriLane resume snapshot: {error:#}");
        }
        emit_fe(
            &app,
            FrontendEvent::RunbookUpdated {
                state: Box::new(snapshot.clone()),
            },
        );
        state
            .transcript_log
            .lock()
            .await
            .start_resume_turn(&directive.run_id, &objective, resume_audit_mode.clone())?;
        append_chat_message(&app, "user", text.clone()).await;
        append_and_emit_system_message(
            &app,
            format!(
                "SYS% resumed run from files\nRUN% id={} stage={} source=previous-stage-runbook",
                directive.run_id, directive.stage_id
            ),
        )
        .await;
        *state.turn_in_progress.lock().await = true;
        if let Err(err) = tx
            .send(AgentCommand::SendMessage {
                text: objective,
                audit_mode: resume_audit_mode,
                resume_stage: Some(directive.stage_id),
            })
            .await
        {
            *state.turn_in_progress.lock().await = false;
            return Err(format!("Agent channel closed: {err}"));
        }
        return Ok(());
    }

    let snapshot = {
        let mut runbook = state.runbook.lock().await;
        runbook.start_turn(&text, audit_mode.clone());
        runbook.clone()
    };
    save_and_emit_runbook(&app, snapshot).await;
    state
        .transcript_log
        .lock()
        .await
        .start_turn(&text, audit_mode.clone());
    append_chat_message(&app, "user", text.clone()).await;
    *state.turn_in_progress.lock().await = true;

    if let Err(err) = tx
        .send(AgentCommand::SendMessage {
            text,
            audit_mode,
            resume_stage: None,
        })
        .await
    {
        *state.turn_in_progress.lock().await = false;
        return Err(format!("Agent channel closed: {err}"));
    }

    Ok(())
}

struct ResumeRunDirective {
    run_id: String,
    stage_id: String,
    extra_instructions: String,
}

fn parse_resume_run_directive(text: &str) -> Option<Result<ResumeRunDirective, String>> {
    let (line_index, line) = text
        .lines()
        .enumerate()
        .find(|(_, line)| !line.trim().is_empty())?;
    let line = line.trim();
    if !line.starts_with("TRILANE_RESUME_RUN%") {
        return None;
    }
    let run_id = directive_value(line, "run")
        .or_else(|| directive_value(line, "run_id"))
        .ok_or_else(|| "TRILANE_RESUME_RUN% missing run=<id>".to_string());
    let stage_id = directive_value(line, "stage")
        .ok_or_else(|| "TRILANE_RESUME_RUN% missing stage=<stageN>".to_string())
        .and_then(|value| normalize_stage_arg(&value));
    let extra_instructions = text
        .lines()
        .skip(line_index + 1)
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string();
    Some(run_id.and_then(|run_id| {
        stage_id.map(|stage_id| ResumeRunDirective {
            run_id,
            stage_id,
            extra_instructions,
        })
    }))
}

fn normalize_stage_arg(value: &str) -> Result<String, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "s0" | "stage0" => Ok("stage0".to_string()),
        "s1" | "stage1" => Ok("stage1".to_string()),
        "s2" | "stage2" => Ok("stage2".to_string()),
        "s3" | "stage3" => Ok("stage3".to_string()),
        "s4" | "stage4" => Ok("stage4".to_string()),
        "s5" | "stage5" => Ok("stage5".to_string()),
        _ => Err(format!("unknown stage: {value}")),
    }
}

fn resume_objective(original: &str, extra: &str, file_context: &str) -> String {
    let mut objective = format!(
        "ORIGINAL_OBJECTIVE%\n{}\n\n{}\n\nRESUME_RULES%\nResume from the selected stage using the fixed TriLane stage prompt and the previous-stage runbook state. Preserve prior-stage evidence; regenerate the selected stage and later stages only.",
        original.trim(),
        file_context.trim()
    );
    if !extra.trim().is_empty() {
        objective.push_str("\n\nUSER_RESUME_INSTRUCTIONS%\n");
        objective.push_str(extra.trim());
    }
    objective
}

fn directive_value(line: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    line.split_whitespace().find_map(|part| {
        part.strip_prefix(&prefix)
            .map(|value| value.trim_matches('"').trim_matches('\'').to_string())
            .filter(|value| !value.is_empty())
    })
}

#[tauri::command]
async fn list_trilane_runs(state: State<'_, AppState>) -> Result<Vec<String>, String> {
    Ok(state.transcript_log.lock().await.list_runs())
}

#[tauri::command]
async fn is_agent_started(state: State<'_, AppState>) -> Result<bool, String> {
    let has_sender = state.msg_tx.lock().await.is_some();
    let has_thread = state.thread_id.lock().await.is_some();
    Ok(has_sender && has_thread)
}

#[tauri::command]
async fn approve_command(
    state: State<'_, AppState>,
    request_id: String,
    decision: String,
) -> Result<(), String> {
    let tx = state
        .msg_tx
        .lock()
        .await
        .as_ref()
        .cloned()
        .ok_or("Agent not started")?;
    tx.send(AgentCommand::Approve {
        request_id,
        decision,
    })
    .await
    .map_err(|_| "Agent channel closed".to_string())
}

#[tauri::command]
async fn stop_agent(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    let tx = state.msg_tx.lock().await.take();
    if let Some(tx) = tx {
        let _ = tx.send(AgentCommand::Shutdown).await;
    }
    let snapshot = {
        let mut runbook = state.runbook.lock().await;
        if runbook.status == runbook::RunbookStatus::Running {
            runbook.stop_turn("stopped by user reboot");
        }
        runbook.clone()
    };
    if snapshot.status == runbook::RunbookStatus::Error {
        state
            .state_store
            .save_runbook(&snapshot)
            .await
            .map_err(|error| format!("Failed to save stopped runbook: {error:#}"))?;
        state
            .transcript_log
            .lock()
            .await
            .finish_turn("stopped", &snapshot);
        emit_fe(
            &app,
            FrontendEvent::RunbookUpdated {
                state: Box::new(snapshot),
            },
        );
    }
    *state.thread_id.lock().await = None;
    *state.turn_in_progress.lock().await = false;
    Ok(())
}

#[tauri::command]
async fn get_chat_history(state: State<'_, AppState>) -> Result<Vec<ChatMessage>, String> {
    Ok(state.messages.lock().await.clone())
}

#[tauri::command]
async fn is_turn_in_progress(state: State<'_, AppState>) -> Result<bool, String> {
    Ok(*state.turn_in_progress.lock().await)
}

#[tauri::command]
async fn get_findings(state: State<'_, AppState>) -> Result<Vec<Finding>, String> {
    let runbook = current_runbook_snapshot(&state).await;
    let adjudicated;
    let stored_final_findings = match state.state_store.load_final_findings().await {
        Ok(Some(findings)) if !findings.is_empty() => Some(findings),
        Ok(Some(_)) | Ok(None) => None,
        Err(error) => {
            warn!("Failed to load persisted final findings: {error:#}");
            None
        }
    };
    let final_findings = if let Some(stored) = stored_final_findings.as_ref() {
        stored
    } else if runbook.final_findings.is_empty() {
        adjudicated = runbook_finalize::adjudicate_findings(&runbook.findings, &runbook.claims).0;
        &adjudicated
    } else {
        &runbook.final_findings
    };
    let final_findings = final_findings
        .iter()
        .map(|finding| Finding {
            id: finding.id.clone(),
            title: finding.title.clone(),
            severity: finding.severity.clone(),
            status: finding.verification_status.clone(),
            location: finding.location.clone(),
            code_path: finding.code_path.clone(),
            description: finding.detail.clone(),
            payload: finding.payload.clone(),
            cwe: infer_cwe_label(&finding.title, &finding.detail),
            confidence: finding.confidence.clone(),
            evidence_state: finding.evidence_state.clone(),
            duplicate_count: finding.duplicates.len(),
            original_id: finding.original_id.clone(),
            candidate_id: finding.candidate_id.clone(),
        })
        .collect();
    Ok(final_findings)
}

#[tauri::command]
async fn get_scan_progress(state: State<'_, AppState>) -> Result<Option<ScanProgress>, String> {
    let runbook = current_runbook_snapshot(&state).await;
    Ok(runbook::scan_progress_from_runbook(&runbook))
}

#[tauri::command]
async fn get_runbook_state(state: State<'_, AppState>) -> Result<RunbookState, String> {
    Ok(current_runbook_snapshot(&state).await)
}

#[tauri::command]
async fn export_final_report(state: State<'_, AppState>) -> Result<String, String> {
    let runbook = current_runbook_snapshot(&state).await;
    let report = runbook.final_report_markdown();
    let downloads = dirs::download_dir()
        .or_else(|| dirs::home_dir().map(|home| home.join("Downloads")))
        .ok_or_else(|| "Could not locate Downloads directory".to_string())?;
    std::fs::create_dir_all(&downloads)
        .map_err(|error| format!("Failed to create Downloads directory: {error}"))?;
    let filename = format!(
        "trilane-poc-bundle-{}.md",
        chrono::Local::now().format("%Y%m%d-%H%M%S")
    );
    let path = downloads.join(filename);
    std::fs::write(&path, report).map_err(|error| format!("Failed to write report: {error}"))?;
    Ok(path.to_string_lossy().to_string())
}

#[tauri::command]
async fn clear_chat(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    state.messages.lock().await.clear();
    *state.turn_in_progress.lock().await = false;
    let snapshot = RunbookState::default();
    *state.runbook.lock().await = snapshot.clone();
    state
        .state_store
        .clear()
        .await
        .map_err(|error| format!("Failed to clear SQLite state: {error:#}"))?;
    emit_fe(
        &app,
        FrontendEvent::RunbookUpdated {
            state: Box::new(snapshot),
        },
    );
    Ok(())
}

#[tauri::command]
fn close_window(window: tauri::Window) -> Result<(), String> {
    window.close().map_err(|error| error.to_string())
}

#[tauri::command]
fn minimize_window(window: tauri::Window) -> Result<(), String> {
    window.minimize().map_err(|error| error.to_string())
}

#[tauri::command]
fn toggle_maximize_window(window: tauri::Window) -> Result<(), String> {
    let is_maximized = window.is_maximized().map_err(|error| error.to_string())?;
    if is_maximized {
        window.unmaximize().map_err(|error| error.to_string())
    } else {
        window.maximize().map_err(|error| error.to_string())
    }
}

#[tauri::command]
fn start_window_drag(window: tauri::Window) -> Result<(), String> {
    window.start_dragging().map_err(|error| error.to_string())
}

fn infer_cwe_label(title: &str, detail: &str) -> String {
    let haystack = format!("{title}\n{detail}").to_ascii_lowercase();
    if haystack.contains("sql") {
        "CWE-89".to_string()
    } else if haystack.contains("xss") {
        "CWE-79".to_string()
    } else if haystack.contains("ssrf") {
        "CWE-918".to_string()
    } else if haystack.contains("redirect") {
        "CWE-601".to_string()
    } else if haystack.contains("xxe") {
        "CWE-611".to_string()
    } else if haystack.contains("traversal") || haystack.contains("lfi") {
        "CWE-22".to_string()
    } else if haystack.contains("idor") || haystack.contains("authorization") {
        "CWE-639".to_string()
    } else if haystack.contains("secret") || haystack.contains("key") {
        "CWE-798".to_string()
    } else if haystack.contains("md5") || haystack.contains("crypto") {
        "CWE-327".to_string()
    } else if haystack.contains("cors") {
        "CWE-942".to_string()
    } else if haystack.contains("rate") || haystack.contains("brute") {
        "CWE-307".to_string()
    } else {
        "CWE-TBD".to_string()
    }
}
