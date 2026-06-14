// TriLane - Tauri GUI for lane-orchestrated vulnerability hunting.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod mimo_adapter;
mod runbook;
mod runbook_claims;
mod runbook_finalize;
mod state_store;
mod transcript_log;
mod workflow;

use serde::Deserialize;
use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use tauri::AppHandle;
use tauri::Emitter;
use tauri::Manager;
use tauri::State;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tracing::info;
use tracing::warn;

use codex_app_server_client::InProcessAppServerClient;
use codex_app_server_client::InProcessClientStartArgs;
use codex_app_server_client::InProcessServerEvent as ServerEvent;
use codex_app_server_protocol::ClientRequest;
use codex_app_server_protocol::RequestId;
use codex_app_server_protocol::ServerNotification;
use codex_app_server_protocol::ServerRequest;
use codex_app_server_protocol::ThreadStartParams;
use codex_app_server_protocol::ThreadStartResponse;
use codex_app_server_protocol::TurnStartParams;
use codex_app_server_protocol::TurnStartResponse;
use codex_app_server_protocol::UserInput;
use codex_arg0::Arg0DispatchPaths;
use codex_config::CloudRequirementsLoader;
use codex_config::LoaderOverrides;
use codex_core::config::ConfigBuilder;
use codex_exec_server::EnvironmentManager;
use codex_exec_server::ExecServerRuntimePaths;
use codex_feedback::CodexFeedback;
use codex_protocol::protocol::SessionSource;
use runbook::AuditMode;
use runbook::RunbookLaneUpdate;
use runbook::RunbookState;
use state_store::TriLaneStateStore;
use transcript_log::TranscriptArchive;
use workflow::TriLaneWorkflow;
use workflow::WorkflowAction;
use workflow::WorkflowLaneBatch;
use workflow::WorkflowLaneSpec;
use workflow::WorkflowPrompt;

const MIMO_PROVIDER_ID: &str = "xiaomi";
const MIMO_PROVIDER_NAME: &str = "Xiaomi MiMo";
const MIMO_TOKEN_PLAN_CN_BASE_URL: &str = "https://token-plan-cn.xiaomimimo.com/v1";
const MIMO_DEFAULT_MODEL: &str = "mimo-v2.5-pro";
const MIMO_DEFAULT_MULTIMODAL_MODEL: &str = "mimo-v2.5";
const MIMO_API_KEY_ENV: &str = "XIAOMI_API_KEY";
const DEFAULT_WORKFLOW_LANE_CONCURRENCY: usize = 2;
const RUNBOOK_MARKER_FLUSH_BATCH_LINES: usize = 12;
const RUNBOOK_MARKER_FLUSH_INTERVAL: Duration = Duration::from_millis(350);
const WORKFLOW_LANE_MAX_ATTEMPTS: u8 = 3;
const WORKFLOW_LANE_RETRY_TICK: Duration = Duration::from_secs(1);

include!("main_types.inc.rs");
include!("main_status.inc.rs");
include!("main_state_sync.inc.rs");
include!("main_commands.inc.rs");
include!("main_config.inc.rs");
include!("main_agent_loop.inc.rs");
include!("main_workflow_runtime.inc.rs");
include!("main_frontend.inc.rs");

fn main() {
    // Set minimum stack size for all threads to avoid stack overflow in deep codex call chains
    // Default is 2MB which is too small; 16MB prevents overflow
    std::env::set_var("RUST_MIN_STACK", "16777216");
    let arg0_path_entry_guard = codex_arg0::arg0_dispatch();
    let arg0_paths = Arg0DispatchPaths {
        codex_self_exe: std::env::current_exe().ok(),
        codex_linux_sandbox_exe: None,
        main_execve_wrapper_exe: arg0_path_entry_guard
            .as_ref()
            .and_then(|path_entry| path_entry.paths().main_execve_wrapper_exe.clone()),
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    info!("TriLane starting...");
    let state_store = tauri::async_runtime::block_on(TriLaneStateStore::open_default())
        .expect("failed to open TriLane SQLite state store");
    let initial_runbook = tauri::async_runtime::block_on(state_store.load_runbook())
        .ok()
        .flatten()
        .unwrap_or_default();

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(AppState {
            arg0_paths,
            msg_tx: Mutex::new(None),
            thread_id: Mutex::new(None),
            turn_in_progress: Mutex::new(false),
            messages: Mutex::new(Vec::new()),
            runbook: Mutex::new(initial_runbook),
            agent_delta_marker_buffers: Mutex::new(HashMap::new()),
            pending_runbook_markers: Mutex::new(PendingRunbookMarkers::default()),
            state_store,
            transcript_log: Mutex::new(TranscriptArchive::new()),
        })
        .invoke_handler(tauri::generate_handler![
            start_agent,
            send_message,
            is_agent_started,
            is_turn_in_progress,
            approve_command,
            stop_agent,
            get_chat_history,
            get_findings,
            get_scan_progress,
            get_runbook_state,
            export_final_report,
            clear_chat,
            close_window,
            minimize_window,
            toggle_maximize_window,
            start_window_drag,
            read_model_config,
            save_model_config,
            get_env_api_key,
            save_provider_api_key,
            reveal_provider_api_key,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
    drop(arg0_path_entry_guard);
}

#[cfg(test)]
mod tests {
    use super::*;

    include!("main_tests.inc.rs");
}
