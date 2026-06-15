#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelConfig {
    pub model_provider: String,
    pub model: String,
    pub multimodal_model: String,
    pub openai_base_url: String,
    pub api_key_env: String,
    pub model_context_window: i64,
    pub model_reasoning_effort: String,
    pub oss_provider: String,
    pub custom_providers: Vec<CustomProvider>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomProvider {
    pub id: String,
    pub name: String,
    pub base_url: String,
    pub env_key: String,
    pub api_key_masked: String, // e.g. "sk-...abc" — only last 4 chars shown
}

fn trilane_home() -> std::path::PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
        .join(".trilane")
}

fn trilane_agent_cli_overrides(audit_mode: &AuditMode) -> Vec<(String, toml::Value)> {
    let sandbox_mode = if audit_mode.grants_full_access() {
        "danger-full-access"
    } else {
        "workspace-write"
    };
    let mut overrides = vec![
        (
            "sandbox_mode".to_string(),
            toml::Value::String(sandbox_mode.to_string()),
        ),
        (
            "approval_policy".to_string(),
            toml::Value::String("on-request".to_string()),
        ),
        (
            "features.multi_agent_v2.enabled".to_string(),
            toml::Value::Boolean(true),
        ),
        (
            "features.multi_agent_v2.max_concurrent_threads_per_session".to_string(),
            toml::Value::Integer(6),
        ),
        (
            "features.multi_agent_v2.default_wait_timeout_ms".to_string(),
            toml::Value::Integer(120_000),
        ),
        (
            "features.multi_agent_v2.max_wait_timeout_ms".to_string(),
            toml::Value::Integer(600_000),
        ),
        (
            "features.multi_agent_v2.hide_spawn_agent_metadata".to_string(),
            toml::Value::Boolean(true),
        ),
        (
            "features.multi_agent_v2.root_agent_usage_hint_text".to_string(),
            toml::Value::String(
                "For TriLane audits, the backend workflow owns S2 child-engine scheduling with bounded concurrency and provider backoff. The root agent should emit S1 surface ledgers and then consume the RUNBOOK_CONTEXT merge packet; it should not open its own S2 subagents."
                    .to_string(),
            ),
        ),
        (
            "features.multi_agent_v2.subagent_usage_hint_text".to_string(),
            toml::Value::String(
                "You are a focused TriLane audit subagent. Stay within your assigned domain, emit SURFACE%/CANDIDATE%/CLAIM%/FINDING% markers with concrete evidence, and return a compact ledger to the parent."
                    .to_string(),
            ),
        ),
    ];
    if audit_mode.grants_full_access() {
        overrides.push((
            "sandbox_workspace_write.network_access".to_string(),
            toml::Value::Boolean(true),
        ));
    }
    overrides
}

fn config_path() -> std::path::PathBuf {
    trilane_home().join("config.toml")
}

fn secrets_path() -> std::path::PathBuf {
    trilane_home().join("secrets.toml")
}

fn derived_api_key_env(provider_id: &str) -> String {
    format!(
        "{}_API_KEY",
        provider_id
            .to_uppercase()
            .replace(|c: char| !c.is_alphanumeric(), "")
    )
}

fn provider_env_key(provider_id: &str, provider: Option<&toml::Table>) -> String {
    if provider_id == MIMO_PROVIDER_ID {
        return provider
            .and_then(|table| table.get("env_key"))
            .and_then(|value| value.as_str())
            .filter(|env_key| !env_key.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| MIMO_API_KEY_ENV.to_string());
    }
    provider
        .and_then(|table| table.get("env_key"))
        .and_then(|value| value.as_str())
        .filter(|env_key| !env_key.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| derived_api_key_env(provider_id))
}

fn configured_provider_env_key(provider_id: &str) -> String {
    let content = std::fs::read_to_string(config_path()).unwrap_or_default();
    let Ok(table) = content.parse::<toml::Table>() else {
        return derived_api_key_env(provider_id);
    };

    let provider = table
        .get("model_providers")
        .and_then(|value| value.as_table())
        .and_then(|providers| providers.get(provider_id))
        .and_then(|value| value.as_table());

    provider_env_key(provider_id, provider)
}

struct MimoAdapterConfig {
    provider_id: String,
    base_url: String,
    env_key: String,
    multimodal_model: Option<String>,
}

fn mimo_adapter_config() -> Result<Option<MimoAdapterConfig>, String> {
    let content = std::fs::read_to_string(config_path()).unwrap_or_default();
    let table: toml::Table = content.parse().map_err(|e| format!("Parse error: {e}"))?;
    let provider_id = table
        .get("model_provider")
        .and_then(|value| value.as_str())
        .unwrap_or("openai");
    if provider_id != MIMO_PROVIDER_ID {
        return Ok(None);
    }
    let provider = table
        .get("model_providers")
        .and_then(|value| value.as_table())
        .and_then(|providers| providers.get(provider_id))
        .and_then(|value| value.as_table());
    let Some(provider) = provider else {
        return Ok(Some(MimoAdapterConfig {
            provider_id: MIMO_PROVIDER_ID.to_string(),
            base_url: MIMO_TOKEN_PLAN_CN_BASE_URL.to_string(),
            env_key: MIMO_API_KEY_ENV.to_string(),
            multimodal_model: Some(MIMO_DEFAULT_MULTIMODAL_MODEL.to_string()),
        }));
    };
    let base_url = provider
        .get("base_url")
        .and_then(|value| value.as_str())
        .unwrap_or(MIMO_TOKEN_PLAN_CN_BASE_URL);
    if !base_url.contains("xiaomimimo.com") {
        return Err(format!(
            "Xiaomi MiMo provider must use a xiaomimimo.com OpenAI-compatible base URL, got {base_url}"
        ));
    }
    let multimodal_model = table
        .get("multimodal_model")
        .and_then(|value| value.as_str())
        .or_else(|| {
            provider
                .get("multimodal_model")
                .and_then(|value| value.as_str())
        })
        .filter(|model| !model.trim().is_empty())
        .unwrap_or(MIMO_DEFAULT_MULTIMODAL_MODEL)
        .to_string();

    Ok(Some(MimoAdapterConfig {
        provider_id: provider_id.to_string(),
        base_url: base_url.to_string(),
        env_key: provider_env_key(provider_id, Some(provider)),
        multimodal_model: Some(multimodal_model),
    }))
}

/// Read secrets from ~/.trilane/secrets.toml — returns provider_id -> api_key map
fn read_secrets() -> std::collections::HashMap<String, String> {
    let path = secrets_path();
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return std::collections::HashMap::new(),
    };
    let table: toml::Table = match content.parse() {
        Ok(v) => v,
        Err(_) => return std::collections::HashMap::new(),
    };
    let mut map = std::collections::HashMap::new();
    for (key, val) in &table {
        if let Some(s) = val.as_str() {
            map.insert(key.clone(), s.to_string());
        }
    }
    map
}

fn apply_saved_provider_api_keys() -> Result<(), String> {
    let secrets = read_secrets();
    if secrets.is_empty() {
        return Ok(());
    }

    let content = std::fs::read_to_string(config_path()).unwrap_or_default();
    let table: toml::Table = content.parse().map_err(|e| format!("Parse error: {e}"))?;
    let providers = table
        .get("model_providers")
        .and_then(|value| value.as_table());

    for (provider_id, api_key) in secrets {
        if api_key.is_empty() {
            continue;
        }

        let provider = providers
            .and_then(|providers| providers.get(&provider_id))
            .and_then(|value| value.as_table());
        let env_key = provider_env_key(&provider_id, provider);
        std::env::set_var(&env_key, api_key);
        info!("Loaded saved API key for provider {provider_id} into {env_key}");
    }

    Ok(())
}

/// Write secrets to ~/.trilane/secrets.toml
fn write_secrets(secrets: &std::collections::HashMap<String, String>) -> Result<(), String> {
    let path = secrets_path();
    std::fs::create_dir_all(path.parent().unwrap()).map_err(|e| format!("mkdir failed: {e}"))?;
    let mut doc = String::new();
    for (key, val) in secrets {
        doc.push_str(&format!("{key} = \"{val}\"\n"));
    }
    std::fs::write(&path, doc).map_err(|e| format!("Write failed: {e}"))?;
    Ok(())
}

/// Mask an API key: show first 3 chars + "..." + last 4 chars, or "not set" if empty
fn mask_api_key(key: &str) -> String {
    if key.is_empty() {
        return "not set".to_string();
    }
    if key.len() <= 7 {
        return "***".to_string();
    }
    format!("{}...{}", &key[..3], &key[key.len() - 4..])
}

#[tauri::command]
async fn read_model_config() -> Result<ModelConfig, String> {
    let path = config_path();
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    let table: toml::Table = content.parse().map_err(|e| format!("Parse error: {e}"))?;

    let model_provider = table
        .get("model_provider")
        .and_then(|v| v.as_str())
        .unwrap_or("openai")
        .to_string();

    let model = table
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let multimodal_model = table
        .get("multimodal_model")
        .and_then(|v| v.as_str())
        .unwrap_or(MIMO_DEFAULT_MULTIMODAL_MODEL)
        .to_string();

    let mut openai_base_url = table
        .get("openai_base_url")
        .and_then(|v| v.as_str())
        .unwrap_or("https://api.openai.com/v1")
        .to_string();

    let _api_key_env = "OPENAI_API_KEY"; // unused placeholder, actual value computed below

    let model_context_window = table
        .get("model_context_window")
        .and_then(|v| v.as_integer())
        .unwrap_or(1000000);

    let model_reasoning_effort = table
        .get("model_reasoning_effort")
        .and_then(|v| v.as_str())
        .unwrap_or("medium")
        .to_string();

    let oss_provider = table
        .get("oss_provider")
        .and_then(|v| v.as_str())
        .unwrap_or("ollama")
        .to_string();

    let mut custom_providers = Vec::new();
    if let Some(providers) = table.get("model_providers").and_then(|v| v.as_table()) {
        for (id, val) in providers {
            if id == MIMO_PROVIDER_ID {
                if let Some(pt) = val.as_table() {
                    if model_provider == MIMO_PROVIDER_ID {
                        openai_base_url = pt
                            .get("base_url")
                            .and_then(|v| v.as_str())
                            .unwrap_or(MIMO_TOKEN_PLAN_CN_BASE_URL)
                            .to_string();
                    }
                }
                continue;
            }
            if let Some(pt) = val.as_table() {
                let base_url = pt
                    .get("base_url")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                // Read API key from secrets file
                let secrets = read_secrets();
                let api_key = secrets.get(id).cloned().unwrap_or_default();
                let api_key_masked = mask_api_key(&api_key);
                custom_providers.push(CustomProvider {
                    id: id.clone(),
                    name: pt
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or(id)
                        .to_string(),
                    base_url: base_url.clone(),
                    env_key: pt
                        .get("env_key")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    api_key_masked,
                });
                // If the active provider is a custom one, use its base_url as openai_base_url
                if model_provider == *id && !base_url.is_empty() {
                    openai_base_url = base_url;
                }
            }
        }
    }

    // Also match built-in local providers to their default URLs
    if model_provider == "ollama" && !table.contains_key("openai_base_url") {
        openai_base_url = "http://localhost:11434/v1".to_string();
    }
    if model_provider == "lmstudio" && !table.contains_key("openai_base_url") {
        openai_base_url = "http://localhost:1234/v1".to_string();
    }
    if model_provider == MIMO_PROVIDER_ID {
        openai_base_url = table
            .get("model_providers")
            .and_then(|v| v.as_table())
            .and_then(|providers| providers.get(MIMO_PROVIDER_ID))
            .and_then(|v| v.as_table())
            .and_then(|provider| provider.get("base_url"))
            .and_then(|v| v.as_str())
            .unwrap_or(MIMO_TOKEN_PLAN_CN_BASE_URL)
            .to_string();
    }

    // Compute api_key_env based on provider
    let api_key_env = if model_provider == MIMO_PROVIDER_ID {
        MIMO_API_KEY_ENV.to_string()
    } else if model_provider == "openai" || model_provider == "amazon-bedrock" {
        "OPENAI_API_KEY".to_string()
    } else if let Some(cp) = custom_providers.iter().find(|p| p.id == model_provider) {
        if cp.env_key.is_empty() {
            derived_api_key_env(&model_provider)
        } else {
            cp.env_key.clone()
        }
    } else {
        "OPENAI_API_KEY".to_string()
    };

    Ok(ModelConfig {
        model_provider,
        model,
        multimodal_model,
        openai_base_url,
        api_key_env,
        model_context_window,
        model_reasoning_effort,
        oss_provider,
        custom_providers,
    })
}

#[tauri::command]
async fn save_model_config(config: ModelConfig) -> Result<(), String> {
    let path = config_path();
    std::fs::create_dir_all(path.parent().unwrap()).map_err(|e| format!("mkdir failed: {e}"))?;

    let mut doc = String::new();
    doc.push_str(&format!("model_provider = \"{}\"\n", config.model_provider));
    doc.push_str("sandbox_mode = \"workspace-write\"\n");
    doc.push_str("approval_policy = \"on-request\"\n");
    if config.model_provider == MIMO_PROVIDER_ID && config.model.is_empty() {
        doc.push_str(&format!("model = \"{MIMO_DEFAULT_MODEL}\"\n"));
    } else if !config.model.is_empty() {
        doc.push_str(&format!("model = \"{}\"\n", config.model));
    }
    if config.multimodal_model.is_empty() && config.model_provider == MIMO_PROVIDER_ID {
        doc.push_str(&format!(
            "multimodal_model = \"{MIMO_DEFAULT_MULTIMODAL_MODEL}\"\n"
        ));
    } else if !config.multimodal_model.is_empty() {
        doc.push_str(&format!(
            "multimodal_model = \"{}\"\n",
            config.multimodal_model
        ));
    }
    // Only write openai_base_url for openai/amazon-bedrock (built-in providers that use it)
    // Custom providers have their base_url in [model_providers.xxx]
    if (config.model_provider == "openai" || config.model_provider == "amazon-bedrock")
        && !config.openai_base_url.is_empty()
    {
        doc.push_str(&format!(
            "openai_base_url = \"{}\"\n",
            config.openai_base_url
        ));
    }
    doc.push_str(&format!(
        "model_context_window = {}\n",
        config.model_context_window
    ));
    doc.push_str(&format!(
        "model_reasoning_effort = \"{}\"\n",
        config.model_reasoning_effort
    ));
    if !config.oss_provider.is_empty() {
        doc.push_str(&format!("oss_provider = \"{}\"\n", config.oss_provider));
    }
    doc.push('\n');

    if config.model_provider == MIMO_PROVIDER_ID
        || config
            .custom_providers
            .iter()
            .all(|provider| provider.id != MIMO_PROVIDER_ID)
    {
        let base_url =
            if config.model_provider == MIMO_PROVIDER_ID && !config.openai_base_url.is_empty() {
                config.openai_base_url.as_str()
            } else {
                MIMO_TOKEN_PLAN_CN_BASE_URL
            };
        doc.push_str(&format!("[model_providers.{MIMO_PROVIDER_ID}]\n"));
        doc.push_str(&format!("name = \"{MIMO_PROVIDER_NAME}\"\n"));
        doc.push_str(&format!("base_url = \"{base_url}\"\n"));
        doc.push_str(&format!("env_key = \"{MIMO_API_KEY_ENV}\"\n"));
        doc.push_str("wire_api = \"responses\"\n");
        doc.push_str("requires_openai_auth = false\n");
        doc.push_str("supports_websockets = false\n");
        doc.push_str("adapter = \"mimo-chat-completions\"\n");
        doc.push_str(&format!(
            "multimodal_model = \"{}\"\n",
            if config.multimodal_model.is_empty() {
                MIMO_DEFAULT_MULTIMODAL_MODEL
            } else {
                config.multimodal_model.as_str()
            }
        ));
        doc.push('\n');
    }

    for provider in &config.custom_providers {
        if provider.id == MIMO_PROVIDER_ID {
            continue;
        }
        doc.push_str(&format!("[model_providers.{}]\n", provider.id));
        doc.push_str(&format!("name = \"{}\"\n", provider.name));
        doc.push_str(&format!("base_url = \"{}\"\n", provider.base_url));
        if !provider.env_key.is_empty() {
            doc.push_str(&format!("env_key = \"{}\"\n", provider.env_key));
        }
        doc.push_str("wire_api = \"responses\"\n");
        doc.push_str("requires_openai_auth = false\n");
        doc.push('\n');
    }

    std::fs::write(&path, &doc).map_err(|e| format!("Write failed: {e}"))?;
    info!("Config saved to {}", path.display());
    info!("Config content:\n{}", doc);
    // Verify the written file can be parsed back
    let verify_content =
        std::fs::read_to_string(&path).map_err(|e| format!("Verify read failed: {e}"))?;
    let _verify: toml::Table = verify_content
        .parse()
        .map_err(|e| format!("Verify parse failed: {e}\nFile content:\n{verify_content}"))?;
    Ok(())
}

/// Save a custom provider's API key to the secrets file (separate from config.toml)
/// This keeps API keys out of the main config file
#[tauri::command]
async fn save_provider_api_key(provider_id: String, api_key: String) -> Result<(), String> {
    let mut secrets = read_secrets();
    let env_key = configured_provider_env_key(&provider_id);
    if api_key.is_empty() {
        secrets.remove(&provider_id);
    } else {
        secrets.insert(provider_id.clone(), api_key.clone());
        // Set as env var so the agent can use it immediately
        std::env::set_var(&env_key, &api_key);
        info!("Set env var {} for provider {}", env_key, provider_id);
    }
    write_secrets(&secrets)?;
    Ok(())
}

/// One-time reveal of a provider's API key — returns the full key, then caller must not store it
#[tauri::command]
async fn reveal_provider_api_key(provider_id: String) -> Result<Option<String>, String> {
    let secrets = read_secrets();
    Ok(secrets.get(&provider_id).cloned())
}

#[tauri::command]
async fn get_env_api_key(env_var: String) -> Result<Option<String>, String> {
    Ok(std::env::var(&env_var).ok())
}
