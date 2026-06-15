import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";

interface CustomProvider {
  id: string;
  name: string;
  base_url: string;
  env_key: string;
  api_key_masked: string;
}

interface ModelConfig {
  model_provider: string;
  model: string;
  multimodal_model: string;
  openai_base_url: string;
  api_key_env: string;
  model_context_window: number;
  model_reasoning_effort: string;
  oss_provider: string;
  custom_providers: CustomProvider[];
}

const BUILT_IN_PROVIDERS = [
  { id: "openai", name: "OpenAI", code: "OA", defaultUrl: "https://api.openai.com/v1", placeholder: "e.g. gpt-5, o3" },
  { id: "xiaomi", name: "Xiaomi MiMo", code: "XM", defaultUrl: "https://token-plan-cn.xiaomimimo.com/v1", placeholder: "mimo-v2.5-pro" },
  { id: "ollama", name: "Ollama", code: "OL", defaultUrl: "http://localhost:11434/v1", placeholder: "e.g. llama3, qwen2.5-coder:7b" },
  { id: "lmstudio", name: "LM Studio", code: "LM", defaultUrl: "http://localhost:1234/v1", placeholder: "local model name" },
  { id: "amazon-bedrock", name: "Bedrock", code: "BR", defaultUrl: "", placeholder: "e.g. anthropic.claude-3-5-sonnet" },
];

const XIAOMI_PROVIDER_ID = "xiaomi";
const XIAOMI_TOKEN_PLAN_CN_URL = "https://token-plan-cn.xiaomimimo.com/v1";
const XIAOMI_DEFAULT_MODEL = "mimo-v2.5-pro";
const XIAOMI_DEFAULT_MULTIMODAL_MODEL = "mimo-v2.5";

export default function SettingsPanel() {
  const [config, setConfig] = useState<ModelConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [apiKey, setApiKey] = useState("");
  const [showApiKey, setShowApiKey] = useState(false);
  const [newProviderId, setNewProviderId] = useState("");
  const [newProviderName, setNewProviderName] = useState("");
  const [newProviderUrl, setNewProviderUrl] = useState("");
  const [newProviderKey, setNewProviderKey] = useState("");
  const [saveError, setSaveError] = useState<string | null>(null);
  // One-time reveal state
  const [revealKey, setRevealKey] = useState<string | null>(null);
  const [revealProviderId, setRevealProviderId] = useState<string | null>(null);

  useEffect(() => {
    loadConfig();
  }, []);

  async function loadConfig() {
    try {
      const cfg = await invoke<ModelConfig>("read_model_config");
      setConfig(cfg);
      const key = cfg.model_provider === XIAOMI_PROVIDER_ID
        ? await invoke<string | null>("reveal_provider_api_key", { providerId: XIAOMI_PROVIDER_ID })
        : await invoke<string | null>("get_env_api_key", {
            envVar: cfg.api_key_env || "OPENAI_API_KEY",
          });
      if (key) setApiKey(key);
    } catch (e) {
      console.error("Failed to load config:", e);
      setConfig({
        model_provider: "openai",
        model: "",
        multimodal_model: XIAOMI_DEFAULT_MULTIMODAL_MODEL,
        openai_base_url: "https://api.openai.com/v1",
        api_key_env: "OPENAI_API_KEY",
        model_context_window: 1000000,
        model_reasoning_effort: "medium",
        oss_provider: "ollama",
        custom_providers: [],
      });
    }
    setLoading(false);
  }

  async function handleSave() {
    if (!config) return;
    setSaving(true);
    try {
      if (config.model_provider === XIAOMI_PROVIDER_ID && apiKey) {
        await invoke("save_provider_api_key", { providerId: XIAOMI_PROVIDER_ID, apiKey });
      }
      await invoke("save_model_config", { config });
      // Save any new provider API keys that were entered in the add form
      // Re-read from disk to verify persistence
      const verified = await invoke<ModelConfig>("read_model_config");
      setConfig(verified);
      setSaved(true);
      setSaveError(null);
      setTimeout(() => setSaved(false), 2000);
    } catch (e) {
      setSaveError(`Save failed: ${e}`);
    }
    setSaving(false);
  }

  async function addCustomProvider() {
    if (!config || !newProviderId || !newProviderUrl) return;
    if (newProviderId.trim().toLowerCase() === XIAOMI_PROVIDER_ID) {
      setSaveError("Xiaomi MiMo is a built-in provider. Select XM in provider.matrix instead.");
      return;
    }
    const envKey = newProviderId.toUpperCase().replace(/[^A-Z0-9]/g, "") + "_API_KEY";
    const updated = {
      ...config,
      model_provider: newProviderId,
      openai_base_url: newProviderUrl,
      custom_providers: [
        ...config.custom_providers,
        {
          id: newProviderId,
          name: newProviderName || newProviderId,
          base_url: newProviderUrl,
          env_key: envKey,
          api_key_masked: newProviderKey ? "***" : "not set",
        },
      ],
    };
    setConfig(updated);
    setNewProviderId("");
    setNewProviderName("");
    setNewProviderUrl("");
    // Save API key to secrets file separately (not in config.toml)
    if (newProviderKey) {
      try {
        await invoke("save_provider_api_key", { providerId: newProviderId, apiKey: newProviderKey });
      } catch (e) {
        setSaveError(`API key save failed: ${e}`);
      }
    }
    setNewProviderKey("");
    // Auto-save config after adding provider
    try {
      await invoke("save_model_config", { config: updated });
      // Re-read to verify + get correct masked key
      const verified = await invoke<ModelConfig>("read_model_config");
      setConfig(verified);
      setSaved(true);
      setSaveError(null);
      setTimeout(() => setSaved(false), 2000);
    } catch (e) {
      setSaveError(`Auto-save failed: ${e}`);
    }
  }

  function removeCustomProvider(id: string) {
    if (!config) return;
    const removedProvider = config.custom_providers.find((p) => p.id === id);
    const updated = {
      ...config,
      custom_providers: config.custom_providers.filter((p) => p.id !== id),
    };
    if (config.model_provider === id) {
      updated.model_provider = "openai";
      updated.openai_base_url = "https://api.openai.com/v1";
    }
    if (removedProvider && config.openai_base_url === removedProvider.base_url) {
      updated.openai_base_url = "https://api.openai.com/v1";
    }
    setConfig(updated);
    // Also remove API key from secrets
    invoke("save_provider_api_key", { providerId: id, apiKey: "" }).catch(() => {});
    // Auto-save config
    invoke("save_model_config", { config: updated })
      .then(async () => {
        const verified = await invoke<ModelConfig>("read_model_config");
        setConfig(verified);
        setSaved(true);
        setSaveError(null);
        setTimeout(() => setSaved(false), 2000);
      })
      .catch((e) => setSaveError(`Auto-save failed: ${e}`));
  }

  // One-time reveal: show full API key for 5 seconds, then clear
  async function handleRevealKey(providerId: string) {
    try {
      const key = await invoke<string | null>("reveal_provider_api_key", { providerId });
      if (key) {
        setRevealKey(key);
        setRevealProviderId(providerId);
        setTimeout(() => { setRevealKey(null); setRevealProviderId(null); }, 5000);
      }
    } catch (e) {
      setSaveError(`Reveal failed: ${e}`);
    }
  }

  // Update API key for existing custom provider
  async function handleUpdateApiKey(providerId: string, newKey: string) {
    try {
      await invoke("save_provider_api_key", { providerId, apiKey: newKey });
      // Re-read config to get updated masked key
      const verified = await invoke<ModelConfig>("read_model_config");
      setConfig(verified);
      setSaved(true);
      setSaveError(null);
      setTimeout(() => setSaved(false), 2000);
    } catch (e) {
      setSaveError(`API key update failed: ${e}`);
    }
  }

  function getActiveProviderInfo() {
    const builtIn = BUILT_IN_PROVIDERS.find((p) => p.id === config!.model_provider);
    if (builtIn) return { ...builtIn, base_url: config!.openai_base_url, isCustom: false };
    const custom = config!.custom_providers.find((p) => p.id === config!.model_provider);
    if (custom) return { id: custom.id, name: custom.name, code: "CU", defaultUrl: custom.base_url, placeholder: "model name on this provider", base_url: custom.base_url, isCustom: true };
    return null;
  }

  if (loading || !config) {
    return <div className="settings-loading">Loading config...</div>;
  }

  const activeProvider = getActiveProviderInfo();

  return (
    <div className="settings-panel">
      <div className="settings-header">
        <div>
          <span className="eyebrow">CONFIG/TOML</span>
          <h2>model router</h2>
        </div>
        <button className="btn-save" onClick={handleSave} disabled={saving}>
          {saving ? "WRITING" : saved ? "WROTE" : ":w"}
        </button>
      </div>
      {saveError && <div className="save-error">{saveError}</div>}

      {activeProvider && (
        <div className="settings-route">
          <div className="route-cell">
            <span>provider</span>
            <strong>active_provider = {activeProvider.name}</strong>
          </div>
          <div className="route-cell">
            <span>model</span>
            <strong>model = {config.model || "unset"}</strong>
          </div>
          {config.model_provider === XIAOMI_PROVIDER_ID && (
            <div className="route-cell">
              <span>vision</span>
              <strong>multimodal = {config.multimodal_model || XIAOMI_DEFAULT_MULTIMODAL_MODEL}</strong>
            </div>
          )}
          <div className="route-cell wide">
            <span>endpoint</span>
            <code>{config.openai_base_url || activeProvider.defaultUrl || "managed by provider"}</code>
          </div>
          <div className="route-cell">
            <span>reasoning</span>
            <strong>effort = {config.model_reasoning_effort}</strong>
          </div>
        </div>
      )}

      {/* Provider + Model (unified) */}
      <section className="settings-section">
        <h3>[provider.matrix]</h3>

        {/* Provider selection */}
        <div className="provider-grid">
          {BUILT_IN_PROVIDERS.map((p) => (
            <button
              key={p.id}
              className={`provider-card ${config.model_provider === p.id ? "active" : ""}`}
              onClick={() => {
                const newBaseUrl =
                  p.id === XIAOMI_PROVIDER_ID ? XIAOMI_TOKEN_PLAN_CN_URL :
                  p.id === "ollama" ? "http://localhost:11434/v1" :
                  p.id === "lmstudio" ? "http://localhost:1234/v1" :
                  p.id === "openai" ? "https://api.openai.com/v1" :
                  config.openai_base_url;
                setConfig({
                  ...config,
                  model_provider: p.id,
                  openai_base_url: newBaseUrl,
                  model: p.id === XIAOMI_PROVIDER_ID && !config.model ? XIAOMI_DEFAULT_MODEL : config.model,
                  multimodal_model: p.id === XIAOMI_PROVIDER_ID && !config.multimodal_model ? XIAOMI_DEFAULT_MULTIMODAL_MODEL : config.multimodal_model,
                });
              }}
            >
              <span className="provider-code">{p.code}</span>
              <span className="provider-name">{p.name}</span>
              <span className="provider-url">{p.defaultUrl || "aws runtime"}</span>
            </button>
          ))}
          {config.custom_providers.map((p) => (
            <button
              key={p.id}
              className={`provider-card custom ${config.model_provider === p.id ? "active" : ""}`}
              onClick={() => {
                setConfig({ ...config, model_provider: p.id, openai_base_url: p.base_url });
              }}
            >
              <span className="provider-code">CU</span>
              <span className="provider-name">{p.name}</span>
              <span className="provider-url">{p.base_url}</span>
            </button>
          ))}
        </div>

        {/* Model + connection settings for the selected provider */}
        {activeProvider && (
          <div className="provider-detail">
            <div className="settings-row">
              <label>model_name</label>
              <input
                type="text"
                value={config.model}
                onChange={(e) => setConfig({ ...config, model: e.target.value })}
                placeholder={activeProvider.placeholder}
              />
            </div>

            {/* Base URL for providers that need it */}
            {(config.model_provider === "openai" || config.model_provider === XIAOMI_PROVIDER_ID || activeProvider.isCustom) && (
              <div className="settings-row">
                <label>
                  {config.model_provider === XIAOMI_PROVIDER_ID
                    ? "mimo_base_url"
                    : activeProvider.isCustom ? "provider_base_url" : "base_url"}
                </label>
                <input
                  type="text"
                  value={config.openai_base_url}
                  onChange={(e) => {
                    const newUrl = e.target.value;
                    if (activeProvider.isCustom) {
                      const updatedProviders = config.custom_providers.map((p) =>
                        p.id === config.model_provider ? { ...p, base_url: newUrl } : p
                      );
                      setConfig({ ...config, openai_base_url: newUrl, custom_providers: updatedProviders });
                    } else {
                      setConfig({ ...config, openai_base_url: newUrl });
                    }
                  }}
                  placeholder={activeProvider.defaultUrl || "https://api.example.com/v1"}
                />
                {config.model_provider === XIAOMI_PROVIDER_ID && (
                  <p className="hint">
                    Token Plan CN uses <code>{XIAOMI_TOKEN_PLAN_CN_URL}</code>. Pay-as-you-go uses <code>https://api.xiaomimimo.com/v1</code>.
                  </p>
                )}
              </div>
            )}
            {config.model_provider === "ollama" && (
              <div className="settings-row">
                <label>ollama_url</label>
                <input
                  type="text"
                  value={config.openai_base_url}
                  onChange={(e) => setConfig({ ...config, openai_base_url: e.target.value })}
                  placeholder="http://localhost:11434/v1"
                />
              </div>
            )}
            {config.model_provider === "lmstudio" && (
              <div className="settings-row">
                <label>lmstudio_url</label>
                <input
                  type="text"
                  value={config.openai_base_url}
                  onChange={(e) => setConfig({ ...config, openai_base_url: e.target.value })}
                  placeholder="http://localhost:1234/v1"
                />
              </div>
            )}

            {config.model_provider === XIAOMI_PROVIDER_ID && (
              <>
                <div className="settings-row">
                  <label>mimo_multimodal_model</label>
                  <input
                    type="text"
                    value={config.multimodal_model || XIAOMI_DEFAULT_MULTIMODAL_MODEL}
                    onChange={(e) => setConfig({ ...config, multimodal_model: e.target.value })}
                    placeholder={XIAOMI_DEFAULT_MULTIMODAL_MODEL}
                  />
                  <p className="hint">
                    Image requests are automatically routed to this model. Xiaomi image understanding currently supports <code>mimo-v2.5</code> and <code>mimo-v2-omni</code>.
                  </p>
                </div>
                <div className="settings-row">
                  <label>mimo_api_key = XIAOMI_API_KEY</label>
                  <div className="api-key-row">
                    <input
                      type={showApiKey ? "text" : "password"}
                      value={apiKey}
                      onChange={(e) => setApiKey(e.target.value)}
                      placeholder="tp-xxxxx or sk-xxxxx"
                    />
                    <button
                      className="btn-toggle"
                      onClick={() => setShowApiKey(!showApiKey)}
                    >
                      {showApiKey ? "Hide" : "Show"}
                    </button>
                    <button
                      className="btn-toggle"
                      onClick={() => handleUpdateApiKey(XIAOMI_PROVIDER_ID, apiKey)}
                      disabled={!apiKey}
                    >
                      Save key
                    </button>
                  </div>
                  <p className="hint">
                    The MiMo adapter uses OpenAI-compatible <code>/chat/completions</code> and streams it into Responses-compatible events.
                  </p>
                </div>
              </>
            )}

            {/* API Key for built-in providers */}
            {!activeProvider.isCustom && config.model_provider !== XIAOMI_PROVIDER_ID && config.model_provider !== "ollama" && config.model_provider !== "lmstudio" && (
              <div className="settings-row">
                <label>api_key_env = {config.api_key_env}</label>
                <div className="api-key-row">
                  <input
                    type={showApiKey ? "text" : "password"}
                    value={apiKey}
                    onChange={(e) => setApiKey(e.target.value)}
                    placeholder="Set via environment variable"
                    disabled
                  />
                  <button
                    className="btn-toggle"
                    onClick={() => setShowApiKey(!showApiKey)}
                  >
                    {showApiKey ? "Hide" : "Show"}
                  </button>
                </div>
                <p className="hint">
                  Set via: <code>export {config.api_key_env}="your-key"</code>
                </p>
              </div>
            )}
          </div>
        )}
      </section>

      {/* Model Settings */}
      <section className="settings-section">
        <h3>[runtime.knobs]</h3>
        <div className="settings-row">
          <label>context_window_tokens</label>
          <input
            type="number"
            value={config.model_context_window}
            onChange={(e) =>
              setConfig({
                ...config,
                model_context_window: parseInt(e.target.value) || 1000000,
              })
            }
          />
        </div>
        <div className="settings-row">
          <label>reasoning_effort</label>
          <select
            value={config.model_reasoning_effort}
            onChange={(e) =>
              setConfig({ ...config, model_reasoning_effort: e.target.value })
            }
          >
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
          </select>
        </div>
      </section>

      {/* Custom Providers */}
      <section className="settings-section">
        <h3>[custom.providers]</h3>
        <p className="hint">
          Add generic OpenAI-compatible routes. Xiaomi MiMo has its own adapter above; use custom providers for vLLM, local gateways, DeepSeek-compatible endpoints, and private inference endpoints.
        </p>
        {config.custom_providers.map((p) => (
          <div key={p.id} className="custom-provider-card">
            <div className="provider-info">
              <strong>{p.name}</strong> <code>{p.base_url}</code>
              <span className="api-key-status">
                {revealProviderId === p.id && revealKey
                  ? <code className="reveal-key">{revealKey}</code>
                  : <span className="masked-key">{p.api_key_masked}</span>
                }
                <button className="btn-toggle btn-reveal" onClick={() => handleRevealKey(p.id)}>
                  {revealProviderId === p.id ? "shown (5s)" : "Reveal"}
                </button>
              </span>
            </div>
            <div className="provider-actions">
              <input
                type="password"
                className="api-key-input"
                placeholder="New API key"
                onKeyDown={(e) => {
                  if (e.key === "Enter" && e.currentTarget.value) {
                    handleUpdateApiKey(p.id, e.currentTarget.value);
                    e.currentTarget.value = "";
                  }
                }}
              />
              <button
                className="btn-remove"
                onClick={() => removeCustomProvider(p.id)}
              >
                Remove
              </button>
            </div>
          </div>
        ))}
        <div className="add-provider-form">
          <input
            type="text"
            value={newProviderId}
            onChange={(e) => setNewProviderId(e.target.value)}
            placeholder="Provider ID (e.g. deepseek)"
          />
          <input
            type="text"
            value={newProviderName}
            onChange={(e) => setNewProviderName(e.target.value)}
            placeholder="Display Name (e.g. Xiaomi MiMo)"
          />
          <input
            type="text"
            value={newProviderUrl}
            onChange={(e) => setNewProviderUrl(e.target.value)}
            placeholder="Base URL (e.g. https://api.example.com/v1)"
          />
          <input
            type="password"
            value={newProviderKey}
            onChange={(e) => setNewProviderKey(e.target.value)}
            placeholder="API Key"
          />
          <button className="btn-add" onClick={addCustomProvider}>
            Add provider
          </button>
        </div>
      </section>

      {/* Config File */}
      <section className="settings-section">
        <h3>[paths]</h3>
        <p className="hint">
          Config: <code>~/.trilane/config.toml</code> — API keys stored separately in <code>~/.trilane/secrets.toml</code>
        </p>
      </section>
    </div>
  );
}
