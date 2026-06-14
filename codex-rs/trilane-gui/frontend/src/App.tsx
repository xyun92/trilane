import { useState, useEffect, useRef } from "react";
import type { MouseEvent } from "react";
import { listen } from "@tauri-apps/api/event";
import ChatPanel from "./components/ChatPanel";
import ScanPanel from "./components/ScanPanel";
import FindingsPanel from "./components/FindingsPanel";
import StageProgress from "./components/StageProgress";
import SettingsPanel from "./components/SettingsPanel";
import { invokeWithTimeout } from "./lib/invoke";

interface ChatMessage {
  role: string;
  content: string;
  timestamp: string;
}

interface ScanProgress {
  stage: string;
  stage_name: string;
  progress: number;
  message: string;
  findings_count: number;
}

interface RunbookStage {
  id: string;
  code: string;
  name: string;
  label: string;
  status: "pending" | "active" | "done" | "blocked";
  summary: string;
  evidence_count: number;
  candidate_count: number;
  findings_count: number;
  updated_at: string;
}

interface RunbookCoverage {
  id: string;
  category: string;
  label: string;
  mapped_count: number;
  total_hint: number | null;
  status: "pending" | "mapped" | "partial";
  updated_at: string;
}

interface RunbookCandidate {
  id: string;
  stage: string;
  category: string;
  title: string;
  target: string;
  status:
    | "candidate"
    | "probed"
    | "needs_verify"
    | "rejected"
    | "duplicate"
    | "out_of_scope"
    | "confirmed";
  severity: string | null;
  evidence_count: number;
  verification_count: number;
  source_confirmed: boolean;
  updated_at: string;
}

interface RunbookSurface {
  id: string;
  stage: string;
  kind: string;
  category: string;
  label: string;
  target: string;
  signal_count: number;
  updated_at: string;
}

interface RunbookClaim {
  id: string;
  fingerprint: string;
  stage: string;
  category: string;
  title: string;
  target: string;
  status:
    | "seed"
    | "anchored"
    | "armed"
    | "running"
    | "corroborated"
    | "verified"
    | "weaponized"
    | "publishable"
    | "blocked"
    | "discarded"
    | "merged";
  evidence_level:
    | "signal"
    | "source_backed"
    | "runtime_signal"
    | "reproducible"
    | "impact_proven"
    | "control_passed";
  severity: string | null;
  code_path: string;
  root_cause: string;
  precondition: string;
  impact: string;
  payload: string;
  positive_evidence: string;
  negative_evidence: string;
  merged_into: string | null;
  signal_count: number;
  probe_count: number;
  verification_count: number;
  updated_at: string;
}

interface RunbookClaimSummary {
  surfaces: number;
  raw_signals: number;
  root_claims: number;
  publishable: number;
  verified: number;
  blocked: number;
  discarded: number;
  merged: number;
  coverage_debt: number;
  evidence_ladder_complete: number;
}

interface RunbookEvidence {
  id: string;
  stage: string;
  kind: string;
  title: string;
  detail: string;
  timestamp: string;
}

interface RunbookFinding {
  id: string;
  stage: string;
  candidate_id: string | null;
  severity: string;
  title: string;
  code_path: string;
  confidence: string;
  evidence_state: string;
  detail: string;
  timestamp: string;
}

interface RunbookAttackAtom {
  id: string;
  stage: string;
  lane_id: string;
  kind: string;
  category: string;
  target: string;
  label: string;
  claim_id: string | null;
  bridge_keys: string[];
  evidence: string;
  confidence: string;
}

interface RunbookChainCandidate {
  id: string;
  stage: string;
  title: string;
  status: string;
  impact: string;
  atom_ids: string[];
  bridge_keys: string[];
  verify_plan: string;
  score: number;
}

interface RunbookStats {
  coverage_mapped: number;
  coverage_total: number;
  coverage_debt: number;
  surfaces: number;
  surface_covered: number;
  domain_queues: number;
  domain_queues_closed: number;
  hypothesis_count: number;
  hypothesis_floor: number;
  hypothesis_debt: number;
  candidates: number;
  root_claims: number;
  probed: number;
  rejected: number;
  merged_claims: number;
  blocked_claims: number;
  discarded_claims: number;
  needs_verify: number;
  confirmed: number;
  publishable_claims: number;
  source_confirmed: number;
  evidence_signals: number;
}

interface RunbookState {
  status: "idle" | "running" | "completed" | "error";
  audit_mode: AuditMode;
  objective: string;
  current_stage: string;
  turn_id: string | null;
  stages: RunbookStage[];
  coverage: RunbookCoverage[];
  surfaces: RunbookSurface[];
  candidates: RunbookCandidate[];
  claims: RunbookClaim[];
  attack_atoms: RunbookAttackAtom[];
  chain_candidates: RunbookChainCandidate[];
  evidence: RunbookEvidence[];
  findings: RunbookFinding[];
  claim_summary: RunbookClaimSummary;
  stats: RunbookStats;
  last_updated: string;
}

interface Finding {
  id: string;
  title: string;
  severity: string;
  status: string;
  location: string;
  code_path: string;
  description: string;
  payload: string;
  cwe: string;
  confidence: string;
  evidence_state: string;
  duplicate_count: number;
  original_id: string;
  candidate_id: string | null;
}

type Tab = "chat" | "scan" | "findings" | "settings";
type AuditMode = "safe" | "lab";

const TABS: Array<{ id: Tab; label: string; code: string }> = [
  { id: "chat", label: "AGENT", code: "01" },
  { id: "scan", label: "SCAN", code: "02" },
  { id: "findings", label: "FINDINGS", code: "03" },
  { id: "settings", label: "CONFIG", code: "04" },
];
const MAX_STREAMING_COMMAND_CHARS = 2400;

export default function App() {
  const [activeTab, setActiveTab] = useState<Tab>("chat");
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [scanProgress, setScanProgress] = useState<ScanProgress | null>(null);
  const [runbookState, setRunbookState] = useState<RunbookState | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [agentStarted, setAgentStarted] = useState(false);
  const [agentStarting, setAgentStarting] = useState(false);
  const [auditMode, setAuditMode] = useState<AuditMode>(() => {
    const saved = window.localStorage.getItem("trilane.auditMode");
    return saved === "lab" ? "lab" : "safe";
  });
  const streamingMsgRef = useRef<string>("");
  const streamingMsgItemRef = useRef<string>("");
  const streamingCommandRef = useRef<string>("");
  const streamingCommandItemRef = useRef<string>("");

  function stripAnsi(text: string) {
    // eslint-disable-next-line no-control-regex
    return text.replace(/\x1b\[[0-9;]*[A-Za-z]/g, "");
  }

  function clampTranscript(text: string, maxChars: number) {
    if (text.length <= maxChars) return text;
    return `${text.slice(0, maxChars)}\n...[stream truncated]`;
  }

  useEffect(() => {
    window.localStorage.setItem("trilane.auditMode", auditMode);
  }, [auditMode]);

  // Listen for codex events (agent streaming responses)
  useEffect(() => {
    const unlisten = listen("codex-event", (event) => {
      const payload = event.payload as any;
      if (!payload) return;

      switch (payload.type) {
        case "AgentMessageDelta":
          if (streamingMsgItemRef.current !== payload.item_id) {
            streamingMsgItemRef.current = payload.item_id || "";
            streamingMsgRef.current = "";
          }
          streamingMsgRef.current += payload.delta || "";
          setMessages((prev) => {
            const last = prev[prev.length - 1];
            if (last && last.role === "assistant" && last.content.endsWith("__streaming__")) {
              return [
                ...prev.slice(0, -1),
                { ...last, content: streamingMsgRef.current + "__streaming__" },
              ];
            }
            return [
              ...prev,
              { role: "assistant", content: streamingMsgRef.current + "__streaming__", timestamp: Date.now().toString() },
            ];
          });
          break;

        case "TurnCompleted":
          // Finalize the streaming message
          const finalContent = streamingMsgRef.current;
          streamingMsgRef.current = "";
          streamingMsgItemRef.current = "";
          streamingCommandRef.current = "";
          streamingCommandItemRef.current = "";
          setMessages((prev) => {
            const cleaned = prev.map((message) => {
              if (!message.content.endsWith("__streaming__")) return message;
              const content = message.role === "assistant" && finalContent
                ? finalContent
                : message.content.replace(/__streaming__$/, "");
              return { ...message, content };
            });
            const hasCompletion = cleaned.some((message) => message.content.includes("SYS% turn completed"));
            if (hasCompletion) {
              return cleaned;
            }
            return [
              ...cleaned,
              {
                role: "system",
                content: `SYS% turn completed; status=${payload.status || "completed"}`,
                timestamp: Date.now().toString(),
              },
            ];
          });
          break;

        case "RunbookUpdated":
          setRunbookState(payload.state);
          break;

        case "SystemMessage":
          setMessages((prev) => [
            ...prev,
            {
              role: "system",
              content: payload.content || "",
              timestamp: Date.now().toString(),
            },
          ]);
          break;

        case "ItemCompleted": {
          // A single item (like a tool call or message) completed
          const text = payload.text || payload.content;
          const role = payload.role || (payload.item_type === "command_execution" ? "system" : "assistant");
          if (text) {
            if (role === "assistant") {
              streamingMsgRef.current = "";
              streamingMsgItemRef.current = "";
            }
            if (payload.item_type === "command_execution") {
              streamingCommandRef.current = "";
              streamingCommandItemRef.current = "";
            }
            setMessages((prev) => {
              const last = prev[prev.length - 1];
              if (last && last.role === role && last.content.endsWith("__streaming__")) {
                return [
                  ...prev.slice(0, -1),
                  { ...last, content: text },
                ];
              }
              return [
                ...prev,
                { role, content: text, timestamp: Date.now().toString() },
              ];
            });
          }
          break;
        }

        case "ApprovalRequired":
          // Auto-approve for now — the Rust backend already auto-accepts
          console.log("Approval required:", payload);
          break;

        case "CommandOutputDelta":
          // Command output streaming
          if (streamingCommandItemRef.current !== payload.item_id) {
            streamingCommandItemRef.current = payload.item_id || "";
            streamingCommandRef.current = "";
          }
          streamingCommandRef.current = clampTranscript(
            streamingCommandRef.current + stripAnsi(payload.delta || ""),
            MAX_STREAMING_COMMAND_CHARS,
          );
          setMessages((prev) => {
            const last = prev[prev.length - 1];
            const content = `CMD% streaming\n${streamingCommandRef.current}__streaming__`;
            if (last && last.role === "system" && last.content.startsWith("CMD% streaming")) {
              return [
                ...prev.slice(0, -1),
                { ...last, content },
              ];
            }
            return [
              ...prev,
              { role: "system", content, timestamp: Date.now().toString() },
            ];
          });
          break;

        case "Error":
          setMessages((prev) => [
            ...prev,
            { role: "system", content: payload.message || "Agent error", timestamp: Date.now().toString() },
          ]);
          break;
      }
    });

    return () => {
      unlisten.then((fn) => fn());
    };
  }, []);

  // Start agent before sending first message
  async function startAgentIfNeeded() {
    if (agentStarting) return true;
    try {
      const backendStarted = await invokeWithTimeout<boolean>("is_agent_started", undefined, 5000);
      if (backendStarted) {
        setAgentStarted(true);
        return true;
      }
      setAgentStarted(false);
    } catch (error) {
      setAgentStarted(false);
      setMessages((prev) => [
        ...prev,
        { role: "system", content: `Failed to reach agent backend: ${error}`, timestamp: Date.now().toString() },
      ]);
      return false;
    }
    setAgentStarting(true);
    try {
      await invokeWithTimeout("start_agent", { model: null, cwd: null, auditMode }, 45000);
      setAgentStarted(true);
      return true;
    } catch (e) {
      setMessages((prev) => [
        ...prev,
        { role: "system", content: `Failed to start agent: ${e}`, timestamp: Date.now().toString() },
      ]);
      return false;
    } finally {
      setAgentStarting(false);
    }
  }

  async function rebootAgent() {
    try {
      await invokeWithTimeout("stop_agent", undefined, 15000);
      await invokeWithTimeout("clear_chat", undefined, 5000);
    } catch (error) {
      console.error("Failed to stop agent:", error);
    } finally {
      streamingMsgRef.current = "";
      streamingMsgItemRef.current = "";
      streamingCommandRef.current = "";
      streamingCommandItemRef.current = "";
      setMessages([]);
      setRunbookState(null);
      setScanProgress(null);
      setAgentStarted(false);
      setAgentStarting(false);
    }
  }

  async function startWindowDrag(event: MouseEvent<HTMLElement>) {
    if (event.button !== 0) return;

    const target = event.target as HTMLElement;
    if (target.closest("button, .tabs, .window-controls")) return;

    try {
      await invokeWithTimeout("start_window_drag", undefined, 3000);
    } catch (error) {
      console.error("Failed to start window drag:", error);
    }
  }

  async function runWindowAction(command: string) {
    try {
      await invokeWithTimeout(command, undefined, 3000);
    } catch (error) {
      console.error("Failed to run window action:", error);
    }
  }

  // Poll runbook projection so Scan remains useful even if a frontend event is missed.
  useEffect(() => {
    const interval = setInterval(async () => {
      const progress = await invokeWithTimeout<ScanProgress | null>("get_scan_progress", undefined, 5000);
      setScanProgress(progress);
      const runbook = await invokeWithTimeout<RunbookState>("get_runbook_state", undefined, 5000);
      setRunbookState(runbook);
      const f = await invokeWithTimeout<Finding[]>("get_findings", undefined, 5000);
      setFindings(f);
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="app">
      {/* Header */}
      <header className="header" onMouseDown={startWindowDrag}>
        <div className="window-controls">
          <button
            type="button"
            className="window-btn window-btn-close"
            onClick={() => runWindowAction("close_window")}
          />
          <button
            type="button"
            className="window-btn window-btn-minimize"
            onClick={() => runWindowAction("minimize_window")}
          />
          <button
            type="button"
            className="window-btn window-btn-maximize"
            onClick={() => runWindowAction("toggle_maximize_window")}
          />
        </div>
        <div className="header-left">
          <h1 className="logo">
            <span className="logo-mark">TRI</span>
            <span>TRILANE://LOCAL</span>
          </h1>
          <span className="version">CRT OPS CONSOLE</span>
          {agentStarting && <span className="runtime-pill warn">BOOT</span>}
          {agentStarted && <span className="runtime-pill ok">ONLINE</span>}
        </div>
        <nav className="tabs">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              className={`tab ${activeTab === tab.id ? "active" : ""}`}
              onClick={() => setActiveTab(tab.id)}
            >
              <span className="tab-code">{tab.code}</span>
              <span>{tab.label}</span>
              {tab.id === "findings" && findings.length > 0 && (
                <span className="tab-count">{findings.length}</span>
              )}
            </button>
          ))}
        </nav>
      </header>

      {/* Stage Progress Bar */}
      {scanProgress && <StageProgress progress={scanProgress} />}

      {/* Main Content */}
      <main className="main">
        {activeTab === "chat" && (
          <ChatPanel
            messages={messages}
            setMessages={setMessages}
            agentStarted={agentStarted}
            agentStarting={agentStarting}
            auditMode={auditMode}
            setAuditMode={setAuditMode}
            onStartAgent={startAgentIfNeeded}
            onRebootAgent={rebootAgent}
          />
        )}
        {activeTab === "scan" && (
          <ScanPanel
            runbook={runbookState}
            progress={scanProgress}
            auditMode={auditMode}
          />
        )}
        {activeTab === "findings" && (
          <FindingsPanel findings={findings} />
        )}
        {activeTab === "settings" && (
          <SettingsPanel />
        )}
      </main>
    </div>
  );
}
