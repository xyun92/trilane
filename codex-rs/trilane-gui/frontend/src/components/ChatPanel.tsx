import { useState, useRef, useEffect } from "react";
import { invokeWithTimeout } from "../lib/invoke";

interface ChatMessage {
  role: string;
  content: string;
  timestamp: string;
}

interface Props {
  messages: ChatMessage[];
  setMessages: React.Dispatch<React.SetStateAction<ChatMessage[]>>;
  agentStarted: boolean;
  agentStarting: boolean;
  auditMode: "safe" | "lab";
  setAuditMode: React.Dispatch<React.SetStateAction<"safe" | "lab">>;
  onStartAgent: () => Promise<boolean>;
  onRebootAgent: () => Promise<void>;
}

const MAX_RENDERED_LINES = 120;
const COLLAPSED_SYSTEM_LINES = 3;

type PendingAuditMode = {
  nextMode: "safe" | "lab";
  requiresReboot: boolean;
};

export default function ChatPanel({
  messages,
  setMessages,
  agentStarted,
  agentStarting,
  auditMode,
  setAuditMode,
  onStartAgent,
  onRebootAgent,
}: Props) {
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [expandedSystemMessages, setExpandedSystemMessages] = useState<Set<string>>(new Set());
  const [pendingAuditMode, setPendingAuditMode] = useState<PendingAuditMode | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const handleSend = async () => {
    if (!input.trim() || isLoading) return;
    const userMsg = input.trim();
    setInput("");
    setIsLoading(true);

    setMessages((prev) => [
      ...prev,
      { role: "user", content: userMsg, timestamp: Date.now().toString() },
    ]);

    try {
      if (!agentStarted) {
        const ok = await onStartAgent();
        if (!ok) {
          setIsLoading(false);
          return;
        }
      }

      try {
        await invokeWithTimeout("send_message", {
          text: userMsg,
          auditMode,
        }, 15000);
      } catch (sendError) {
        if (!String(sendError).includes("Agent not started")) {
          throw sendError;
        }
        const ok = await onStartAgent();
        if (!ok) {
          setIsLoading(false);
          return;
        }
        await invokeWithTimeout("send_message", {
          text: userMsg,
          auditMode,
        }, 15000);
      }
      await pollChatHistory();
    } catch (e) {
      setMessages((prev) => [
        ...prev,
        { role: "system", content: `Error: ${e}`, timestamp: Date.now().toString() },
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  const pollChatHistory = () => new Promise<void>((resolve) => {
    let attempts = 0;
    let timeoutNoticeShown = false;
    let lastHistorySignature = "";
    const interval = window.setInterval(async () => {
      attempts += 1;
      try {
        const inProgress = await invokeWithTimeout<boolean>("is_turn_in_progress", undefined, 5000);
        const history = await invokeWithTimeout<ChatMessage[]>("get_chat_history", undefined, 5000);
        const historySignature = history
          .map((message) => `${message.role}:${message.timestamp}:${message.content.length}`)
          .join("|");
        if (history.length > 0 && historySignature !== lastHistorySignature) {
          lastHistorySignature = historySignature;
          setMessages(history);
        }
        if (!inProgress) {
          window.clearInterval(interval);
          resolve();
        }
        if (attempts >= 360 && !timeoutNoticeShown) {
          timeoutNoticeShown = true;
          setMessages((prev) => {
            return [
              ...prev,
              { role: "system", content: "SYS% backend turn still active; syncing completed transcript from backend", timestamp: Date.now().toString() },
            ];
          });
        }
      } catch (error) {
        setMessages((prev) => [
          ...prev,
          { role: "system", content: `SYS% chat IPC failed: ${error}`, timestamp: Date.now().toString() },
        ]);
        window.clearInterval(interval);
        resolve();
      }
    }, 500);
  });

  const handleReboot = async () => {
    setIsLoading(false);
    await onRebootAgent();
  };

  const requestAuditMode = async (nextMode: "safe" | "lab") => {
    if (nextMode === auditMode) return;
    const requiresConfirmation = nextMode === "lab" || agentStarted;
    if (requiresConfirmation) {
      setPendingAuditMode({ nextMode, requiresReboot: agentStarted });
      return;
    }
    setAuditMode(nextMode);
  };

  const confirmAuditModeChange = async () => {
    if (!pendingAuditMode) return;
    const { nextMode, requiresReboot } = pendingAuditMode;
    setPendingAuditMode(null);
    setAuditMode(nextMode);
    if (requiresReboot) {
      await handleReboot();
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  // Strip streaming markers from display
  const displayContent = (content: string) => {
    return content.replace(/__streaming__$/g, "");
  };

  const displayLines = (content: string) => {
    const lines = displayContent(content).split("\n");
    if (lines.length <= MAX_RENDERED_LINES) return lines;
    return [
      ...lines.slice(0, MAX_RENDERED_LINES),
      `...[${lines.length - MAX_RENDERED_LINES} lines hidden]`,
    ];
  };

  const messageKey = (msg: ChatMessage, index: number) => `${msg.timestamp}-${index}`;

  const renderedLinesForMessage = (msg: ChatMessage, index: number) => {
    const lines = displayLines(msg.content);
    if (msg.role !== "system" || expandedSystemMessages.has(messageKey(msg, index))) {
      return lines;
    }
    if (lines.length <= COLLAPSED_SYSTEM_LINES) {
      return lines;
    }
    return lines.slice(0, COLLAPSED_SYSTEM_LINES);
  };

  const toggleSystemMessage = (key: string) => {
    setExpandedSystemMessages((prev) => {
      const next = new Set(prev);
      if (next.has(key)) {
        next.delete(key);
      } else {
        next.add(key);
      }
      return next;
    });
  };

  const status = agentStarting ? "booting" : agentStarted ? "online" : "cold";

  return (
    <div className="chat-panel">
      <div className="console-topline">
        <div>
          <span className="eyebrow">AGENT%</span>
          <h2>terminal transcript</h2>
        </div>
        <div className={`agent-state ${status}`}>
          <span className="state-dot" />
          {status}
        </div>
      </div>

      {/* Messages */}
      <div className="terminal-body">
        <div className="messages">
          {messages.length === 0 && (
            <div className="empty-state">
              <div className="empty-kicker">TRILANE BOOT SEQUENCE COMPLETE</div>
              <h2>awaiting target_</h2>
              <p>NO ACTIVE TURN. TARGET BUFFER EMPTY.</p>
              <div className="quick-actions">
                <button onClick={() => setInput("Penetration test juice-shop, source code is in ~/juice-shop, service is running on localhost:3000. If not, use colima or start the service directly")}>
                  ./tri lab target
                </button>
                <button onClick={() => setInput("Explain the current TriLane runbook status")}>
                  man trilane
                </button>
                <button onClick={() => setInput("review the current workspace for auth bypass and injection paths")}>
                  audit --workspace
                </button>
              </div>
            </div>
          )}
          {messages.map((msg, i) => {
            const key = messageKey(msg, i);
            const lines = displayLines(msg.content);
            const renderedLines = renderedLinesForMessage(msg, i);
            const isCollapsedSystem = msg.role === "system" && renderedLines.length < lines.length;
            const isExpandedSystem = msg.role === "system" && expandedSystemMessages.has(key) && lines.length > COLLAPSED_SYSTEM_LINES;

            return (
              <div key={key} className={`message ${msg.role}`}>
                <div className="message-role">
                  {msg.role === "user" ? "YOU>" : msg.role === "assistant" ? "TRI%" : "SYS!"}
                </div>
                <div className="message-content">
                  {renderedLines.map((line, j) => (
                    <p key={j}>{line}</p>
                  ))}
                  {msg.content.endsWith("__streaming__") && (
                    <span className="typing-indicator">█</span>
                  )}
                  {(isCollapsedSystem || isExpandedSystem) && (
                    <button
                      className="message-toggle"
                      type="button"
                      onClick={() => toggleSystemMessage(key)}
                    >
                      {isExpandedSystem ? "LESS" : `SHOW +${lines.length - renderedLines.length}`}
                    </button>
                  )}
                </div>
              </div>
            );
          })}
          {agentStarting && (
            <div className="message system">
              <div className="message-role">SYS!</div>
              <div className="message-content">
                <span className="typing-indicator">booting agent...</span>
              </div>
            </div>
          )}
          <div ref={messagesEndRef} />
        </div>

        <aside className="ops-rail">
          <div className="rail-title">RUNTIME STACK</div>
          <div className="rail-row"><span>agent</span><strong>{status}</strong></div>
          <div className="rail-row"><span>mode</span><strong>{auditMode}</strong></div>
          <div className="rail-row"><span>scope</span><strong>workspace</strong></div>
          <div className="rail-row"><span>io</span><strong>tauri/ipc</strong></div>
          <div className="rail-meter">
            <span>signal</span>
            <div><i /><i /><i /><i className={agentStarted ? "" : "off"} /></div>
          </div>
          <button className="rail-action" type="button" onClick={handleReboot}>
            REBOOT AGENT
          </button>
        </aside>
      </div>

      {/* Input */}
      {pendingAuditMode && (
        <div className="mode-confirm" role="dialog" aria-label="confirm access mode change">
          <div>
            <span>ACCESS CHANGE</span>
            <strong>{pendingAuditMode.nextMode.toUpperCase()} MODE</strong>
            <p>
              {pendingAuditMode.nextMode === "lab"
                ? "Lab Mode grants full local filesystem and command execution access for authorized lab targets."
                : "Safe Mode constrains the local agent session and reduces write/exec freedom."}
            </p>
            {pendingAuditMode.requiresReboot && (
              <p>Changing mode requires rebooting the current local agent session.</p>
            )}
          </div>
          <div className="mode-confirm-actions">
            <button type="button" onClick={() => setPendingAuditMode(null)}>
              CANCEL
            </button>
            <button type="button" className="danger" onClick={() => void confirmAuditModeChange()}>
              CONFIRM
            </button>
          </div>
        </div>
      )}
      <div className="input-bar">
        <textarea
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="agent % type command, target, sink, or question"
          rows={1}
        />
        <div className="audit-mode-picker" aria-label="audit mode">
          <button
            type="button"
            className={auditMode === "safe" ? "active" : ""}
            onClick={() => void requestAuditMode("safe")}
            title="SAFE MODE"
          >
            <span />
            SAFE
          </button>
          <button
            type="button"
            className={auditMode === "lab" ? "active" : ""}
            onClick={() => void requestAuditMode("lab")}
            title="LAB MODE"
          >
            <span />
            LAB
          </button>
        </div>
        <button onClick={handleSend} disabled={isLoading || !input.trim()}>
          EXEC
        </button>
      </div>
    </div>
  );
}
