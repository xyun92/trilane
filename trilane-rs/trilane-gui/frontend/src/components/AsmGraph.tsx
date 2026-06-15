import { useEffect, useMemo, useState } from "react";
import {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MiniMap,
  Position,
  ReactFlow,
  type NodeMouseHandler,
  type NodeProps,
  type NodeTypes,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { buildGraph, toneColor, type AsmFlowNode, type AsmGraphProps } from "./AsmGraphModel";

const nodeTypes: NodeTypes = {
  asmNode: AsmNode,
};

function AsmNode({ data, selected }: NodeProps<AsmFlowNode>) {
  return (
    <div className={`asm-node tone-${data.tone} kind-${data.kind} ${selected ? "selected" : ""}`}>
      <Handle type="target" position={Position.Left} className="asm-handle" />
      <div className="asm-node-kicker">
        <span>{data.kind}</span>
        <strong>{data.status || data.stage || "mapped"}</strong>
      </div>
      <div className="asm-node-title">{data.title}</div>
      <div className="asm-node-subtitle">{data.subtitle}</div>
      {data.metric && <div className="asm-node-meter">{data.metric}</div>}
      <Handle type="source" position={Position.Right} className="asm-handle" />
    </div>
  );
}

export default function AsmGraph({ runbook, auditMode }: AsmGraphProps) {
  const { nodes, edges, selectedFallbackId, summary } = useMemo(
    () => buildGraph(runbook, auditMode),
    [auditMode, runbook],
  );
  const [selectedId, setSelectedId] = useState(selectedFallbackId);
  const handleNodeClick: NodeMouseHandler<AsmFlowNode> = (_, node) => setSelectedId(node.id);

  useEffect(() => {
    if (!nodes.some((node) => node.id === selectedId)) {
      setSelectedId(selectedFallbackId);
    }
  }, [nodes, selectedFallbackId, selectedId]);

  const selectedNode = nodes.find((node) => node.id === selectedId) ?? nodes[0];

  return (
    <section className="asm-cockpit">
      <div className="asm-cockpit-header">
        <div>
          <span className="eyebrow">ASM GRAPH</span>
          <h3>Attack state map</h3>
        </div>
        <div className="asm-legend">
          <span><i className="legend-domain" />Domain</span>
          <span><i className="legend-surface" />Surface</span>
          <span><i className="legend-claim" />Claim</span>
          <span><i className="legend-chain" />Chain</span>
          <span><i className="legend-finding" />Finding</span>
          <span><i className="legend-rejected" />Rejected</span>
        </div>
      </div>

      <div className="asm-layout">
        <div className="asm-flow-shell">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            fitView
            fitViewOptions={{ padding: 0.18 }}
            minZoom={0.2}
            maxZoom={1.45}
            nodesDraggable={false}
            nodesConnectable={false}
            elementsSelectable
            onNodeClick={handleNodeClick}
            proOptions={{ hideAttribution: true }}
          >
            <Background
              variant={BackgroundVariant.Lines}
              gap={24}
              color="#504945"
            />
            <MiniMap
              pannable
              zoomable
              nodeColor={(node) => toneColor((node.data as AsmFlowNode["data"]).tone)}
              maskColor="rgba(29, 32, 33, 0.72)"
            />
            <Controls showInteractive={false} />
          </ReactFlow>
        </div>

        <aside className="asm-inspector">
          <div className="asm-inspector-top">
            <span>{summary.phase}</span>
            <strong>{summary.complexity}</strong>
          </div>
          {selectedNode ? (
            <>
              <div className={`asm-inspector-badge tone-${selectedNode.data.tone}`}>
                {selectedNode.data.kind} / {selectedNode.data.status || "mapped"}
              </div>
              <h4>{selectedNode.data.title}</h4>
              <p>{selectedNode.data.detail || selectedNode.data.subtitle}</p>
              <dl>
                <div>
                  <dt>Category</dt>
                  <dd>{selectedNode.data.category || "target"}</dd>
                </div>
                <div>
                  <dt>Stage</dt>
                  <dd>{selectedNode.data.stage || "ASM"}</dd>
                </div>
                <div>
                  <dt>Severity</dt>
                  <dd>{selectedNode.data.severity || "n/a"}</dd>
                </div>
                <div>
                  <dt>Signal</dt>
                  <dd>{selectedNode.data.metric || "watching"}</dd>
                </div>
              </dl>
            </>
          ) : (
            <p className="asm-empty">Waiting for the runbook to emit graphable state.</p>
          )}
          <div className="asm-summary-grid">
            <div><span>Nodes</span><strong>{nodes.length}</strong></div>
            <div><span>Edges</span><strong>{edges.length}</strong></div>
            <div><span>Mode</span><strong>{summary.mode}</strong></div>
            <div><span>Findings</span><strong>{summary.findings}</strong></div>
          </div>
        </aside>
      </div>
    </section>
  );
}
