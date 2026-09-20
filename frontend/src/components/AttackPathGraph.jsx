import React, { useMemo, useState, useCallback } from "react";
import ReactFlow, {
  Background, Controls, MiniMap, MarkerType, useNodesState, useEdgesState,
} from "reactflow";
import "reactflow/dist/style.css";
import { SeverityBadge } from "./Badges";

const TYPE_ICON = {
  internet: "🌐",
  iam_user: "👤",
  iam_role: "🎭",
  ec2_instance: "🖥️",
  security_group: "🛡️",
  s3_bucket: "🪣",
  rds_instance: "🗄️",
  lambda_function: "λ",
  vpc: "🧩",
  kms_key: "🔑",
};

function layoutNodes(nodes, edges) {
  // Simple layered layout: BFS depth from entry points, columns by depth.
  const adjacency = {};
  edges.forEach((e) => {
    adjacency[e.source] = adjacency[e.source] || [];
    adjacency[e.source].push(e.target);
  });

  const depth = {};
  const entryPoints = nodes.filter((n) => n.is_entry_point).map((n) => n.id);
  const queue = entryPoints.length ? [...entryPoints] : [nodes[0]?.id].filter(Boolean);
  queue.forEach((id) => (depth[id] = 0));

  let i = 0;
  while (i < queue.length) {
    const current = queue[i++];
    const nextDepth = depth[current] + 1;
    (adjacency[current] || []).forEach((tgt) => {
      if (depth[tgt] === undefined || depth[tgt] > nextDepth) {
        depth[tgt] = nextDepth;
        queue.push(tgt);
      }
    });
  }

  const maxDepth = Math.max(0, ...Object.values(depth));
  nodes.forEach((n) => {
    if (depth[n.id] === undefined) depth[n.id] = maxDepth + 1;
  });

  const columnCounts = {};
  return nodes.map((n) => {
    const col = depth[n.id];
    columnCounts[col] = (columnCounts[col] || 0);
    const row = columnCounts[col]++;
    return {
      ...n,
      x: col * 260,
      y: row * 110,
    };
  });
}

export default function AttackPathGraph({ graphData, loading }) {
  const [selectedPath, setSelectedPath] = useState(null);

  const laidOut = useMemo(() => {
    if (!graphData) return [];
    return layoutNodes(graphData.nodes, graphData.edges);
  }, [graphData]);

  const highlightedNodeIds = useMemo(() => {
    if (!selectedPath) return null;
    return new Set(selectedPath.node_ids);
  }, [selectedPath]);

  const highlightedEdgeIds = useMemo(() => {
    if (!selectedPath) return null;
    return new Set(selectedPath.edge_ids);
  }, [selectedPath]);

  const flowNodes = useMemo(
    () =>
      laidOut.map((n) => {
        const dimmed = highlightedNodeIds && !highlightedNodeIds.has(n.id);
        const isHighlighted = highlightedNodeIds && highlightedNodeIds.has(n.id);
        let borderColor = "#232c3d";
        if (n.is_crown_jewel) borderColor = "#ef4444";
        else if (n.is_entry_point) borderColor = "#f0b429";
        if (isHighlighted) borderColor = "#f0b429";

        return {
          id: n.id,
          position: { x: n.x, y: n.y },
          data: {
            label: (
              <div className="flex items-center gap-2">
                <span>{TYPE_ICON[n.type] || "◆"}</span>
                <div className="flex flex-col">
                  <span className="text-xs font-medium text-slate-100 leading-tight">
                    {n.label}
                  </span>
                  <span className="text-[10px] text-slate-500 leading-tight">
                    {n.type.replace(/_/g, " ")}
                  </span>
                </div>
              </div>
            ),
          },
          style: {
            background: n.is_crown_jewel ? "#1f1315" : "#161d2b",
            border: `1.5px solid ${borderColor}`,
            borderRadius: 8,
            padding: "8px 10px",
            opacity: dimmed ? 0.25 : 1,
            width: 190,
          },
        };
      }),
    [laidOut, highlightedNodeIds]
  );

  const flowEdges = useMemo(
    () =>
      (graphData?.edges || []).map((e) => {
        const isHighlighted = highlightedEdgeIds && highlightedEdgeIds.has(e.id);
        const dimmed = highlightedEdgeIds && !isHighlighted;
        return {
          id: e.id,
          source: e.source,
          target: e.target,
          label: e.label.length > 28 ? e.label.slice(0, 26) + "…" : e.label,
          animated: isHighlighted,
          style: {
            stroke: isHighlighted ? "#f0b429" : "#3a4560",
            strokeWidth: isHighlighted ? 2.5 : 1.2,
            opacity: dimmed ? 0.15 : 0.9,
          },
          labelStyle: { fill: "#94a3b8", fontSize: 10 },
          labelBgStyle: { fill: "#0f1420" },
          markerEnd: { type: MarkerType.ArrowClosed, color: isHighlighted ? "#f0b429" : "#3a4560" },
        };
      }),
    [graphData, highlightedEdgeIds]
  );

  const [nodes, , onNodesChange] = useNodesState(flowNodes);
  const [edges, , onEdgesChange] = useEdgesState(flowEdges);

  const paths = graphData?.attack_paths || [];

  if (loading) {
    return <div className="text-slate-500 text-sm p-6">Analyzing attack surface…</div>;
  }

  return (
    <div className="grid grid-cols-1 xl:grid-cols-4 gap-4 h-[70vh]">
      <div className="xl:col-span-1 flex flex-col gap-2 overflow-y-auto pr-1">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-slate-300">Attack paths</h3>
          {selectedPath && (
            <button
              className="text-[11px] text-cg-accent hover:underline"
              onClick={() => setSelectedPath(null)}
            >
              clear
            </button>
          )}
        </div>
        {paths.length === 0 && (
          <p className="text-xs text-slate-500">No paths from entry points to sensitive data were found.</p>
        )}
        {paths.map((p) => (
          <button
            key={p.id}
            onClick={() => setSelectedPath(selectedPath?.id === p.id ? null : p)}
            className={`text-left rounded-lg border px-3 py-3 transition-colors ${
              selectedPath?.id === p.id
                ? "border-cg-accent bg-cg-accent/10"
                : "border-cg-border bg-cg-panel hover:border-slate-500"
            }`}
          >
            <div className="flex items-center justify-between mb-1.5">
              <SeverityBadge severity={p.severity} />
              <span className="font-mono text-xs text-slate-400">
                risk {p.total_risk_score}
              </span>
            </div>
            <p className="text-xs text-slate-300 font-medium mb-1">{p.name}</p>
            <p className="text-[11px] text-slate-500">{p.steps} hop{p.steps === 1 ? "" : "s"}</p>
          </button>
        ))}
      </div>

      <div className="xl:col-span-3 bg-cg-panel border border-cg-border rounded-lg overflow-hidden">
        <ReactFlow
          nodes={nodes.length ? nodes : flowNodes}
          edges={edges.length ? edges : flowEdges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          fitView
          proOptions={{ hideAttribution: true }}
        >
          <Background color="#1a2233" gap={20} />
          <Controls showInteractive={false} />
          <MiniMap
            nodeColor={() => "#232c3d"}
            maskColor="rgba(10,14,20,0.7)"
            style={{ background: "#0f1420" }}
          />
        </ReactFlow>
      </div>

      {selectedPath && (
        <div className="xl:col-span-4 bg-cg-panel border border-cg-border rounded-lg p-4">
          <h4 className="text-xs uppercase tracking-wide text-slate-500 mb-2">
            Attack narrative
          </h4>
          <p className="text-sm text-slate-300 leading-relaxed">{selectedPath.narrative}</p>
        </div>
      )}
    </div>
  );
}
