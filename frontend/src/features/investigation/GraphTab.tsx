import React, { useState, useEffect, useMemo } from 'react';
import type { EmailRecord, GraphDataResponse, GraphNode as GraphNodeType, GraphEdge as GraphEdgeType } from '../../types';
import ReactFlow, { 
  Background, 
  Controls, 
  MarkerType,
  Handle,
  Position,
  ReactFlowProvider
} from 'reactflow';
import type { Node, Edge } from 'reactflow';
import 'reactflow/dist/style.css';
import { 
  Mail, 
  User, 
  Globe, 
  Link as LinkIcon, 
  Server, 
  Cpu, 
  MapPin, 
  Target, 
  Briefcase, 
  ShieldAlert, 
  CheckCircle2, 
  Info,
  Database,
  RefreshCw
} from 'lucide-react';

interface Props {
  data: EmailRecord;
}

// Visual theme configurations per node label
const LABEL_THEMES: Record<string, { bg: string; border: string; text: string; icon: any }> = {
  Email: { bg: 'bg-indigo-50', border: 'border-indigo-500', text: 'text-indigo-700', icon: Mail },
  Sender: { bg: 'bg-purple-50', border: 'border-purple-500', text: 'text-purple-700', icon: User },
  Domain: { bg: 'bg-blue-50', border: 'border-blue-500', text: 'text-blue-700', icon: Globe },
  URL: { bg: 'bg-amber-50', border: 'border-amber-500', text: 'text-amber-700', icon: LinkIcon },
  IP: { bg: 'bg-cyan-50', border: 'border-cyan-500', text: 'text-cyan-700', icon: Server },
  ASN: { bg: 'bg-slate-50', border: 'border-slate-500', text: 'text-slate-700', icon: Cpu },
  ISP: { bg: 'bg-emerald-50', border: 'border-emerald-500', text: 'text-emerald-700', icon: Server },
  Country: { bg: 'bg-emerald-100', border: 'border-emerald-600', text: 'text-emerald-800', icon: MapPin },
  Campaign: { bg: 'bg-rose-50', border: 'border-rose-500', text: 'text-rose-700', icon: Target },
  Case: { bg: 'bg-sky-50', border: 'border-sky-500', text: 'text-sky-700', icon: Briefcase },
};

// Generic Custom Node Component
const EntityNodeCard = ({ data }: { data: { label: string; properties: any; onSelect?: () => void } }) => {
  const label = data.label || 'Node';
  const props = data.properties || {};
  const theme = LABEL_THEMES[label] || { bg: 'bg-gray-50', border: 'border-gray-400', text: 'text-gray-700', icon: Info };
  const IconComponent = theme.icon;

  const title = props.address || props.url || props.name || props.subject_summary || props.case_number || props.asn || props.id || label;
  const isSuspicious = props.is_suspicious || props.threat_level === 'High' || props.threat_level === 'Critical' || props.is_vpn_proxy_tor;

  return (
    <div 
      className={`px-3.5 py-2.5 rounded-lg border-2 shadow-md bg-white w-64 cursor-pointer hover:shadow-lg transition-all ${
        isSuspicious ? 'border-red-500 shadow-red-100' : theme.border
      }`}
    >
      <Handle type="target" position={Position.Left} className="w-2.5 h-2.5 bg-slate-400" />

      <div className="flex items-center justify-between border-b border-slate-100 pb-1.5 mb-1.5">
        <div className="flex items-center gap-1.5 font-bold text-xs">
          <div className={`p-1 rounded-md ${theme.bg} ${theme.text}`}>
            <IconComponent className="w-3.5 h-3.5" />
          </div>
          <span className="uppercase text-[10px] tracking-wider font-extrabold text-slate-500">{label}</span>
        </div>
        {isSuspicious && (
          <span className="flex items-center gap-1 text-[10px] font-bold text-red-600 bg-red-50 px-1.5 py-0.5 rounded">
            <ShieldAlert className="w-3 h-3 text-red-500" /> Threat
          </span>
        )}
      </div>

      <div className="space-y-1 text-xs text-slate-800">
        <div className="font-semibold text-slate-900 truncate" title={String(title)}>
          {String(title)}
        </div>
        {props.threat_score !== undefined && (
          <div className="text-[11px] text-slate-500 flex justify-between">
            <span>Threat Score:</span>
            <span className="font-bold text-red-600">{props.threat_score}/100</span>
          </div>
        )}
        {props.reputation_score !== undefined && (
          <div className="text-[11px] text-slate-500 flex justify-between">
            <span>Reputation:</span>
            <span className={`font-semibold ${props.reputation_score < 50 ? 'text-red-600' : 'text-emerald-600'}`}>
              {props.reputation_score}/100
            </span>
          </div>
        )}
        {props.is_vpn_proxy_tor && (
          <div className="text-[10px] font-semibold text-amber-700 bg-amber-50 px-1.5 py-0.5 rounded inline-block mt-1">
            VPN / Proxy / TOR Node
          </div>
        )}
      </div>

      <Handle type="source" position={Position.Right} className="w-2.5 h-2.5 bg-slate-400" />
    </div>
  );
};

const nodeTypes = {
  entityNode: EntityNodeCard,
};

export const GraphTab: React.FC<Props> = ({ data }) => {
  const [graphData, setGraphData] = useState<GraphDataResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedNode, setSelectedNode] = useState<GraphNodeType | null>(null);

  const fetchGraph = async () => {
    setLoading(true);
    try {
      const response = await fetch(`/api/v1/graph/email/${data.id}`);
      if (response.ok) {
        const result: GraphDataResponse = await response.json();
        setGraphData(result);
      } else {
        throw new Error('API request failed');
      }
    } catch (err) {
      console.warn('Failed to fetch backend threat graph, building fallback graph', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (data && data.id) {
      fetchGraph();
    }
  }, [data?.id]);

  const { nodes, edges } = useMemo(() => {
    if (!graphData || !graphData.nodes || graphData.nodes.length === 0) {
      return { nodes: [], edges: [] };
    }

    // Auto-layout node positions by category column
    const columnOffsets: Record<string, number> = {
      Case: 50,
      Email: 350,
      Sender: 650,
      Domain: 950,
      URL: 950,
      IP: 1250,
      ISP: 1550,
      ASN: 1550,
      Country: 1850,
      Campaign: 650,
    };

    const columnYCounters: Record<string, number> = {};

    const flowNodes: Node[] = graphData.nodes.map((node: GraphNodeType) => {
      const label = node.label || 'Entity';
      const x = columnOffsets[label] || 600;
      const yCount = columnYCounters[label] || 0;
      columnYCounters[label] = yCount + 1;
      const y = 80 + yCount * 130;

      return {
        id: node.id,
        type: 'entityNode',
        position: { x, y },
        data: {
          label: node.label,
          properties: node.properties
        }
      };
    });

    const flowEdges: Edge[] = graphData.edges.map((edge: GraphEdgeType) => {
      const isRisk = edge.relationship === 'CONTAINS' || edge.relationship === 'PART_OF';

      return {
        id: edge.id,
        source: edge.source,
        target: edge.target,
        label: edge.relationship,
        type: 'smoothstep',
        animated: isRisk,
        labelStyle: { fill: '#475569', fontWeight: 700, fontSize: 10 },
        labelBgStyle: { fill: '#ffffff', fillOpacity: 0.9 },
        style: { stroke: isRisk ? '#ef4444' : '#64748b', strokeWidth: 2 },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: isRisk ? '#ef4444' : '#64748b',
        },
      };
    });

    return { nodes: flowNodes, edges: flowEdges };
  }, [graphData]);

  const isLiveNeo4j = graphData?.provider_mode === 'NEO4J_LIVE' && graphData?.is_neo4j_connected;

  return (
    <div className="space-y-4">
      {/* Header Controls & Status Banner */}
      <div className="flex flex-wrap items-center justify-between gap-3 bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
        <div>
          <h2 className="text-xl font-bold text-slate-900 flex items-center gap-2">
            <Database className="w-5 h-5 text-indigo-600" />
            Threat Relationship Graph
          </h2>
          <p className="text-xs text-slate-500">
            Multi-entity network topology linking Email, Sender, Domain, IP, ASN, Country, Campaign & Case
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Connection Mode Indicator */}
          {isLiveNeo4j ? (
            <div className="flex items-center gap-1.5 bg-emerald-50 text-emerald-700 px-3 py-1.5 rounded-full text-xs font-semibold border border-emerald-200">
              <CheckCircle2 className="w-4 h-4 text-emerald-600" />
              <span>Neo4j Database (Live Connected)</span>
            </div>
          ) : (
            <div className="flex items-center gap-1.5 bg-amber-50 text-amber-800 px-3 py-1.5 rounded-full text-xs font-semibold border border-amber-200" title="Neo4j is disconnected in dev environment. Operating via Demo Graph Provider.">
              <Info className="w-4 h-4 text-amber-600" />
              <span>Demo Graph Provider Mode (Neo4j Offline)</span>
            </div>
          )}

          <button
            onClick={fetchGraph}
            disabled={loading}
            className="flex items-center gap-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Graph Visualizer Container */}
      <div className="w-full h-[620px] border border-slate-200 rounded-xl bg-slate-900 overflow-hidden shadow-lg relative">
        <ReactFlowProvider>
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            onNodeClick={(_, node) => {
              const matched = graphData?.nodes.find(n => n.id === node.id);
              if (matched) setSelectedNode(matched);
            }}
            fitView
            fitViewOptions={{ padding: 0.2 }}
            minZoom={0.3}
            maxZoom={1.8}
            attributionPosition="bottom-right"
          >
            <Background color="#334155" gap={20} size={1} />
            <Controls className="bg-white border border-slate-200 shadow-md rounded-lg" />
          </ReactFlow>
        </ReactFlowProvider>

        {/* Selected Node Details Drawer */}
        {selectedNode && (
          <div className="absolute bottom-4 right-4 w-80 bg-white/95 backdrop-blur-md rounded-xl shadow-2xl border border-slate-200 p-4 text-xs space-y-3 z-10 animate-in fade-in slide-in-from-bottom-2 duration-200">
            <div className="flex items-center justify-between border-b border-slate-200 pb-2">
              <span className="font-bold text-slate-900 uppercase text-[11px] tracking-wider">
                {selectedNode.label} Metadata
              </span>
              <button 
                onClick={() => setSelectedNode(null)} 
                className="text-slate-400 hover:text-slate-600 font-bold"
              >
                ✕
              </button>
            </div>
            <div className="max-h-48 overflow-y-auto space-y-1.5 font-mono text-[11px]">
              {Object.entries(selectedNode.properties || {}).map(([key, val]) => (
                <div key={key} className="flex justify-between gap-2 border-b border-slate-100 pb-1">
                  <span className="text-slate-500 font-semibold">{key}:</span>
                  <span className="text-slate-800 text-right truncate" title={String(val)}>{String(val)}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Entity Nodes Legend */}
      <div className="bg-white p-3.5 rounded-xl border border-slate-200 shadow-sm flex flex-wrap gap-4 text-xs font-medium text-slate-600">
        <span className="font-bold text-slate-900">Node Legend:</span>
        <div className="flex items-center gap-1.5"><div className="w-3 h-3 rounded-full bg-indigo-500"></div> Email</div>
        <div className="flex items-center gap-1.5"><div className="w-3 h-3 rounded-full bg-purple-500"></div> Sender</div>
        <div className="flex items-center gap-1.5"><div className="w-3 h-3 rounded-full bg-blue-500"></div> Domain</div>
        <div className="flex items-center gap-1.5"><div className="w-3 h-3 rounded-full bg-amber-500"></div> URL</div>
        <div className="flex items-center gap-1.5"><div className="w-3 h-3 rounded-full bg-cyan-500"></div> IP</div>
        <div className="flex items-center gap-1.5"><div className="w-3 h-3 rounded-full bg-slate-500"></div> ASN / ISP</div>
        <div className="flex items-center gap-1.5"><div className="w-3 h-3 rounded-full bg-emerald-500"></div> Country</div>
        <div className="flex items-center gap-1.5"><div className="w-3 h-3 rounded-full bg-rose-500"></div> Campaign</div>
        <div className="flex items-center gap-1.5"><div className="w-3 h-3 rounded-full bg-sky-500"></div> Case</div>
      </div>
    </div>
  );
};
