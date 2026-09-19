import React, { useMemo } from 'react';
import type { EmailRecord, Hop } from '../../types';
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
import { ShieldAlert, Globe, Server } from 'lucide-react';

interface Props {
  data: EmailRecord;
}

// Custom Node component for Hop
const HopNode = ({ data }: { data: any }) => {
  const isSuspicious = data.isSuspicious;
  
  return (
    <div className={`px-4 py-3 rounded-lg border-2 shadow-md bg-white w-64 ${isSuspicious ? 'border-red-500 shadow-red-100' : 'border-blue-500 shadow-blue-100'}`}>
      <Handle type="target" position={Position.Left} className="w-2 h-2 bg-slate-400" />
      
      <div className="flex items-center justify-between border-b border-slate-100 pb-2 mb-2">
        <div className="flex items-center gap-2 font-bold text-slate-800">
          <div className={`flex items-center justify-center w-6 h-6 rounded-full text-xs text-white ${isSuspicious ? 'bg-red-500' : 'bg-blue-600'}`}>
            {data.hopNumber}
          </div>
          <span className="text-sm truncate w-32" title={data.ip}>{data.ip}</span>
        </div>
        {isSuspicious && <ShieldAlert className="w-4 h-4 text-red-500" />}
      </div>
      
      <div className="space-y-1 text-xs text-slate-600">
        <div className="flex items-center gap-1.5">
          <Globe className="w-3 h-3 text-slate-400" />
          <span className="truncate">{data.city || 'Unknown'}, {data.country || 'Unknown'}</span>
        </div>
        <div className="flex items-center gap-1.5">
          <Server className="w-3 h-3 text-slate-400" />
          <span className="truncate" title={data.isp}>{data.isp || 'Unknown ISP'}</span>
        </div>
        {data.isVpnProxyTor && (
          <div className="mt-2 text-xs font-semibold text-red-600 bg-red-50 px-2 py-0.5 rounded inline-block">
            VPN/Proxy Detected
          </div>
        )}
      </div>

      <Handle type="source" position={Position.Right} className="w-2 h-2 bg-slate-400" />
    </div>
  );
};

const nodeTypes = {
  hopNode: HopNode,
};

const GraphContent: React.FC<Props> = ({ data }) => {
  const { nodes, edges } = useMemo(() => {
    if (!data || !data.hops || data.hops.length === 0) {
      return { nodes: [], edges: [] };
    }

    const initialNodes: Node[] = [];
    const initialEdges: Edge[] = [];

    // Sort hops by hop_number just in case
    const sortedHops = [...data.hops].sort((a, b) => a.hop_number - b.hop_number);

    let xOffset = 50;
    
    sortedHops.forEach((hop: Hop, index) => {
      const isSuspicious = hop.is_vpn_proxy_tor || hop.infrastructure_intel?.reputation === 'suspicious' || hop.infrastructure_intel?.reputation === 'malicious';
      
      initialNodes.push({
        id: `hop-${hop.hop_number}`,
        type: 'hopNode',
        position: { x: xOffset, y: 150 },
        data: {
          hopNumber: hop.hop_number,
          ip: hop.ip_address,
          country: hop.country,
          city: hop.city,
          isp: hop.isp,
          isSuspicious: isSuspicious,
          isVpnProxyTor: hop.is_vpn_proxy_tor
        }
      });

      if (index > 0) {
        const prevHop = sortedHops[index - 1];
        initialEdges.push({
          id: `edge-${prevHop.hop_number}-${hop.hop_number}`,
          source: `hop-${prevHop.hop_number}`,
          target: `hop-${hop.hop_number}`,
          label: `${hop.delay_seconds}s delay`,
          type: 'smoothstep',
          animated: true,
          labelStyle: { fill: '#64748b', fontWeight: 600, fontSize: 10 },
          labelBgStyle: { fill: '#f8fafc', fillOpacity: 0.8 },
          style: { stroke: isSuspicious ? '#ef4444' : '#94a3b8', strokeWidth: 2 },
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: isSuspicious ? '#ef4444' : '#94a3b8',
          },
        });
      }

      xOffset += 320; // Space between nodes
    });

    return { nodes: initialNodes, edges: initialEdges };
  }, [data]);

  if (nodes.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-slate-500">
        <p>No transit graph data available for this email.</p>
      </div>
    );
  }

  return (
    <div className="w-full h-[600px] border border-slate-200 rounded-lg bg-slate-50 overflow-hidden shadow-inner">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.2 }}
        minZoom={0.5}
        maxZoom={1.5}
        attributionPosition="bottom-right"
      >
        <Background color="#cbd5e1" gap={16} />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
};

export const GraphTab: React.FC<Props> = ({ data }) => {
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-medium text-slate-900">Email Transit Network</h2>
        <div className="flex gap-4 text-xs font-medium">
          <div className="flex items-center gap-1.5 text-slate-600">
            <div className="w-3 h-3 rounded-full bg-blue-500"></div> Normal Route
          </div>
          <div className="flex items-center gap-1.5 text-slate-600">
            <div className="w-3 h-3 rounded-full bg-red-500"></div> Suspicious Hop
          </div>
        </div>
      </div>
      <ReactFlowProvider>
        <GraphContent data={data} />
      </ReactFlowProvider>
    </div>
  );
};
