import React from 'react';
import type { EmailRecord } from '../../types';
import { Shield, ShieldCheck, ShieldAlert } from 'lucide-react';

interface Props {
  data: EmailRecord;
}

export const AuthTab: React.FC<Props> = ({ data }) => {
  const getStatusIcon = (status: string) => {
    const s = status.toUpperCase();
    if (s.includes('PASS')) return <ShieldCheck className="w-6 h-6 text-green-500" />;
    if (s.includes('FAIL') && !s.includes('SOFT')) return <ShieldAlert className="w-6 h-6 text-red-500" />;
    if (s.includes('SOFTFAIL')) return <ShieldAlert className="w-6 h-6 text-orange-500" />;
    return <Shield className="w-6 h-6 text-slate-400" />;
  };

  const getStatusBadge = (status: string) => {
    const s = status.toUpperCase();
    let bg = 'bg-slate-100 text-slate-700 border-slate-200';
    if (s.includes('PASS')) bg = 'bg-green-50 text-green-700 border-green-200';
    if (s.includes('FAIL') && !s.includes('SOFT')) bg = 'bg-red-50 text-red-700 border-red-200';
    if (s.includes('SOFTFAIL')) bg = 'bg-orange-50 text-orange-700 border-orange-200';
    
    return <span className={`px-2.5 py-1 text-xs font-semibold rounded-md border ${bg}`}>{status.toUpperCase()}</span>;
  };

  return (
    <div className="space-y-6 max-w-4xl">
      
      {/* Caveat Alert */}
      <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 flex gap-3">
        <Shield className="w-5 h-5 text-blue-600 flex-shrink-0 mt-0.5" />
        <div>
          <h4 className="font-semibold text-blue-900 text-sm">Forensic Caveat</h4>
          <p className="text-sm text-blue-800 mt-1">
            {data.auth_caveat || "The authentication results below are parsed from the Authentication-Results header reported by the receiving server. They have not been independently cryptographically verified by this tool."}
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        
        {/* SPF */}
        <div className="bg-white rounded-lg border border-slate-200 shadow-sm p-5">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              {getStatusIcon(data.spf_status)}
              <h3 className="font-bold text-slate-900 text-lg">SPF</h3>
            </div>
            {getStatusBadge(data.spf_status)}
          </div>
          <div className="space-y-3 mt-4 text-sm">
            <div>
              <span className="block text-xs font-semibold text-slate-500 uppercase tracking-wide">Domain</span>
              <span className="font-medium text-slate-900">{data.spf_details?.domain || 'Unknown'}</span>
            </div>
            <div>
              <span className="block text-xs font-semibold text-slate-500 uppercase tracking-wide">Explanation</span>
              <span className="text-slate-700">{data.spf_details?.explanation || 'No explanation provided.'}</span>
            </div>
          </div>
        </div>

        {/* DKIM */}
        <div className="bg-white rounded-lg border border-slate-200 shadow-sm p-5">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              {getStatusIcon(data.dkim_status)}
              <h3 className="font-bold text-slate-900 text-lg">DKIM</h3>
            </div>
            {getStatusBadge(data.dkim_status)}
          </div>
          <div className="space-y-3 mt-4 text-sm">
            <div>
              <span className="block text-xs font-semibold text-slate-500 uppercase tracking-wide">Domain</span>
              <span className="font-medium text-slate-900">{data.dkim_details?.domain || 'Unknown'}</span>
            </div>
            <div>
              <span className="block text-xs font-semibold text-slate-500 uppercase tracking-wide">Selector</span>
              <span className="font-medium text-slate-900">{data.dkim_details?.selector || 'Unknown'}</span>
            </div>
            <div>
              <span className="block text-xs font-semibold text-slate-500 uppercase tracking-wide">Explanation</span>
              <span className="text-slate-700">{data.dkim_details?.explanation || 'No explanation provided.'}</span>
            </div>
          </div>
        </div>

        {/* DMARC */}
        <div className="bg-white rounded-lg border border-slate-200 shadow-sm p-5">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              {getStatusIcon(data.dmarc_status)}
              <h3 className="font-bold text-slate-900 text-lg">DMARC</h3>
            </div>
            {getStatusBadge(data.dmarc_status)}
          </div>
          <div className="space-y-3 mt-4 text-sm">
            <div>
              <span className="block text-xs font-semibold text-slate-500 uppercase tracking-wide">Domain</span>
              <span className="font-medium text-slate-900">{data.dmarc_details?.domain || 'Unknown'}</span>
            </div>
            <div>
              <span className="block text-xs font-semibold text-slate-500 uppercase tracking-wide">Policy</span>
              <span className="font-medium text-slate-900">{data.dmarc_details?.policy || 'Unknown'}</span>
            </div>
            <div>
              <span className="block text-xs font-semibold text-slate-500 uppercase tracking-wide">Explanation</span>
              <span className="text-slate-700">{data.dmarc_details?.explanation || 'No explanation provided.'}</span>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
};
