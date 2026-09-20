import React, { useState, useEffect } from 'react';
import type { EmailRecord, AttributionSupportResponse, Hop } from '../../types';
import { 
  Server, 
  Globe, 
  ShieldCheck, 
  AlertTriangle, 
  HelpCircle, 
  Info, 
  Clock, 
  ArrowRight,
  ShieldAlert,
  Compass
} from 'lucide-react';

interface Props {
  data: EmailRecord;
}

export const TraceTab: React.FC<Props> = ({ data }) => {
  const [attribution, setAttribution] = useState<AttributionSupportResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    if (data && data.id) {
      fetch(`/api/v1/emails/${data.id}/attribution-support`)
        .then((res) => (res.ok ? res.json() : null))
        .then((result: AttributionSupportResponse | null) => {
          if (result) setAttribution(result);
        })
        .catch((err) => console.warn('Attribution support fetch failed', err))
        .finally(() => setLoading(false));
    }
  }, [data?.id]);

  const sortedHops = [...(data.hops || [])].sort((a: Hop, b: Hop) => a.hop_number - b.hop_number);

  return (
    <div className="space-y-6 max-w-5xl">
      
      {/* Header Hop Route Timeline Visualizer */}
      <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-100 pb-3">
          <div className="flex items-center gap-2">
            <Compass className="w-5 h-5 text-indigo-600" />
            <h3 className="font-bold text-slate-900 text-lg">Header Transit Hop Trace</h3>
          </div>
          <span className="text-xs font-semibold text-slate-500 bg-slate-100 px-3 py-1 rounded-full">
            {sortedHops.length} Transit Hops Analyzed
          </span>
        </div>

        {/* Timeline Hops Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {sortedHops.map((hop: Hop, idx: number) => {
            const isSuspicious = hop.is_vpn_proxy_tor;
            return (
              <div 
                key={idx} 
                className={`p-3.5 rounded-lg border text-xs space-y-2 relative transition-all ${
                  isSuspicious ? 'bg-red-50/50 border-red-200' : 'bg-slate-50 border-slate-200'
                }`}
              >
                <div className="flex items-center justify-between font-bold">
                  <span className={`px-2 py-0.5 rounded text-[11px] ${isSuspicious ? 'bg-red-500 text-white' : 'bg-blue-600 text-white'}`}>
                    Hop {hop.hop_number}
                  </span>
                  <span className="font-mono text-slate-800">{hop.ip_address}</span>
                </div>

                <div className="space-y-1 text-slate-600">
                  <div className="flex items-center gap-1.5 truncate">
                    <Globe className="w-3.5 h-3.5 text-slate-400" />
                    <span>{hop.city || 'Unknown'}, {hop.country || 'Unknown'}</span>
                  </div>
                  <div className="flex items-center gap-1.5 truncate">
                    <Server className="w-3.5 h-3.5 text-slate-400" />
                    <span title={hop.isp}>{hop.isp || 'Unknown ISP'}</span>
                  </div>
                  <div className="flex items-center gap-1.5 text-slate-500">
                    <Clock className="w-3.5 h-3.5 text-slate-400" />
                    <span>Delay: {hop.delay_seconds}s</span>
                  </div>
                </div>

                {hop.is_vpn_proxy_tor && (
                  <div className="text-[10px] font-bold text-red-600 bg-red-100/80 px-2 py-0.5 rounded inline-block">
                    VPN / Proxy / Tor Node
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Attribution-Support Analysis Card (STEP 14) */}
      <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
        <div className="bg-gradient-to-r from-slate-900 to-indigo-950 px-5 py-4 text-white flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <ShieldCheck className="w-6 h-6 text-indigo-400" />
            <div>
              <h3 className="font-bold text-base">Attribution-Support Analysis</h3>
              <p className="text-xs text-slate-300">Evidence-based network infrastructure assessment</p>
            </div>
          </div>
          {attribution && (
            <div className="text-right">
              <span className="text-xs uppercase text-slate-300 font-semibold block">Confidence Level</span>
              <span className="text-lg font-extrabold text-emerald-400">{attribution.confidence_percentage}</span>
            </div>
          )}
        </div>

        <div className="p-5 space-y-5 text-xs text-slate-700">
          {loading ? (
            <div className="text-slate-500 animate-pulse">Calculating evidence-based attribution assessment...</div>
          ) : attribution ? (
            <>
              {/* 1. Probable Source Infrastructure */}
              <div className="bg-slate-50 p-4 rounded-lg border border-slate-200 space-y-1">
                <span className="text-[11px] font-extrabold text-slate-500 uppercase tracking-wider block">
                  Probable Source Infrastructure
                </span>
                <p className="text-sm font-bold text-slate-900 leading-snug">
                  {attribution.probable_source_infrastructure}
                </p>
              </div>

              {/* 2. Confidence Meter */}
              <div className="space-y-1.5">
                <div className="flex justify-between font-semibold">
                  <span className="text-slate-700">Assessment Confidence Score</span>
                  <span className="text-indigo-600 font-bold">{attribution.confidence_percentage}</span>
                </div>
                <div className="w-full bg-slate-100 h-2.5 rounded-full overflow-hidden">
                  <div 
                    className="bg-indigo-600 h-full rounded-full transition-all duration-500"
                    style={{ width: `${Math.round(attribution.confidence_score * 100)}%` }}
                  ></div>
                </div>
              </div>

              {/* 3. Supporting Evidence & Alternative Explanations Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Supporting Evidence */}
                <div className="bg-emerald-50/50 p-4 rounded-lg border border-emerald-200 space-y-2">
                  <h4 className="font-bold text-emerald-900 text-xs flex items-center gap-1.5">
                    <ShieldCheck className="w-4 h-4 text-emerald-600" />
                    Supporting Evidence
                  </h4>
                  <ul className="space-y-1.5 font-medium text-emerald-950">
                    {attribution.supporting_evidence.map((item, idx) => (
                      <li key={idx} className="flex items-start gap-1.5 leading-snug">
                        <span className="text-emerald-600 font-bold">•</span>
                        <span>{item}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Alternative Explanations */}
                <div className="bg-amber-50/50 p-4 rounded-lg border border-amber-200 space-y-2">
                  <h4 className="font-bold text-amber-900 text-xs flex items-center gap-1.5">
                    <HelpCircle className="w-4 h-4 text-amber-600" />
                    Alternative Technical Explanations
                  </h4>
                  <ul className="space-y-1.5 font-medium text-amber-950">
                    {attribution.alternative_explanations.map((item, idx) => (
                      <li key={idx} className="flex items-start gap-1.5 leading-snug">
                        <span className="text-amber-600 font-bold">•</span>
                        <span>{item}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>

              {/* 4. Limitations Disclaimer Notice Box */}
              <div className="bg-slate-100 p-4 rounded-lg border border-slate-300 flex items-start gap-3">
                <AlertTriangle className="w-5 h-5 text-slate-700 flex-shrink-0 mt-0.5" />
                <div className="space-y-0.5">
                  <span className="font-bold text-slate-900 text-xs uppercase tracking-wider block">
                    Limitations & Legal Attribution Disclaimer
                  </span>
                  <p className="text-slate-700 font-medium leading-relaxed">
                    "{attribution.limitations}"
                  </p>
                </div>
              </div>
            </>
          ) : (
            <p className="text-slate-500 italic">No attribution-support data available.</p>
          )}
        </div>
      </div>
    </div>
  );
};
