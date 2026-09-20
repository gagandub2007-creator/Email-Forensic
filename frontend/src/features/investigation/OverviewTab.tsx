import React, { useState, useEffect } from 'react';
import type { EmailRecord, CorrelationResponse } from '../../types';
import { Mail, Calendar, User, UserCheck, AlertTriangle, History, Layers, ShieldCheck, Info, ExternalLink } from 'lucide-react';

interface Props {
  data: EmailRecord;
}

export const OverviewTab: React.FC<Props> = ({ data }) => {
  const [correlations, setCorrelations] = useState<CorrelationResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    if (data && data.id) {
      fetch(`/api/v1/emails/${data.id}/correlations`)
        .then((res) => (res.ok ? res.json() : null))
        .then((result: CorrelationResponse | null) => {
          if (result) setCorrelations(result);
        })
        .catch((err) => console.warn('Correlation fetch failed', err))
        .finally(() => setLoading(false));
    }
  }, [data?.id]);

  return (
    <div className="space-y-6 max-w-4xl">
      
      {/* Key Metadata Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-white p-4 rounded-lg border border-slate-200 shadow-sm">
          <div className="flex items-center gap-2 text-slate-500 mb-1">
            <User className="w-4 h-4" />
            <span className="text-xs font-semibold uppercase tracking-wider">Sender</span>
          </div>
          <div className="text-sm font-medium text-slate-900 truncate" title={data.sender_address}>
            {data.sender_name ? `${data.sender_name} <${data.sender_address}>` : data.sender_address}
          </div>
        </div>

        <div className="bg-white p-4 rounded-lg border border-slate-200 shadow-sm">
          <div className="flex items-center gap-2 text-slate-500 mb-1">
            <UserCheck className="w-4 h-4" />
            <span className="text-xs font-semibold uppercase tracking-wider">Recipient</span>
          </div>
          <div className="text-sm font-medium text-slate-900 truncate" title={data.recipient_address}>
            {data.recipient_address}
          </div>
        </div>

        <div className="bg-white p-4 rounded-lg border border-slate-200 shadow-sm">
          <div className="flex items-center gap-2 text-slate-500 mb-1">
            <Calendar className="w-4 h-4" />
            <span className="text-xs font-semibold uppercase tracking-wider">Date</span>
          </div>
          <div className="text-sm font-medium text-slate-900">
            {data.email_date ? new Date(data.email_date).toUTCString() : 'Unknown'}
          </div>
        </div>

        <div className="bg-white p-4 rounded-lg border border-slate-200 shadow-sm">
          <div className="flex items-center gap-2 text-slate-500 mb-1">
            <Mail className="w-4 h-4" />
            <span className="text-xs font-semibold uppercase tracking-wider">Message ID</span>
          </div>
          <div className="text-sm font-medium text-slate-900 truncate" title={data.message_id}>
            {data.message_id || 'Unknown'}
          </div>
        </div>
      </div>

      {/* Related Historical Activity (STEP 13) */}
      <div className="bg-white rounded-lg border border-slate-200 shadow-sm overflow-hidden">
        <div className="bg-slate-50 px-4 py-3 border-b border-slate-200 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <History className="w-5 h-5 text-indigo-600" />
            <h3 className="font-semibold text-slate-900">Related Historical Activity</h3>
          </div>
          {correlations && (
            <span className="text-xs font-medium text-slate-500 bg-slate-200 px-2.5 py-0.5 rounded-full">
              {correlations.previous_occurrences_count} Related Occurrence(s)
            </span>
          )}
        </div>

        <div className="p-4 space-y-4">
          {loading ? (
            <div className="text-xs text-slate-500 animate-pulse">Correlating historical investigation database...</div>
          ) : correlations && correlations.previous_occurrences_count > 0 ? (
            <>
              {/* Artifact match summary badges */}
              <div className="flex flex-wrap gap-2 text-xs font-medium">
                {correlations.shared_domains.length > 0 && (
                  <span className="bg-blue-50 text-blue-700 px-2.5 py-1 rounded-md border border-blue-200 flex items-center gap-1">
                    <Layers className="w-3.5 h-3.5 text-blue-500" />
                    {correlations.shared_domains.length} Shared Domain(s)
                  </span>
                )}
                {correlations.shared_urls.length > 0 && (
                  <span className="bg-amber-50 text-amber-800 px-2.5 py-1 rounded-md border border-amber-200 flex items-center gap-1">
                    <ExternalLink className="w-3.5 h-3.5 text-amber-600" />
                    {correlations.shared_urls.length} Shared URL(s)
                  </span>
                )}
                {correlations.shared_infrastructure.shared_ips.length > 0 && (
                  <span className="bg-cyan-50 text-cyan-800 px-2.5 py-1 rounded-md border border-cyan-200 flex items-center gap-1">
                    <ShieldCheck className="w-3.5 h-3.5 text-cyan-600" />
                    {correlations.shared_infrastructure.shared_ips.length} Shared IP(s)
                  </span>
                )}
                {correlations.shared_attachments && correlations.shared_attachments.length > 0 && (
                  <span className="bg-purple-50 text-purple-800 px-2.5 py-1 rounded-md border border-purple-200 flex items-center gap-1">
                    <Mail className="w-3.5 h-3.5 text-purple-600" />
                    {correlations.shared_attachments.length} Matching Attachment Hash(es)
                  </span>
                )}
              </div>

              {/* Related Investigations List */}
              <div className="space-y-2">
                <h4 className="text-xs font-bold text-slate-600 uppercase tracking-wider">Matched Past Investigations</h4>
                <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
                  {correlations.related_investigations.map((item, idx) => (
                    <div key={idx} className="p-3 bg-slate-50 rounded-lg border border-slate-200 text-xs flex justify-between items-start">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-indigo-700 bg-indigo-50 px-2 py-0.5 rounded border border-indigo-200">
                            {item.case_number}
                          </span>
                          <span className="font-semibold text-slate-800">{item.case_title}</span>
                        </div>
                        <p className="text-slate-600 italic">"{item.subject_summary}"</p>
                        <div className="flex flex-wrap gap-1 text-[11px] text-slate-500">
                          <span className="font-semibold text-slate-700">Matched via:</span>
                          {item.matched_artifacts.map((m, mIdx) => (
                            <span key={mIdx} className="bg-white border border-slate-200 px-1.5 py-0.5 rounded text-slate-700">
                              {m}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </>
          ) : (
            <p className="text-sm text-slate-500 italic">No prior matching investigations found in historical threat database.</p>
          )}

          {/* Potential Campaign Relationship Box (Strict Cautious Language) */}
          {correlations?.potential_campaign?.has_potential_campaign && (
            <div className="mt-4 p-4 rounded-lg bg-indigo-50/70 border border-indigo-200 text-xs space-y-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 font-bold text-indigo-900 text-sm">
                  <AlertTriangle className="w-4 h-4 text-indigo-600" />
                  <span>{correlations.potential_campaign.campaign_name}</span>
                </div>
                <span className="text-indigo-700 font-extrabold bg-indigo-100 px-2.5 py-0.5 rounded-full text-[11px]">
                  Potential Confidence: {Math.round(correlations.potential_campaign.confidence_score * 100)}%
                </span>
              </div>
              <p className="text-indigo-950 font-medium leading-relaxed">
                {correlations.potential_campaign.description}
              </p>
              <div className="text-[11px] text-indigo-800/80 bg-white/70 p-2 rounded border border-indigo-100 flex items-start gap-1.5">
                <Info className="w-3.5 h-3.5 text-indigo-500 flex-shrink-0 mt-0.5" />
                <span>{correlations.potential_campaign.cautious_language_disclaimer}</span>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Flagging Reasons */}
      <div className="bg-white rounded-lg border border-slate-200 shadow-sm overflow-hidden">
        <div className="bg-slate-50 px-4 py-3 border-b border-slate-200 flex items-center gap-2">
          <AlertTriangle className="w-5 h-5 text-slate-700" />
          <h3 className="font-semibold text-slate-900">Why this email was flagged</h3>
        </div>
        <div className="p-4">
          {data.contributing_factors && data.contributing_factors.length > 0 ? (
            <ul className="space-y-3">
              {data.contributing_factors.map((factor, idx) => (
                <li key={idx} className="flex items-start gap-3">
                  <div className="mt-0.5 flex-shrink-0 w-1.5 h-1.5 rounded-full bg-red-500"></div>
                  <span className="text-sm text-slate-700 leading-snug">{factor}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-slate-500 italic">No specific threat factors were identified for this email.</p>
          )}
        </div>
      </div>

      {/* AI Analysis Extra Signals */}
      {data.ai_analysis && data.ai_analysis.signals && data.ai_analysis.signals.length > 0 && (
        <div className="bg-white rounded-lg border border-slate-200 shadow-sm overflow-hidden">
          <div className="bg-slate-50 px-4 py-3 border-b border-slate-200">
            <h3 className="font-semibold text-slate-900">Natural Language Signals</h3>
          </div>
          <div className="p-4">
            <ul className="space-y-3">
              {data.ai_analysis.signals.map((signal, idx) => (
                <li key={idx} className="flex items-start gap-3">
                  <div className="mt-0.5 flex-shrink-0 w-1.5 h-1.5 rounded-full bg-amber-500"></div>
                  <span className="text-sm text-slate-700 leading-snug">{signal}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
      
    </div>
  );
};
