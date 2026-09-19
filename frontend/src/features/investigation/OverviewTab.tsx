import React from 'react';
import type { EmailRecord } from '../../types';
import { Mail, Calendar, User, UserCheck, AlertTriangle } from 'lucide-react';

interface Props {
  data: EmailRecord;
}

export const OverviewTab: React.FC<Props> = ({ data }) => {
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
