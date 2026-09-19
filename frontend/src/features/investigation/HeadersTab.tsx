import React from 'react';
import type { EmailRecord } from '../../types';
import { FileCode } from 'lucide-react';

interface Props {
  data: EmailRecord;
}

export const HeadersTab: React.FC<Props> = ({ data }) => {
  return (
    <div className="space-y-8 max-w-5xl">
      
      {/* Important Headers */}
      <div className="bg-white rounded-lg border border-slate-200 shadow-sm overflow-hidden">
        <div className="bg-slate-50 px-4 py-3 border-b border-slate-200 flex items-center gap-2">
          <FileCode className="w-5 h-5 text-slate-700" />
          <h3 className="font-semibold text-slate-900">Important Headers</h3>
        </div>
        <div className="p-0">
          <table className="w-full text-sm text-left">
            <tbody className="divide-y divide-slate-100">
              <tr className="hover:bg-slate-50">
                <th className="px-4 py-3 font-medium text-slate-700 bg-slate-50 w-48 border-r border-slate-100">Message-ID</th>
                <td className="px-4 py-3 text-slate-900 break-all">{data.message_id || 'N/A'}</td>
              </tr>
              <tr className="hover:bg-slate-50">
                <th className="px-4 py-3 font-medium text-slate-700 bg-slate-50 w-48 border-r border-slate-100">Date</th>
                <td className="px-4 py-3 text-slate-900">{data.email_date || 'N/A'}</td>
              </tr>
              <tr className="hover:bg-slate-50">
                <th className="px-4 py-3 font-medium text-slate-700 bg-slate-50 w-48 border-r border-slate-100">From</th>
                <td className="px-4 py-3 text-slate-900 break-all">{data.sender_name ? `${data.sender_name} <${data.sender_address}>` : data.sender_address || 'N/A'}</td>
              </tr>
              <tr className="hover:bg-slate-50">
                <th className="px-4 py-3 font-medium text-slate-700 bg-slate-50 w-48 border-r border-slate-100">To</th>
                <td className="px-4 py-3 text-slate-900 break-all">{data.recipient_address || 'N/A'}</td>
              </tr>
              <tr className="hover:bg-slate-50">
                <th className="px-4 py-3 font-medium text-slate-700 bg-slate-50 w-48 border-r border-slate-100">Reply-To</th>
                <td className="px-4 py-3 text-slate-900 break-all">{data.reply_to || 'N/A'}</td>
              </tr>
              <tr className="hover:bg-slate-50">
                <th className="px-4 py-3 font-medium text-slate-700 bg-slate-50 w-48 border-r border-slate-100">Return-Path</th>
                <td className="px-4 py-3 text-slate-900 break-all">{data.return_path || 'N/A'}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* Received Timeline */}
      <div className="bg-white rounded-lg border border-slate-200 shadow-sm overflow-hidden">
        <div className="bg-slate-50 px-4 py-3 border-b border-slate-200">
          <h3 className="font-semibold text-slate-900">Received Timeline (Transit Path)</h3>
        </div>
        <div className="p-6">
          {data.hops && data.hops.length > 0 ? (
            <div className="space-y-0 relative">
              {data.hops.map((hop, idx) => (
                <div key={idx} className="flex gap-4 group">
                  <div className="flex flex-col items-center">
                    <div className="w-8 h-8 rounded-full bg-slate-100 border-2 border-slate-200 flex items-center justify-center text-xs font-bold text-slate-600 z-10">
                      {hop.hop_number}
                    </div>
                    {idx < data.hops.length - 1 && (
                      <div className="w-0.5 h-full bg-slate-200 my-1 group-hover:bg-blue-300 transition-colors"></div>
                    )}
                  </div>
                  
                  <div className="pb-8 pt-1 flex-1">
                    <div className="bg-slate-50 border border-slate-200 rounded p-4">
                      <div className="flex flex-wrap gap-x-6 gap-y-2 mb-2">
                        <div>
                          <span className="text-xs font-semibold text-slate-500 uppercase tracking-wide">IP Address</span>
                          <div className="text-sm font-medium text-slate-900">{hop.ip_address}</div>
                        </div>
                        <div>
                          <span className="text-xs font-semibold text-slate-500 uppercase tracking-wide">Location</span>
                          <div className="text-sm font-medium text-slate-900">{hop.city}, {hop.country}</div>
                        </div>
                        <div>
                          <span className="text-xs font-semibold text-slate-500 uppercase tracking-wide">Timestamp</span>
                          <div className="text-sm font-medium text-slate-900">{hop.timestamp ? new Date(hop.timestamp).toUTCString() : 'N/A'}</div>
                        </div>
                        <div>
                          <span className="text-xs font-semibold text-slate-500 uppercase tracking-wide">Delay</span>
                          <div className="text-sm font-medium text-slate-900">{hop.delay_seconds}s</div>
                        </div>
                      </div>
                      
                      {hop.raw_header_reference && (
                        <div className="mt-3 pt-3 border-t border-slate-200">
                          <details className="text-xs">
                            <summary className="cursor-pointer text-blue-600 hover:text-blue-800 font-medium select-none">View Raw Header</summary>
                            <pre className="mt-2 p-2 bg-slate-800 text-slate-200 rounded overflow-x-auto font-mono whitespace-pre-wrap break-all">
                              {hop.raw_header_reference}
                            </pre>
                          </details>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-slate-500 italic">No received headers could be parsed.</p>
          )}
        </div>
      </div>
      
    </div>
  );
};
