import React from 'react';
import type { EmailRecord } from '../../types';
import { Link2, AlertTriangle, ShieldCheck, Globe } from 'lucide-react';

interface Props {
  data: EmailRecord;
}

export const IOCsTab: React.FC<Props> = ({ data }) => {
  return (
    <div className="space-y-8 max-w-5xl">
      
      {/* URLs */}
      <div className="bg-white rounded-lg border border-slate-200 shadow-sm overflow-hidden">
        <div className="bg-slate-50 px-4 py-3 border-b border-slate-200 flex items-center gap-2">
          <Link2 className="w-5 h-5 text-slate-700" />
          <h3 className="font-semibold text-slate-900">URLs & Domains</h3>
        </div>
        <div className="p-0">
          {data.urls && data.urls.length > 0 ? (
            <table className="w-full text-sm text-left">
              <thead className="bg-slate-50 text-slate-500 font-semibold border-b border-slate-200">
                <tr>
                  <th className="px-4 py-3">URL</th>
                  <th className="px-4 py-3">Domain</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Intel</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {data.urls.map((url, idx) => (
                  <tr key={idx} className="hover:bg-slate-50 transition-colors">
                    <td className="px-4 py-3 font-mono text-xs break-all max-w-xs">{url.url}</td>
                    <td className="px-4 py-3">{url.domain}</td>
                    <td className="px-4 py-3">
                      {url.is_suspicious ? (
                        <span className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-semibold bg-red-50 text-red-700">
                          <AlertTriangle className="w-3 h-3" /> Suspicious
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-semibold bg-green-50 text-green-700">
                          <ShieldCheck className="w-3 h-3" /> Clean
                        </span>
                      )}
                      {url.is_typosquatted && (
                        <span className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-semibold bg-orange-50 text-orange-700 ml-2">
                          Typosquat
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-500">
                      {url.domain_intel ? 'Available' : 'None'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="p-4 text-sm text-slate-500 italic">No URLs found in the email body.</div>
          )}
        </div>
      </div>

      {/* IP Addresses */}
      <div className="bg-white rounded-lg border border-slate-200 shadow-sm overflow-hidden">
        <div className="bg-slate-50 px-4 py-3 border-b border-slate-200 flex items-center gap-2">
          <Globe className="w-5 h-5 text-slate-700" />
          <h3 className="font-semibold text-slate-900">Extracted IPs (Body & Headers)</h3>
        </div>
        <div className="p-4 flex flex-wrap gap-2">
          {data.ipv4_addresses && data.ipv4_addresses.length > 0 ? (
            data.ipv4_addresses.map((ip, idx) => (
              <span key={idx} className="px-2.5 py-1 rounded bg-slate-100 border border-slate-200 text-sm font-mono text-slate-700">
                {ip}
              </span>
            ))
          ) : (
            <span className="text-sm text-slate-500 italic">No IPv4 addresses found.</span>
          )}
        </div>
      </div>

    </div>
  );
};
