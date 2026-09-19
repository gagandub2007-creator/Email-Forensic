import React from 'react';
import type { EmailRecord } from '../../types';

interface Props {
  data: EmailRecord;
}

export const EvidenceTab: React.FC<Props> = ({ data }) => {
  return (
    <div className="space-y-6 max-w-5xl">
      <div className="bg-white rounded-lg border border-slate-200 shadow-sm p-6">
        <h2 className="text-xl font-medium mb-4 text-slate-900">Blockchain Evidence Log</h2>
        {data.blockchain_log ? (
          <div className="space-y-3 text-sm">
            <div>
              <span className="block text-xs font-semibold text-slate-500 uppercase tracking-wide">Status</span>
              <span className="font-medium text-green-700 bg-green-50 px-2 py-0.5 rounded border border-green-200">{data.blockchain_log.status}</span>
            </div>
            <div>
              <span className="block text-xs font-semibold text-slate-500 uppercase tracking-wide">Transaction Hash</span>
              <span className="font-mono text-slate-700">{data.blockchain_log.transaction_hash}</span>
            </div>
            <div>
              <span className="block text-xs font-semibold text-slate-500 uppercase tracking-wide">Block Number</span>
              <span className="font-mono text-slate-700">{data.blockchain_log.block_number}</span>
            </div>
          </div>
        ) : (
          <div className="p-8 text-center text-slate-500 bg-slate-50 rounded border border-slate-200">
            <p>Blockchain integration placeholder. Future integration will anchor forensic evidence on-chain.</p>
          </div>
        )}
      </div>

      <div className="bg-white rounded-lg border border-slate-200 shadow-sm p-6">
        <h2 className="text-xl font-medium mb-4 text-slate-900">Attachments</h2>
        {data.attachments && data.attachments.length > 0 ? (
          <div className="space-y-2">
            {data.attachments.map((att, idx) => (
              <div key={idx} className="p-3 border border-slate-200 rounded-md bg-slate-50">
                <div className="font-medium text-slate-900">{att.filename}</div>
                <div className="text-xs text-slate-500 mt-1 font-mono">SHA256: {att.sha256_hash}</div>
                <div className="text-xs text-slate-500 mt-1">Size: {att.file_size_bytes} bytes</div>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-sm text-slate-500 italic">No attachments found in this email.</p>
        )}
      </div>
    </div>
  );
};
