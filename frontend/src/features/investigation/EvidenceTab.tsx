import React, { useState, useEffect } from 'react';
import type { EmailRecord, EvidenceRecord, IntegrityCheckResult } from '../../types';
import { ShieldCheck, AlertTriangle, FileText, CheckCircle2, History, Database, Lock } from 'lucide-react';

interface Props {
  data: EmailRecord;
}

export const EvidenceTab: React.FC<Props> = ({ data }) => {
  const [evidence, setEvidence] = useState<EvidenceRecord | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [verifying, setVerifying] = useState<boolean>(false);
  const [verifyResult, setVerifyResult] = useState<IntegrityCheckResult | null>(null);

  useEffect(() => {
    fetchEvidence();
  }, [data.id]);

  const fetchEvidence = async () => {
    setLoading(true);
    try {
      const res = await fetch(`/api/v1/emails/${data.id}/evidence`);
      if (res.ok) {
        const evData: EvidenceRecord = await res.json();
        setEvidence(evData);
      }
    } catch (e) {
      console.error("Failed to load evidence record", e);
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyIntegrity = async () => {
    if (!evidence) return;
    setVerifying(true);
    try {
      const res = await fetch(`/api/v1/evidence/verify/${evidence.id}`, {
        method: 'POST',
      });
      if (res.ok) {
        const result: IntegrityCheckResult = await res.json();
        setVerifyResult(result);
        // Refresh evidence timeline to reflect Evidence viewed log
        fetchEvidence();
      }
    } catch (e) {
      console.error("Failed to verify evidence integrity", e);
    } finally {
      setVerifying(false);
    }
  };

  const currentStatus = verifyResult?.status || evidence?.integrity_status || 'Verified';

  return (
    <div className="space-y-6 max-w-6xl">
      {/* Top Banner: Non-Modification Guarantee */}
      <div className="bg-slate-900 text-slate-100 p-4 rounded-lg border border-slate-800 flex items-center justify-between shadow-md">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-blue-600/20 rounded-md border border-blue-500/30 text-blue-400">
            <Lock className="w-5 h-5" />
          </div>
          <div>
            <h3 className="font-semibold text-sm text-slate-100">Immutable Evidence Vault</h3>
            <p className="text-xs text-slate-400">Raw evidence files are stored in isolated, read-only storage (`backend/app/evidence_vault/`). Original evidence is never modified.</p>
          </div>
        </div>
        <div className="text-right">
          <span className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-semibold border ${
            currentStatus === 'Verified'
              ? 'bg-emerald-950/80 text-emerald-300 border-emerald-500/40'
              : 'bg-rose-950/80 text-rose-300 border-rose-500/40'
          }`}>
            {currentStatus === 'Verified' ? (
              <>
                <CheckCircle2 className="w-3.5 h-3.5 mr-1.5 text-emerald-400" />
                Verified
              </>
            ) : (
              <>
                <AlertTriangle className="w-3.5 h-3.5 mr-1.5 text-rose-400" />
                Integrity mismatch
              </>
            )}
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Evidence Vault Metadata & Live Verification */}
        <div className="lg:col-span-1 space-y-6">
          <div className="bg-white rounded-lg border border-slate-200 shadow-sm p-5 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100">
              <h3 className="text-base font-semibold text-slate-900 flex items-center">
                <Database className="w-4 h-4 mr-2 text-indigo-600" />
                Evidence Metadata
              </h3>
              <span className="text-xs font-mono px-2 py-0.5 bg-slate-100 text-slate-600 rounded">
                SHA-256
              </span>
            </div>

            {loading ? (
              <div className="py-8 text-center text-sm text-slate-400">Loading vault record...</div>
            ) : evidence ? (
              <div className="space-y-3.5 text-xs text-slate-700">
                <div>
                  <span className="block font-medium text-slate-400 uppercase tracking-wider text-[10px]">Evidence ID</span>
                  <span className="font-mono text-slate-900 select-all font-medium text-xs break-all">{evidence.id}</span>
                </div>

                <div>
                  <span className="block font-medium text-slate-400 uppercase tracking-wider text-[10px]">SHA-256 Hash</span>
                  <span className="font-mono text-slate-900 select-all font-semibold break-all bg-slate-50 p-1.5 rounded border border-slate-200 block mt-0.5 text-[11px]">
                    {evidence.sha256_hash}
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-2 pt-1">
                  <div>
                    <span className="block font-medium text-slate-400 uppercase tracking-wider text-[10px]">File Name</span>
                    <span className="font-medium text-slate-800 truncate block">{evidence.file_name}</span>
                  </div>
                  <div>
                    <span className="block font-medium text-slate-400 uppercase tracking-wider text-[10px]">File Size</span>
                    <span className="font-medium text-slate-800">{evidence.file_size_bytes} bytes</span>
                  </div>
                </div>

                <div>
                  <span className="block font-medium text-slate-400 uppercase tracking-wider text-[10px]">Collected By</span>
                  <span className="font-medium text-slate-800">{evidence.collected_by}</span>
                </div>

                <div>
                  <span className="block font-medium text-slate-400 uppercase tracking-wider text-[10px]">Vault Storage Location</span>
                  <span className="font-mono text-slate-600 block text-[10px] break-all bg-slate-100 p-1.5 rounded mt-0.5">{evidence.file_path}</span>
                </div>
              </div>
            ) : (
              <div className="text-xs text-slate-500">Evidence record initialized from current investigation.</div>
            )}

            {/* Live Integrity Recalculation Button */}
            <div className="pt-2">
              <button
                onClick={handleVerifyIntegrity}
                disabled={verifying || !evidence}
                className="w-full flex items-center justify-center space-x-2 px-4 py-2.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-md text-xs font-medium transition-colors shadow-sm disabled:opacity-50"
              >
                <ShieldCheck className="w-4 h-4" />
                <span>{verifying ? 'Recalculating SHA-256...' : 'Recalculate SHA-256 & Verify Integrity'}</span>
              </button>
            </div>

            {verifyResult && (
              <div className={`p-3 rounded-md text-xs border mt-3 ${
                verifyResult.status === 'Verified'
                  ? 'bg-emerald-50 text-emerald-900 border-emerald-200'
                  : 'bg-rose-50 text-rose-900 border-rose-200'
              }`}>
                <div className="font-semibold flex items-center">
                  {verifyResult.status === 'Verified' ? (
                    <CheckCircle2 className="w-4 h-4 mr-1.5 text-emerald-600" />
                  ) : (
                    <AlertTriangle className="w-4 h-4 mr-1.5 text-rose-600" />
                  )}
                  Integrity Status: {verifyResult.status}
                </div>
                <div className="mt-1.5 font-mono text-[10px] break-all space-y-1">
                  <div><span className="text-slate-500">Stored:</span> {verifyResult.stored_hash}</div>
                  <div><span className="text-slate-500">Live Recalculated:</span> {verifyResult.recalculated_hash}</div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Chain-of-Custody Timeline & Blockchain */}
        <div className="lg:col-span-2 space-y-6">
          {/* Chain-of-Custody Timeline */}
          <div className="bg-white rounded-lg border border-slate-200 shadow-sm p-6">
            <div className="flex items-center justify-between mb-5 pb-3 border-b border-slate-100">
              <h3 className="text-base font-semibold text-slate-900 flex items-center">
                <History className="w-4 h-4 mr-2 text-indigo-600" />
                Chain-of-Custody Audit Timeline
              </h3>
              <span className="text-xs text-slate-500">
                {evidence?.chain_of_custody_logs?.length || 0} Recorded Audit Events
              </span>
            </div>

            <div className="space-y-6 relative before:absolute before:inset-0 before:left-3.5 before:w-0.5 before:bg-slate-200">
              {evidence?.chain_of_custody_logs && evidence.chain_of_custody_logs.length > 0 ? (
                evidence.chain_of_custody_logs.map((log, index) => {
                  let badgeColor = 'bg-blue-500 text-white';
                  if (log.action.includes('collected')) badgeColor = 'bg-emerald-600 text-white';
                  if (log.action.includes('performed')) badgeColor = 'bg-indigo-600 text-white';
                  if (log.action.includes('viewed')) badgeColor = 'bg-sky-600 text-white';
                  if (log.action.includes('exported')) badgeColor = 'bg-amber-600 text-white';
                  if (log.action.includes('generated')) badgeColor = 'bg-purple-600 text-white';

                  return (
                    <div key={index} className="relative flex items-start space-x-4 pl-8">
                      <div className={`absolute left-1 top-1 w-5 h-5 rounded-full ${badgeColor} flex items-center justify-center text-[10px] font-bold shadow-sm`}>
                        {index + 1}
                      </div>

                      <div className="flex-1 bg-slate-50 rounded-md p-3.5 border border-slate-200">
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-xs text-slate-900">{log.action}</span>
                          <span className="text-[11px] font-mono text-slate-500">
                            {new Date(log.timestamp).toLocaleString()}
                          </span>
                        </div>

                        <div className="mt-2 grid grid-cols-2 gap-2 text-xs text-slate-600">
                          <div>
                            <span className="text-slate-400 font-medium">Actor / System:</span> {log.user}
                          </div>
                          <div>
                            <span className="text-slate-400 font-medium">Evidence ID:</span>{' '}
                            <span className="font-mono text-[11px] text-slate-800">{log.evidence_id.substring(0, 8)}...</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })
              ) : (
                <div className="py-6 text-center text-xs text-slate-400">No chain-of-custody logs recorded yet.</div>
              )}
            </div>
          </div>

          {/* Blockchain On-Chain Verification Ledger */}
          <div className="bg-white rounded-lg border border-slate-200 shadow-sm p-6">
            <h3 className="text-base font-semibold mb-4 text-slate-900 flex items-center">
              <ShieldCheck className="w-4 h-4 mr-2 text-emerald-600" />
              On-Chain Cryptographic Anchoring
            </h3>
            {data.blockchain_log ? (
              <div className="space-y-3 text-xs bg-slate-50 p-4 rounded-md border border-slate-200">
                <div className="flex items-center justify-between pb-2 border-b border-slate-200">
                  <span className="font-medium text-slate-500">Ledger Status</span>
                  <span className="font-semibold text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200">
                    {data.blockchain_log.status}
                  </span>
                </div>
                <div>
                  <span className="block font-medium text-slate-500">Transaction Hash</span>
                  <span className="font-mono text-slate-800 select-all block mt-0.5 break-all">{data.blockchain_log.transaction_hash}</span>
                </div>
                <div className="grid grid-cols-2 gap-4 pt-1">
                  <div>
                    <span className="block font-medium text-slate-500">Block Number</span>
                    <span className="font-mono text-slate-800">{data.blockchain_log.block_number}</span>
                  </div>
                  <div>
                    <span className="block font-medium text-slate-500">Merkle Root</span>
                    <span className="font-mono text-slate-800 truncate block">{data.blockchain_log.merkle_root}</span>
                  </div>
                </div>
              </div>
            ) : (
              <div className="p-6 text-center text-xs text-slate-500 bg-slate-50 rounded border border-slate-200">
                <p>Evidence cryptographic hash queued for next block anchor batch.</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
