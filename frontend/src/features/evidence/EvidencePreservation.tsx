import React, { useState, useEffect, useCallback } from 'react';
import {
  Shield, ShieldCheck, ShieldAlert, Clock, User, FileText,
  Hash, HardDrive, Eye, Download, Activity, CheckCircle2,
  XCircle, RefreshCw, ChevronRight, Fingerprint, Lock
} from 'lucide-react';
import type { EvidenceRecord, EvidenceVerifyResult, CustodyEvent } from '../../types';

const API_BASE = 'http://localhost:8000/api/v1';

/* ------------------------------------------------------------------ */
/*  Action icon/colour helper                                          */
/* ------------------------------------------------------------------ */
const ACTION_STYLE: Record<string, { icon: React.ReactNode; color: string; bg: string }> = {
  'Evidence collected':  { icon: <Download className="w-4 h-4" />,  color: 'text-emerald-600',  bg: 'bg-emerald-100' },
  'Analysis performed':  { icon: <Activity className="w-4 h-4" />,  color: 'text-blue-600',     bg: 'bg-blue-100'    },
  'Evidence viewed':     { icon: <Eye className="w-4 h-4" />,       color: 'text-violet-600',   bg: 'bg-violet-100'  },
  'Evidence exported':   { icon: <Download className="w-4 h-4" />,  color: 'text-amber-600',    bg: 'bg-amber-100'   },
  'Report generated':    { icon: <FileText className="w-4 h-4" />,  color: 'text-rose-600',     bg: 'bg-rose-100'    },
};

/* ------------------------------------------------------------------ */
/*  Main component                                                     */
/* ------------------------------------------------------------------ */
export const EvidencePreservation: React.FC = () => {
  const [records, setRecords]       = useState<EvidenceRecord[]>([]);
  const [selected, setSelected]     = useState<EvidenceRecord | null>(null);
  const [timeline, setTimeline]     = useState<CustodyEvent[]>([]);
  const [verifyResult, setVerify]   = useState<EvidenceVerifyResult | null>(null);
  const [loading, setLoading]       = useState(false);
  const [verifying, setVerifying]   = useState(false);

  /* ---- Fetch all evidence records ---- */
  const fetchRecords = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/evidence`);
      if (res.ok) setRecords(await res.json());
    } catch { /* network error */ }
    setLoading(false);
  }, []);

  useEffect(() => { fetchRecords(); }, [fetchRecords]);

  /* ---- Fetch custody timeline for a record ---- */
  const fetchTimeline = async (evidenceId: string) => {
    const res = await fetch(`${API_BASE}/evidence/${evidenceId}/custody`);
    if (res.ok) setTimeline(await res.json());
  };

  /* ---- Select a record ---- */
  const handleSelect = async (rec: EvidenceRecord) => {
    setSelected(rec);
    setVerify(null);
    await fetchTimeline(rec.id);
  };

  /* ---- Verify integrity ---- */
  const handleVerify = async () => {
    if (!selected) return;
    setVerifying(true);
    try {
      const res = await fetch(`${API_BASE}/evidence/${selected.id}/verify`);
      if (res.ok) {
        const data: EvidenceVerifyResult = await res.json();
        setVerify(data);
        // Refresh record to reflect updated integrity_status
        await fetchRecords();
        await fetchTimeline(selected.id);
      }
    } catch { /* network error */ }
    setVerifying(false);
  };

  /* ---- Format helpers ---- */
  const fmtDate = (iso: string) =>
    new Date(iso).toLocaleString('en-IN', {
      day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    });

  const fmtBytes = (b: number) => {
    if (b < 1024) return `${b} B`;
    if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
    return `${(b / (1024 * 1024)).toFixed(2)} MB`;
  };

  /* ---------------------------------------------------------------- */
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center shadow-lg shadow-indigo-200">
            <Fingerprint className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-slate-800 tracking-tight">Evidence Preservation</h1>
            <p className="text-xs text-slate-500">SHA-256 integrity verification &amp; chain-of-custody timeline</p>
          </div>
        </div>
        <button
          onClick={fetchRecords}
          className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-indigo-700 bg-indigo-50 rounded-lg hover:bg-indigo-100 transition-colors"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* ---- Left panel: evidence list ---- */}
        <div className="lg:col-span-1 bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
          <div className="px-4 py-3 border-b border-slate-100 bg-slate-50/60">
            <h2 className="text-sm font-semibold text-slate-700 flex items-center gap-2">
              <Lock className="w-4 h-4 text-indigo-500" />
              Evidence Registry
              <span className="ml-auto text-xs font-normal bg-indigo-100 text-indigo-700 px-2 py-0.5 rounded-full">
                {records.length}
              </span>
            </h2>
          </div>

          <div className="divide-y divide-slate-100 max-h-[calc(100vh-260px)] overflow-y-auto">
            {records.length === 0 && (
              <div className="p-8 text-center text-slate-400 text-sm">
                No evidence records yet. Analyze an email to get started.
              </div>
            )}
            {records.map(rec => (
              <button
                key={rec.id}
                onClick={() => handleSelect(rec)}
                className={`w-full text-left px-4 py-3 hover:bg-slate-50 transition-colors flex items-center gap-3 ${
                  selected?.id === rec.id ? 'bg-indigo-50 border-l-2 border-indigo-500' : ''
                }`}
              >
                {rec.integrity_status === 'Verified' ? (
                  <ShieldCheck className="w-5 h-5 text-emerald-500 flex-shrink-0" />
                ) : (
                  <ShieldAlert className="w-5 h-5 text-red-500 flex-shrink-0" />
                )}
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium text-slate-800 truncate">{rec.filename}</p>
                  <p className="text-xs text-slate-400 font-mono truncate">{rec.sha256_hash.slice(0, 16)}…</p>
                </div>
                <ChevronRight className="w-4 h-4 text-slate-300 flex-shrink-0" />
              </button>
            ))}
          </div>
        </div>

        {/* ---- Right panel: details + timeline ---- */}
        <div className="lg:col-span-2 space-y-6">
          {!selected ? (
            <div className="bg-white rounded-xl border border-slate-200 p-12 text-center">
              <Shield className="w-12 h-12 text-slate-300 mx-auto mb-4" />
              <p className="text-slate-400 text-sm">Select an evidence record to view details and chain-of-custody.</p>
            </div>
          ) : (
            <>
              {/* Metadata card */}
              <div className="bg-white rounded-xl border border-slate-200 shadow-sm">
                <div className="px-5 py-4 border-b border-slate-100 flex items-center justify-between">
                  <h2 className="text-sm font-semibold text-slate-700 flex items-center gap-2">
                    <FileText className="w-4 h-4 text-indigo-500" />
                    Evidence Metadata
                  </h2>
                  <span className={`text-xs font-semibold px-2.5 py-1 rounded-full ${
                    selected.integrity_status === 'Verified'
                      ? 'bg-emerald-100 text-emerald-700'
                      : 'bg-red-100 text-red-700'
                  }`}>
                    {selected.integrity_status}
                  </span>
                </div>
                <div className="p-5 grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm">
                  <MetaRow icon={<Fingerprint className="w-4 h-4" />} label="Evidence ID"  value={selected.id} mono />
                  <MetaRow icon={<Hash className="w-4 h-4" />}        label="SHA-256"       value={selected.sha256_hash} mono />
                  <MetaRow icon={<FileText className="w-4 h-4" />}    label="Filename"      value={selected.filename} />
                  <MetaRow icon={<HardDrive className="w-4 h-4" />}   label="File Size"     value={fmtBytes(selected.file_size_bytes)} />
                  <MetaRow icon={<Clock className="w-4 h-4" />}       label="Collected At"  value={fmtDate(selected.created_at)} />
                  <MetaRow icon={<User className="w-4 h-4" />}        label="Collected By"  value={selected.collected_by} />
                  <MetaRow icon={<FileText className="w-4 h-4" />}    label="Case ID"       value={selected.case_id || '—'} mono />
                  <MetaRow icon={<FileText className="w-4 h-4" />}    label="Investigation" value={selected.investigation_id || '—'} mono />
                </div>
              </div>

              {/* Verify integrity */}
              <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5">
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-sm font-semibold text-slate-700 flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4 text-indigo-500" />
                    Integrity Verification
                  </h2>
                  <button
                    onClick={handleVerify}
                    disabled={verifying}
                    className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-gradient-to-r from-indigo-500 to-purple-600 rounded-lg hover:from-indigo-600 hover:to-purple-700 transition-all disabled:opacity-50 shadow-sm"
                  >
                    <RefreshCw className={`w-4 h-4 ${verifying ? 'animate-spin' : ''}`} />
                    Verify Now
                  </button>
                </div>

                {verifyResult && (
                  <div className={`rounded-lg p-4 border ${
                    verifyResult.match
                      ? 'bg-emerald-50 border-emerald-200'
                      : 'bg-red-50 border-red-200'
                  }`}>
                    <div className="flex items-center gap-3 mb-3">
                      {verifyResult.match ? (
                        <CheckCircle2 className="w-6 h-6 text-emerald-600" />
                      ) : (
                        <XCircle className="w-6 h-6 text-red-600" />
                      )}
                      <span className={`text-lg font-bold ${verifyResult.match ? 'text-emerald-700' : 'text-red-700'}`}>
                        {verifyResult.status}
                      </span>
                    </div>
                    <div className="space-y-1 text-xs font-mono text-slate-600">
                      <p><span className="text-slate-400">Stored:       </span>{verifyResult.stored_hash}</p>
                      <p><span className="text-slate-400">Recalculated: </span>{verifyResult.recalculated_hash}</p>
                      <p><span className="text-slate-400">Verified at:  </span>{fmtDate(verifyResult.verified_at)}</p>
                    </div>
                  </div>
                )}
              </div>

              {/* Chain-of-custody timeline */}
              <div className="bg-white rounded-xl border border-slate-200 shadow-sm">
                <div className="px-5 py-4 border-b border-slate-100">
                  <h2 className="text-sm font-semibold text-slate-700 flex items-center gap-2">
                    <Clock className="w-4 h-4 text-indigo-500" />
                    Chain-of-Custody Timeline
                    <span className="ml-auto text-xs font-normal bg-slate-100 text-slate-600 px-2 py-0.5 rounded-full">
                      {timeline.length} events
                    </span>
                  </h2>
                </div>
                <div className="p-5">
                  {timeline.length === 0 ? (
                    <p className="text-sm text-slate-400 text-center py-6">No custody events recorded.</p>
                  ) : (
                    <ol className="relative border-l-2 border-slate-200 ml-3 space-y-6">
                      {timeline.map((evt) => {
                        const style = ACTION_STYLE[evt.action] || ACTION_STYLE['Evidence collected'];
                        return (
                          <li key={evt.id} className="ml-6">
                            <span className={`absolute -left-[13px] flex items-center justify-center w-6 h-6 rounded-full ring-4 ring-white ${style.bg}`}>
                              <span className={style.color}>{style.icon}</span>
                            </span>
                            <div className="flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-4">
                              <span className={`text-sm font-semibold ${style.color}`}>{evt.action}</span>
                              <span className="text-xs text-slate-400">{fmtDate(evt.timestamp)}</span>
                            </div>
                            <p className="text-xs text-slate-500 mt-0.5 flex items-center gap-1">
                              <User className="w-3 h-3" /> {evt.user}
                            </p>
                          </li>
                        );
                      })}
                    </ol>
                  )}
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};

/* Small helper for metadata rows */
const MetaRow: React.FC<{
  icon: React.ReactNode;
  label: string;
  value: string;
  mono?: boolean;
}> = ({ icon, label, value, mono }) => (
  <div className="flex items-start gap-2">
    <span className="text-slate-400 mt-0.5">{icon}</span>
    <div className="min-w-0">
      <p className="text-xs text-slate-400 font-medium">{label}</p>
      <p className={`text-slate-700 truncate ${mono ? 'font-mono text-xs' : ''}`} title={value}>
        {value}
      </p>
    </div>
  </div>
);

export default EvidencePreservation;
