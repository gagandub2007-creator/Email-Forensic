import React, { useState, useEffect } from 'react';
import {
  Shield, ShieldCheck, ShieldAlert, Hash, Clock, User,
  FileText, HardDrive, CheckCircle2, XCircle, RefreshCw,
  Link2, Eye, Download, Activity, Fingerprint, Lock, Blocks
} from 'lucide-react';
import type { EmailRecord, EvidenceRecord, EvidenceVerifyResult, LedgerVerifyResult, CustodyEvent } from '../../types';

const API_BASE = 'http://localhost:8000/api/v1';

interface Props {
  data: EmailRecord;
}

const ACTION_STYLE: Record<string, { icon: React.ReactNode; color: string; bg: string }> = {
  'Evidence collected':  { icon: <Download className="w-3.5 h-3.5" />,  color: 'text-emerald-600',  bg: 'bg-emerald-100' },
  'Analysis performed':  { icon: <Activity className="w-3.5 h-3.5" />,  color: 'text-blue-600',     bg: 'bg-blue-100'    },
  'Evidence viewed':     { icon: <Eye className="w-3.5 h-3.5" />,       color: 'text-violet-600',   bg: 'bg-violet-100'  },
  'Evidence exported':   { icon: <Download className="w-3.5 h-3.5" />,  color: 'text-amber-600',    bg: 'bg-amber-100'   },
  'Report generated':    { icon: <FileText className="w-3.5 h-3.5" />,  color: 'text-rose-600',     bg: 'bg-rose-100'    },
};

export const EvidenceTab: React.FC<Props> = ({ data }) => {
  const [evidence, setEvidence]         = useState<EvidenceRecord | null>(null);
  const [hashVerify, setHashVerify]     = useState<EvidenceVerifyResult | null>(null);
  const [ledgerVerify, setLedgerVerify] = useState<LedgerVerifyResult | null>(null);
  const [timeline, setTimeline]         = useState<CustodyEvent[]>([]);
  const [verifying, setVerifying]       = useState(false);
  const [ledgerVerifying, setLedVerifying] = useState(false);

  useEffect(() => {
    const load = async () => {
      try {
        const res = await fetch(`${API_BASE}/evidence/${data.id}`);
        if (res.ok) {
          const ev: EvidenceRecord = await res.json();
          setEvidence(ev);
          setTimeline(ev.custody_events || []);
        }
      } catch { /* network error */ }
    };
    load();
  }, [data.id]);

  const handleVerifyHash = async () => {
    if (!evidence) return;
    setVerifying(true);
    try {
      const res = await fetch(`${API_BASE}/evidence/${evidence.id}/verify`);
      if (res.ok) setHashVerify(await res.json());
    } catch { /* */ }
    setVerifying(false);
  };

  const handleVerifyLedger = async () => {
    if (!evidence) return;
    setLedVerifying(true);
    try {
      const res = await fetch(`${API_BASE}/ledger/${evidence.id}/verify`);
      if (res.ok) setLedgerVerify(await res.json());
    } catch { /* */ }
    setLedVerifying(false);
  };

  const fmtDate = (iso: string) =>
    new Date(iso).toLocaleString('en-IN', {
      day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    });

  if (!evidence) {
    return (
      <div className="bg-white rounded-lg border border-slate-200 p-8 text-center text-slate-400">
        <Shield className="w-10 h-10 mx-auto mb-3 opacity-40" />
        <p className="text-sm">Loading evidence data…</p>
      </div>
    );
  }

  const le = evidence.ledger_entry;

  return (
    <div className="space-y-6 max-w-5xl">
      {/* Disclaimer */}
      <div className="bg-indigo-50 border border-indigo-200 rounded-lg px-4 py-3 text-xs text-indigo-700 flex items-start gap-2">
        <Lock className="w-4 h-4 mt-0.5 flex-shrink-0" />
        <span>
          <strong>Blockchain is used here as a tamper-evident record for evidence integrity, not as storage for the original email.</strong>{' '}
          Only the SHA-256 hash, evidence ID, timestamp, and case reference are registered on the ledger. No raw email content, attachments, or personal data is stored.
        </span>
      </div>

      {/* Row 1: Evidence metadata + integrity verification */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Evidence Metadata */}
        <div className="bg-white rounded-lg border border-slate-200 shadow-sm">
          <div className="px-5 py-3 border-b border-slate-100 flex items-center gap-2">
            <Fingerprint className="w-4 h-4 text-indigo-500" />
            <h3 className="text-sm font-semibold text-slate-700">Evidence Metadata</h3>
            <span className={`ml-auto text-xs font-semibold px-2 py-0.5 rounded-full ${
              evidence.integrity_status === 'Verified'
                ? 'bg-emerald-100 text-emerald-700'
                : 'bg-red-100 text-red-700'
            }`}>{evidence.integrity_status}</span>
          </div>
          <div className="p-4 space-y-3 text-sm">
            <Row icon={<Fingerprint className="w-4 h-4" />} label="Evidence ID" value={evidence.id} mono />
            <Row icon={<Hash className="w-4 h-4" />} label="SHA-256" value={evidence.sha256_hash} mono />
            <Row icon={<FileText className="w-4 h-4" />} label="Filename" value={evidence.filename} />
            <Row icon={<HardDrive className="w-4 h-4" />} label="File Size" value={`${evidence.file_size_bytes} bytes`} />
            <Row icon={<Clock className="w-4 h-4" />} label="Registered" value={fmtDate(evidence.created_at)} />
            <Row icon={<User className="w-4 h-4" />} label="Collected By" value={evidence.collected_by} />
          </div>
        </div>

        {/* Evidence Integrity Verification */}
        <div className="bg-white rounded-lg border border-slate-200 shadow-sm">
          <div className="px-5 py-3 border-b border-slate-100 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-indigo-500" />
              <h3 className="text-sm font-semibold text-slate-700">Evidence Integrity</h3>
            </div>
            <button onClick={handleVerifyHash} disabled={verifying}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-white bg-gradient-to-r from-indigo-500 to-purple-600 rounded-md hover:from-indigo-600 hover:to-purple-700 disabled:opacity-50">
              <RefreshCw className={`w-3.5 h-3.5 ${verifying ? 'animate-spin' : ''}`} /> Verify Hash
            </button>
          </div>
          <div className="p-4">
            {hashVerify ? (
              <div className={`rounded-lg p-4 border ${hashVerify.match
                ? 'bg-emerald-50 border-emerald-200' : 'bg-red-50 border-red-200'}`}>
                <div className="flex items-center gap-2 mb-2">
                  {hashVerify.match
                    ? <CheckCircle2 className="w-5 h-5 text-emerald-600" />
                    : <XCircle className="w-5 h-5 text-red-600" />}
                  <span className={`text-sm font-bold ${hashVerify.match ? 'text-emerald-700' : 'text-red-700'}`}>
                    ✓ Hash {hashVerify.status.toLowerCase()}
                  </span>
                </div>
                <div className="text-xs font-mono text-slate-600 space-y-0.5">
                  <p><span className="text-slate-400">Stored:       </span>{hashVerify.stored_hash}</p>
                  <p><span className="text-slate-400">Recalculated: </span>{hashVerify.recalculated_hash}</p>
                </div>
              </div>
            ) : (
              <div className="text-center py-6 text-slate-400 text-sm">
                Click "Verify Hash" to recalculate SHA-256 and compare with stored hash.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Row 2: Ledger Record */}
      <div className="bg-white rounded-lg border border-slate-200 shadow-sm">
        <div className="px-5 py-3 border-b border-slate-100 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Blocks className="w-4 h-4 text-indigo-500" />
            <h3 className="text-sm font-semibold text-slate-700">Ledger Record</h3>
            {le && (
              <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${
                le.ledger_status === 'CONFIRMED' ? 'bg-emerald-100 text-emerald-700' : 'bg-amber-100 text-amber-700'
              }`}>{le.ledger_status}</span>
            )}
          </div>
          {le && (
            <button onClick={handleVerifyLedger} disabled={ledgerVerifying}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-white bg-gradient-to-r from-emerald-500 to-teal-600 rounded-md hover:from-emerald-600 hover:to-teal-700 disabled:opacity-50">
              <RefreshCw className={`w-3.5 h-3.5 ${ledgerVerifying ? 'animate-spin' : ''}`} /> Verify Ledger
            </button>
          )}
        </div>
        <div className="p-4">
          {le ? (
            <div className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
                <Row icon={<Link2 className="w-4 h-4" />} label="Transaction ID" value={le.ledger_tx_id} mono />
                <Row icon={<Hash className="w-4 h-4" />} label="Evidence Hash" value={le.evidence_hash} mono />
                <Row icon={<Blocks className="w-4 h-4" />} label="Block Number" value={String(le.block_number)} />
                <Row icon={<Clock className="w-4 h-4" />} label="Registered At" value={fmtDate(le.registered_at)} />
                <Row icon={<FileText className="w-4 h-4" />} label="Case Reference" value={le.case_reference || '—'} mono />
                <Row icon={<Lock className="w-4 h-4" />} label="Contract" value={le.contract_address || '—'} mono />
                <Row icon={<Hash className="w-4 h-4" />} label="Merkle Root" value={le.merkle_root || '—'} mono />
                <Row icon={<ShieldCheck className="w-4 h-4" />} label="Verification" value={le.verification_status} />
              </div>

              {ledgerVerify && (
                <div className={`rounded-lg p-4 border ${ledgerVerify.verified
                  ? 'bg-emerald-50 border-emerald-200' : 'bg-red-50 border-red-200'}`}>
                  <div className="flex items-center gap-2">
                    {ledgerVerify.verified
                      ? <CheckCircle2 className="w-5 h-5 text-emerald-600" />
                      : <XCircle className="w-5 h-5 text-red-600" />}
                    <span className={`text-sm font-bold ${ledgerVerify.verified ? 'text-emerald-700' : 'text-red-700'}`}>
                      Ledger Record {ledgerVerify.verified ? 'Verified' : 'Mismatch'}
                    </span>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="text-center py-6 text-slate-400 text-sm">
              No ledger entry found for this evidence.
            </div>
          )}
        </div>
      </div>

      {/* Row 3: Chain of Custody + Attachments */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Chain of Custody */}
        <div className="bg-white rounded-lg border border-slate-200 shadow-sm">
          <div className="px-5 py-3 border-b border-slate-100 flex items-center gap-2">
            <Clock className="w-4 h-4 text-indigo-500" />
            <h3 className="text-sm font-semibold text-slate-700">Chain of Custody</h3>
            <span className="ml-auto text-xs bg-slate-100 text-slate-600 px-2 py-0.5 rounded-full">{timeline.length} events</span>
          </div>
          <div className="p-4">
            {timeline.length === 0 ? (
              <p className="text-sm text-slate-400 text-center py-4">No custody events.</p>
            ) : (
              <ol className="relative border-l-2 border-slate-200 ml-3 space-y-4">
                {timeline.map((evt) => {
                  const style = ACTION_STYLE[evt.action] || ACTION_STYLE['Evidence collected'];
                  return (
                    <li key={evt.id} className="ml-5">
                      <span className={`absolute -left-[11px] flex items-center justify-center w-5 h-5 rounded-full ring-2 ring-white ${style.bg}`}>
                        <span className={style.color}>{style.icon}</span>
                      </span>
                      <p className={`text-xs font-semibold ${style.color}`}>{evt.action}</p>
                      <p className="text-[10px] text-slate-400">{fmtDate(evt.timestamp)} · {evt.user}</p>
                    </li>
                  );
                })}
              </ol>
            )}
          </div>
        </div>

        {/* Attachments */}
        <div className="bg-white rounded-lg border border-slate-200 shadow-sm">
          <div className="px-5 py-3 border-b border-slate-100 flex items-center gap-2">
            <FileText className="w-4 h-4 text-indigo-500" />
            <h3 className="text-sm font-semibold text-slate-700">Attachments</h3>
          </div>
          <div className="p-4">
            {data.attachments && data.attachments.length > 0 ? (
              <div className="space-y-2">
                {data.attachments.map((att, idx) => (
                  <div key={idx} className="p-3 border border-slate-200 rounded-md bg-slate-50">
                    <div className="font-medium text-slate-900 text-sm">{att.filename}</div>
                    <div className="text-[10px] text-slate-500 mt-1 font-mono">SHA256: {att.sha256_hash}</div>
                    <div className="text-[10px] text-slate-500 mt-0.5">{att.file_size_bytes} bytes · {att.mime_type || 'unknown'}</div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-slate-400 italic text-center py-4">No attachments found.</p>
            )}
          </div>
        </div>
      </div>

      {/* Blockchain Legacy Log (existing data from older analysis) */}
      {data.blockchain_log && (
        <div className="bg-white rounded-lg border border-slate-200 shadow-sm">
          <div className="px-5 py-3 border-b border-slate-100 flex items-center gap-2">
            <Blocks className="w-4 h-4 text-slate-400" />
            <h3 className="text-sm font-semibold text-slate-500">Legacy Blockchain Log</h3>
            <span className="text-xs font-semibold bg-green-100 text-green-700 px-2 py-0.5 rounded-full">{data.blockchain_log.status}</span>
          </div>
          <div className="p-4 grid grid-cols-1 sm:grid-cols-3 gap-3 text-sm">
            <Row icon={<Link2 className="w-4 h-4" />} label="Tx Hash" value={data.blockchain_log.transaction_hash} mono />
            <Row icon={<Blocks className="w-4 h-4" />} label="Block" value={String(data.blockchain_log.block_number)} />
            <Row icon={<Clock className="w-4 h-4" />} label="Anchored" value={fmtDate(data.blockchain_log.anchored_at)} />
          </div>
        </div>
      )}
    </div>
  );
};

const Row: React.FC<{ icon: React.ReactNode; label: string; value: string; mono?: boolean }> = ({ icon, label, value, mono }) => (
  <div className="flex items-start gap-2">
    <span className="text-slate-400 mt-0.5">{icon}</span>
    <div className="min-w-0">
      <p className="text-[10px] text-slate-400 font-medium uppercase tracking-wide">{label}</p>
      <p className={`text-slate-700 truncate ${mono ? 'font-mono text-xs' : ''}`} title={value}>{value}</p>
    </div>
  </div>
);
