import React, { useState, useEffect } from 'react';
import { 
  FileText, Download, ShieldCheck, AlertTriangle, Eye, CheckCircle2, 
  Lock, Key, Scale, Layers, Server, Hash, FileSpreadsheet, X 
} from 'lucide-react';

interface ReportPreviewModalProps {
  emailId: string;
  isOpen: boolean;
  onClose: () => void;
}

interface ReportPreviewData {
  email_id: string;
  case_id: string;
  subject: string;
  sender_address: string;
  recipient_address: string;
  threat_level: string;
  overall_threat_score: number;
  ai_classification: string;
  ai_confidence: number;
  evidence_id: string | null;
  sha256_hash: string;
  integrity_status: string;
  ledger_tx_id: string | null;
  ledger_status: string;
  custody_event_count: number;
  sections: string[];
}

export const ReportPreviewModal: React.FC<ReportPreviewModalProps> = ({
  emailId,
  isOpen,
  onClose,
}) => {
  const [data, setData] = useState<ReportPreviewData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [downloading, setDownloading] = useState(false);

  useEffect(() => {
    if (isOpen && emailId) {
      fetchPreview();
    }
  }, [isOpen, emailId]);

  const fetchPreview = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`http://localhost:8000/api/v1/reports/preview/${emailId}`);
      if (!res.ok) throw new Error('Failed to load report preview metadata');
      const json = await res.json();
      setData(json);
    } catch (err: any) {
      setError(err.message || 'Error fetching report preview');
    } finally {
      setLoading(false);
    }
  };

  const handleGeneratePdf = () => {
    window.open(`http://localhost:8000/api/v1/reports/pdf/${emailId}`, '_blank');
  };

  const handleDownloadPdf = async () => {
    setDownloading(true);
    try {
      const res = await fetch(`http://localhost:8000/api/v1/reports/pdf/${emailId}`);
      if (!res.ok) throw new Error('Failed to generate PDF');
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `Forensic_Report_${emailId.slice(0, 8)}.pdf`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      a.remove();
    } catch (err: any) {
      alert(`Download failed: ${err.message}`);
    } finally {
      setDownloading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-sm p-4 overflow-y-auto">
      <div className="bg-slate-900 border border-slate-800 rounded-xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/90">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-indigo-500/10 text-indigo-400 rounded-lg">
              <FileText className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                Digital Forensic Investigation Report Preview
                <span className="text-xs bg-indigo-500/20 text-indigo-300 px-2 py-0.5 rounded border border-indigo-500/30">
                  17 Sections
                </span>
              </h2>
              <p className="text-xs text-slate-400">
                Case & Evidence Certified Report • Compliant with Indian Evidence Act (BSA 2023)
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 p-1.5 rounded-lg hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1 text-sm text-slate-300">
          {loading && (
            <div className="py-12 text-center text-slate-400 animate-pulse">
              Generating forensic report structure...
            </div>
          )}

          {error && (
            <div className="p-4 bg-red-500/10 border border-red-500/30 text-red-400 rounded-lg flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {data && (
            <>
              {/* Summary Banner */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="bg-slate-950/60 p-3.5 rounded-lg border border-slate-800">
                  <span className="text-xs text-slate-500 block">Case ID</span>
                  <span className="font-mono text-slate-200 font-medium">{data.case_id || 'DEFAULT-2026'}</span>
                </div>
                <div className="bg-slate-950/60 p-3.5 rounded-lg border border-slate-800">
                  <span className="text-xs text-slate-500 block">Threat Classification</span>
                  <span className="font-semibold text-indigo-400">{data.ai_classification} ({Math.round(data.ai_confidence * 100)}%)</span>
                </div>
                <div className="bg-slate-950/60 p-3.5 rounded-lg border border-slate-800">
                  <span className="text-xs text-slate-500 block">Evidence Hash Integrity</span>
                  <span className="font-medium text-emerald-400 flex items-center gap-1">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    {data.integrity_status}
                  </span>
                </div>
                <div className="bg-slate-950/60 p-3.5 rounded-lg border border-slate-800">
                  <span className="text-xs text-slate-500 block">Blockchain Ledger</span>
                  <span className="font-mono text-xs text-indigo-300 truncate block">
                    {data.ledger_status === 'CONFIRMED' ? '✓ Anchored' : data.ledger_status}
                  </span>
                </div>
              </div>

              {/* Sections Breakdown */}
              <div className="bg-slate-950/40 p-4 rounded-xl border border-slate-800">
                <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">
                  Report Structure & Evidence Classification Standard
                </h3>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
                  {data.sections.map((section, idx) => (
                    <div key={idx} className="p-2.5 bg-slate-900/80 rounded border border-slate-800/80 flex items-center justify-between">
                      <span className="font-medium text-slate-200">{section}</span>
                      <span className="text-[10px] text-slate-500 font-mono">Verified</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Legend & Compliance Statement */}
              <div className="p-4 bg-amber-500/10 border border-amber-500/20 rounded-xl space-y-2">
                <div className="flex items-center gap-2 text-amber-400 font-semibold text-xs">
                  <Scale className="w-4 h-4" />
                  <span>Strict Evidence Classification Protocol</span>
                </div>
                <p className="text-xs text-amber-200/80 leading-relaxed">
                  This report clearly distinguishes <strong className="text-emerald-400">[FACT]</strong> (directly extracted email headers & hashes), <strong className="text-sky-400">[INFERENCE]</strong> (AI classification), <strong className="text-amber-400">[ESTIMATION]</strong> (approximate IP geolocation), <strong className="text-indigo-400">[CONFIDENCE]</strong> (model score), and <strong className="text-red-400">[LIMITATION]</strong> (non-claim of attacker identity).
                </p>
              </div>
            </>
          )}
        </div>

        {/* Footer Actions */}
        <div className="px-6 py-4 border-t border-slate-800 bg-slate-900/90 flex items-center justify-end gap-3">
          <button
            onClick={onClose}
            className="px-4 py-2 text-slate-400 hover:text-slate-200 text-sm font-medium transition"
          >
            Close
          </button>

          <button
            onClick={handleGeneratePdf}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-sm font-medium flex items-center gap-2 border border-slate-700 transition"
          >
            <Eye className="w-4 h-4" />
            Generate PDF Preview
          </button>

          <button
            onClick={handleDownloadPdf}
            disabled={downloading}
            className="px-5 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white rounded-lg text-sm font-medium flex items-center gap-2 shadow-lg shadow-indigo-600/20 transition"
          >
            <Download className="w-4 h-4" />
            {downloading ? 'Downloading...' : 'Download PDF Report'}
          </button>
        </div>
      </div>
    </div>
  );
};
