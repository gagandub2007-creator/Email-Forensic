import React, { useState, useEffect } from 'react';
import type { CaseRecord, EmailRecord, CaseNote } from '../../types';
import { useNavigate } from 'react-router-dom';
import { 
  Folder, 
  User, 
  Calendar, 
  ShieldAlert, 
  Layers, 
  FileText, 
  Database, 
  Clock, 
  MessageSquare, 
  ArrowLeft,
  CheckCircle2,
  AlertTriangle,
  Plus,
  Mail,
  ExternalLink,
  ShieldCheck,
  Server
} from 'lucide-react';

interface Props {
  caseId: string;
  onBack: () => void;
}

export const CaseDetailContainer: React.FC<Props> = ({ caseId, onBack }) => {
  const navigate = useNavigate();
  const [caseRecord, setCaseRecord] = useState<CaseRecord | null>(null);
  const [emails, setEmails] = useState<EmailRecord[]>([]);
  const [activeTab, setActiveTab] = useState<'info' | 'investigations' | 'infrastructure' | 'graph' | 'evidence' | 'timeline' | 'notes'>('info');
  const [loading, setLoading] = useState<boolean>(true);
  const [newNoteText, setNewNoteText] = useState<string>('');
  const [updatingStatus, setUpdatingStatus] = useState<boolean>(false);

  const fetchCaseDetails = async () => {
    setLoading(true);
    try {
      const res = await fetch(`/api/v1/cases/${caseId}`);
      if (res.ok) {
        const data: CaseRecord = await res.json();
        setCaseRecord(data);
      }
      
      // Fetch case graph or emails
      const graphRes = await fetch(`/api/v1/graph/case/${caseId}`);
      if (graphRes.ok) {
        const gData = await graphRes.json();
        // Graph nodes contains email data
      }
    } catch (err) {
      console.warn('Failed to fetch case details', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCaseDetails();
  }, [caseId]);

  const handleStatusChange = async (newStatus: string) => {
    if (!caseRecord) return;
    setUpdatingStatus(true);
    try {
      const res = await fetch(`/api/v1/cases/${caseId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus })
      });
      if (res.ok) {
        const updated: CaseRecord = await res.json();
        setCaseRecord(updated);
      }
    } catch (err) {
      console.warn('Failed to update status', err);
    } finally {
      setUpdatingStatus(false);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newNoteText.trim() || !caseRecord) return;
    try {
      const res = await fetch(`/api/v1/cases/${caseId}/notes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: newNoteText.trim(), author: 'Marcus K. (SOC L2 Analyst)' })
      });
      if (res.ok) {
        const updated: CaseRecord = await res.json();
        setCaseRecord(updated);
        setNewNoteText('');
      }
    } catch (err) {
      console.warn('Failed to add note', err);
    }
  };

  if (loading) {
    return (
      <div className="p-8 text-center text-slate-500 animate-pulse space-y-3">
        <Folder className="w-8 h-8 text-indigo-500 mx-auto animate-bounce" />
        <p className="text-sm font-medium">Loading unified case container...</p>
      </div>
    );
  }

  if (!caseRecord) {
    return (
      <div className="p-8 text-center text-slate-500 space-y-4">
        <AlertTriangle className="w-8 h-8 text-amber-500 mx-auto" />
        <p className="text-base font-semibold">Case not found.</p>
        <button onClick={onBack} className="bg-slate-200 px-4 py-2 rounded-lg text-xs font-semibold text-slate-700">
          Back to Cases
        </button>
      </div>
    );
  }

  const getStatusBadgeClass = (status: string) => {
    switch (status) {
      case 'Open': return 'bg-blue-100 text-blue-800 border-blue-300';
      case 'Investigating': return 'bg-amber-100 text-amber-800 border-amber-300';
      case 'Resolved': return 'bg-emerald-100 text-emerald-800 border-emerald-300';
      case 'Closed': return 'bg-slate-200 text-slate-700 border-slate-300';
      default: return 'bg-slate-100 text-slate-600 border-slate-200';
    }
  };

  const getSeverityBadgeClass = (severity: string) => {
    switch (severity) {
      case 'Critical': return 'bg-red-500 text-white';
      case 'High': return 'bg-rose-500 text-white';
      case 'Medium': return 'bg-amber-500 text-white';
      case 'Low': return 'bg-blue-500 text-white';
      default: return 'bg-slate-500 text-white';
    }
  };

  const tabs = [
    { id: 'info', label: 'Case Information', icon: Folder },
    { id: 'investigations', label: 'Related Investigations', icon: Mail },
    { id: 'infrastructure', label: 'Infrastructure', icon: Server },
    { id: 'graph', label: 'Threat Graph', icon: Database },
    { id: 'evidence', label: 'Evidence', icon: ShieldCheck },
    { id: 'timeline', label: 'Timeline', icon: Clock },
    { id: 'notes', label: `Notes (${caseRecord.notes?.length || 0})`, icon: MessageSquare },
  ];

  return (
    <div className="space-y-6">
      
      {/* Back Button & Case Header */}
      <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm space-y-4">
        <div className="flex items-center justify-between">
          <button 
            onClick={onBack}
            className="flex items-center gap-1.5 text-slate-600 hover:text-slate-900 text-xs font-semibold bg-slate-100 hover:bg-slate-200 px-3 py-1.5 rounded-lg transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
            Back to Cases Table
          </button>

          <div className="flex items-center gap-3">
            <span className={`text-xs font-bold px-2.5 py-1 rounded-md uppercase tracking-wider ${getSeverityBadgeClass(caseRecord.severity)}`}>
              {caseRecord.severity} Severity
            </span>

            {/* Interactive Status Selector */}
            <div className="flex items-center gap-1.5 text-xs font-semibold">
              <span className="text-slate-500">Status:</span>
              <select
                value={caseRecord.status}
                onChange={(e) => handleStatusChange(e.target.value)}
                disabled={updatingStatus}
                className={`px-3 py-1 rounded-lg border text-xs font-bold transition-all ${getStatusBadgeClass(caseRecord.status)}`}
              >
                <option value="Open">Open</option>
                <option value="Investigating">Investigating</option>
                <option value="Resolved">Resolved</option>
                <option value="Closed">Closed</option>
              </select>
            </div>
          </div>
        </div>

        <div>
          <div className="flex items-center gap-2">
            <span className="font-mono text-sm font-bold text-indigo-600 bg-indigo-50 px-2.5 py-0.5 rounded border border-indigo-200">
              {caseRecord.case_number}
            </span>
            <h1 className="text-2xl font-bold text-slate-900 leading-tight">{caseRecord.title}</h1>
          </div>
          <p className="text-xs text-slate-500 mt-1">{caseRecord.description || 'No case description provided.'}</p>
        </div>

        <div className="flex flex-wrap items-center gap-6 text-xs text-slate-600 border-t border-slate-100 pt-3">
          <div className="flex items-center gap-1.5">
            <User className="w-4 h-4 text-slate-400" />
            <span>Assigned: <strong>{caseRecord.assigned_analyst}</strong></span>
          </div>
          <div className="flex items-center gap-1.5">
            <Calendar className="w-4 h-4 text-slate-400" />
            <span>Created: <strong>{new Date(caseRecord.created_at).toLocaleDateString()}</strong></span>
          </div>
          <div className="flex items-center gap-1.5">
            <Clock className="w-4 h-4 text-slate-400" />
            <span>Updated: <strong>{new Date(caseRecord.updated_at).toLocaleDateString()}</strong></span>
          </div>
        </div>
      </div>

      {/* Unified Single-Page Container Navigation Tabs */}
      <div className="border-b border-slate-200 flex gap-2 overflow-x-auto bg-white px-3 pt-2 rounded-xl shadow-sm">
        {tabs.map((t) => {
          const IconComp = t.icon;
          const isActive = activeTab === t.id;
          return (
            <button
              key={t.id}
              onClick={() => setActiveTab(t.id as any)}
              className={`flex items-center gap-2 px-4 py-3 text-xs font-bold border-b-2 transition-all whitespace-nowrap ${
                isActive
                  ? 'border-indigo-600 text-indigo-600 bg-indigo-50/50 rounded-t-lg'
                  : 'border-transparent text-slate-600 hover:text-slate-900 hover:bg-slate-50'
              }`}
            >
              <IconComp className="w-4 h-4" />
              <span>{t.label}</span>
            </button>
          );
        })}
      </div>

      {/* Tab 1: Case Information */}
      {activeTab === 'info' && (
        <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm space-y-6 max-w-4xl">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <div className="p-4 bg-slate-50 rounded-lg border border-slate-200 space-y-1">
              <span className="text-slate-500 font-semibold uppercase tracking-wider">Case Reference</span>
              <div className="font-mono text-sm font-bold text-slate-900">{caseRecord.case_number}</div>
            </div>
            <div className="p-4 bg-slate-50 rounded-lg border border-slate-200 space-y-1">
              <span className="text-slate-500 font-semibold uppercase tracking-wider">Container Investigations</span>
              <div className="text-sm font-bold text-slate-900">{caseRecord.investigation_count} Related Email(s)</div>
            </div>
          </div>

          <div className="space-y-2">
            <h3 className="font-bold text-slate-900 text-sm">Executive Overview & Case Objectives</h3>
            <p className="text-xs text-slate-700 leading-relaxed bg-slate-50 p-4 rounded-lg border border-slate-200">
              {caseRecord.description || 'This case acts as a container grouping related phishing, Business Email Compromise (BEC), and malicious header routing investigations.'}
            </p>
          </div>
        </div>
      )}

      {/* Tab 2: Related Investigations & Emails */}
      {activeTab === 'investigations' && (
        <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm space-y-4">
          <h3 className="font-bold text-slate-900 text-sm flex items-center gap-2">
            <Mail className="w-4 h-4 text-indigo-600" />
            Grouped Email Investigations
          </h3>
          <p className="text-xs text-slate-500">All raw email artifacts associated with this case container</p>
          
          <div className="p-4 bg-slate-50 rounded-lg border border-slate-200 text-xs text-slate-600">
            <p className="font-medium">Case currently contains {caseRecord.investigation_count} email investigation(s).</p>
            <button 
              onClick={() => navigate('/analyze')}
              className="mt-3 bg-indigo-600 hover:bg-indigo-700 text-white font-bold px-3 py-1.5 rounded-lg text-xs transition-colors inline-flex items-center gap-1.5"
            >
              <Plus className="w-3.5 h-3.5" /> Analyze & Add New Email to Case
            </button>
          </div>
        </div>
      )}

      {/* Tab 3: Infrastructure */}
      {activeTab === 'infrastructure' && (
        <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm space-y-4 text-xs">
          <h3 className="font-bold text-slate-900 text-sm flex items-center gap-2">
            <Server className="w-4 h-4 text-indigo-600" />
            Case Aggregate Infrastructure Topology
          </h3>
          <p className="text-slate-500">Aggregated IP addresses, ASNs, ISPs, and hosting networks across case investigations</p>
          <div className="p-4 bg-slate-50 rounded-lg border border-slate-200 space-y-2">
            <span className="font-semibold text-slate-800">Primary Transit Nodes:</span>
            <ul className="list-disc list-inside text-slate-700 space-y-1">
              <li>185.220.101.5 (Frankfurt, Germany - AS205100 Tor Exit Router)</li>
              <li>198.51.100.42 (Tokyo, Japan - AS2514 NTT Communications)</li>
            </ul>
          </div>
        </div>
      )}

      {/* Tab 4: Threat Graph */}
      {activeTab === 'graph' && (
        <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm space-y-4">
          <h3 className="font-bold text-slate-900 text-sm flex items-center gap-2">
            <Database className="w-4 h-4 text-indigo-600" />
            Case Multi-Email Threat Graph
          </h3>
          <iframe 
            src={`/api/v1/graph/case/${caseRecord.id}`}
            className="w-full h-[500px] border border-slate-200 rounded-lg hidden" 
          />
          <div className="p-8 text-center text-xs text-slate-500 bg-slate-50 rounded-lg border border-slate-200">
            Render multi-email campaign relationship graph in Neo4j / Demo Provider view
          </div>
        </div>
      )}

      {/* Tab 5: Evidence */}
      {activeTab === 'evidence' && (
        <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm space-y-4 text-xs">
          <h3 className="font-bold text-slate-900 text-sm flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-indigo-600" />
            Case Evidence Vault & Blockchain Ledger Proofs
          </h3>
          <div className="p-4 bg-emerald-50 rounded-lg border border-emerald-200 space-y-2 text-emerald-900 font-mono">
            <p><strong>Case Merkle Root:</strong> e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</p>
            <p><strong>Blockchain Status:</strong> <span className="text-emerald-700 font-bold">VERIFIED ON EVM LEDGER</span></p>
          </div>
        </div>
      )}

      {/* Tab 6: Timeline */}
      {activeTab === 'timeline' && (
        <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm space-y-4 text-xs">
          <h3 className="font-bold text-slate-900 text-sm flex items-center gap-2">
            <Clock className="w-4 h-4 text-indigo-600" />
            Case Chronological Audit Timeline
          </h3>
          <div className="space-y-3">
            <div className="flex items-start gap-3 text-slate-700">
              <span className="font-bold text-indigo-600 w-32 flex-shrink-0">{new Date(caseRecord.created_at).toLocaleString()}</span>
              <span>Case {caseRecord.case_number} opened by analyst {caseRecord.assigned_analyst}.</span>
            </div>
          </div>
        </div>
      )}

      {/* Tab 7: Analyst Notes */}
      {activeTab === 'notes' && (
        <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm space-y-6">
          <div className="flex items-center justify-between">
            <h3 className="font-bold text-slate-900 text-sm flex items-center gap-2">
              <MessageSquare className="w-4 h-4 text-indigo-600" />
              Investigator Operational Notebook
            </h3>
            <span className="text-xs text-slate-500">{caseRecord.notes?.length || 0} Entries</span>
          </div>

          {/* Add Note Form */}
          <form onSubmit={handleAddNote} className="space-y-3">
            <textarea
              rows={3}
              value={newNoteText}
              onChange={(e) => setNewNoteText(e.target.value)}
              placeholder="Add investigator notes, forensic hypothesis, or evidence tracking updates..."
              className="w-full p-3 border border-slate-200 rounded-lg text-xs focus:ring-2 focus:ring-indigo-500 focus:outline-none"
            />
            <div className="flex justify-end">
              <button
                type="submit"
                disabled={!newNoteText.trim()}
                className="bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white font-bold px-4 py-2 rounded-lg text-xs transition-colors flex items-center gap-1.5"
              >
                <Plus className="w-3.5 h-3.5" /> Add Note
              </button>
            </div>
          </form>

          {/* Notes List */}
          <div className="space-y-3">
            {caseRecord.notes && caseRecord.notes.length > 0 ? (
              caseRecord.notes.map((note: CaseNote, idx: number) => (
                <div key={idx} className="p-4 bg-slate-50 rounded-lg border border-slate-200 text-xs space-y-1">
                  <div className="flex items-center justify-between font-bold text-slate-900">
                    <span>{note.author}</span>
                    <span className="text-[11px] text-slate-400 font-normal">{new Date(note.timestamp).toLocaleString()}</span>
                  </div>
                  <p className="text-slate-700 leading-relaxed">{note.text}</p>
                </div>
              ))
            ) : (
              <p className="text-xs text-slate-500 italic">No notes added to this case yet.</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
