import React, { useState, useEffect } from 'react';
import type { CaseRecord } from '../../types';
import { CaseDetailContainer } from './CaseDetailContainer';
import { 
  Folder, 
  Plus, 
  Search, 
  Filter, 
  AlertTriangle, 
  User, 
  Calendar, 
  Clock, 
  ChevronRight,
  ShieldAlert,
  CheckCircle2
} from 'lucide-react';

export const CasesManager: React.FC = () => {
  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('All');
  const [severityFilter, setSeverityFilter] = useState<string>('All');
  
  // Create Modal state
  const [showCreateModal, setShowCreateModal] = useState<boolean>(false);
  const [newTitle, setNewTitle] = useState<string>('');
  const [newDescription, setNewDescription] = useState<string>('');
  const [newSeverity, setNewSeverity] = useState<string>('High');
  const [newStatus, setNewStatus] = useState<string>('Open');
  const [newAnalyst, setNewAnalyst] = useState<string>('Marcus K. (SOC L2 Analyst)');
  const [creating, setCreating] = useState<boolean>(false);

  const fetchCases = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/v1/cases');
      if (res.ok) {
        const data: CaseRecord[] = await res.json();
        setCases(data);
      }
    } catch (err) {
      console.warn('Failed to fetch cases', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCases();
  }, []);

  const handleCreateCase = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim()) return;
    setCreating(true);
    try {
      const res = await fetch('/api/v1/cases', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: newTitle.trim(),
          description: newDescription.trim(),
          severity: newSeverity,
          status: newStatus,
          assigned_analyst: newAnalyst
        })
      });
      if (res.ok) {
        const created: CaseRecord = await res.json();
        setCases(prev => [created, ...prev]);
        setShowCreateModal(false);
        setNewTitle('');
        setNewDescription('');
      }
    } catch (err) {
      console.warn('Failed to create case', err);
    } finally {
      setCreating(false);
    }
  };

  // Filter cases
  const filteredCases = cases.filter(c => {
    const matchesSearch = 
      c.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      c.case_number.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (c.description || '').toLowerCase().includes(searchQuery.toLowerCase());
    
    const matchesStatus = statusFilter === 'All' || c.status === statusFilter;
    const matchesSeverity = severityFilter === 'All' || c.severity === severityFilter;

    return matchesSearch && matchesStatus && matchesSeverity;
  });

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'Open':
        return <span className="bg-blue-50 text-blue-700 border border-blue-200 px-2.5 py-1 rounded-md text-xs font-bold">Open</span>;
      case 'Investigating':
        return <span className="bg-amber-50 text-amber-700 border border-amber-200 px-2.5 py-1 rounded-md text-xs font-bold">Investigating</span>;
      case 'Resolved':
        return <span className="bg-emerald-50 text-emerald-700 border border-emerald-200 px-2.5 py-1 rounded-md text-xs font-bold">Resolved</span>;
      case 'Closed':
        return <span className="bg-slate-100 text-slate-600 border border-slate-200 px-2.5 py-1 rounded-md text-xs font-bold">Closed</span>;
      default:
        return <span className="bg-slate-100 text-slate-600 px-2.5 py-1 rounded-md text-xs font-bold">{status}</span>;
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'Critical':
        return <span className="bg-red-500 text-white px-2 py-0.5 rounded text-[11px] font-bold">Critical</span>;
      case 'High':
        return <span className="bg-rose-500 text-white px-2 py-0.5 rounded text-[11px] font-bold">High</span>;
      case 'Medium':
        return <span className="bg-amber-500 text-white px-2 py-0.5 rounded text-[11px] font-bold">Medium</span>;
      case 'Low':
        return <span className="bg-blue-500 text-white px-2 py-0.5 rounded text-[11px] font-bold">Low</span>;
      default:
        return <span className="bg-slate-500 text-white px-2 py-0.5 rounded text-[11px] font-bold">{severity}</span>;
    }
  };

  if (selectedCaseId) {
    return (
      <CaseDetailContainer
        caseId={selectedCaseId}
        onBack={() => {
          setSelectedCaseId(null);
          fetchCases();
        }}
      />
    );
  }

  return (
    <div className="space-y-6">
      
      {/* Top Header & Actions */}
      <div className="flex flex-wrap items-center justify-between gap-4 bg-white p-5 rounded-xl border border-slate-200 shadow-sm">
        <div>
          <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2">
            <Folder className="w-5 h-5 text-indigo-600" />
            Case Management Workstation
          </h1>
          <p className="text-xs text-slate-500">
            Enterprise container management for multi-email forensic investigations
          </p>
        </div>

        <button
          onClick={() => setShowCreateModal(true)}
          className="bg-indigo-600 hover:bg-indigo-700 text-white font-bold px-4 py-2 rounded-lg text-xs transition-colors flex items-center gap-2 shadow-sm"
        >
          <Plus className="w-4 h-4" /> Create New Case
        </button>
      </div>

      {/* Filter & Search Bar */}
      <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm flex flex-wrap items-center gap-4 text-xs">
        <div className="flex-1 min-w-[240px] relative">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search cases by Case ID, Title, or description..."
            className="w-full pl-9 pr-4 py-2 border border-slate-200 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:outline-none"
          />
        </div>

        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-slate-400" />
          <span className="font-semibold text-slate-600">Status:</span>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-1.5 border border-slate-200 rounded-lg font-medium text-slate-700 bg-white"
          >
            <option value="All">All Statuses</option>
            <option value="Open">Open</option>
            <option value="Investigating">Investigating</option>
            <option value="Resolved">Resolved</option>
            <option value="Closed">Closed</option>
          </select>
        </div>

        <div className="flex items-center gap-2">
          <span className="font-semibold text-slate-600">Severity:</span>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-3 py-1.5 border border-slate-200 rounded-lg font-medium text-slate-700 bg-white"
          >
            <option value="All">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
        </div>
      </div>

      {/* Cases Table */}
      <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-slate-50 border-b border-slate-200 text-slate-600 font-bold uppercase tracking-wider text-[11px]">
                <th className="py-3 px-4">Case ID</th>
                <th className="py-3 px-4">Title</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Assigned Analyst</th>
                <th className="py-3 px-4">Created</th>
                <th className="py-3 px-4">Updated</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 font-medium text-slate-800">
              {loading ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-400 animate-pulse">
                    Loading cases repository...
                  </td>
                </tr>
              ) : filteredCases.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-400 italic">
                    No cases match the specified filters.
                  </td>
                </tr>
              ) : (
                filteredCases.map((c: CaseRecord) => (
                  <tr 
                    key={c.id} 
                    onClick={() => setSelectedCaseId(c.id)}
                    className="hover:bg-slate-50 cursor-pointer transition-colors"
                  >
                    <td className="py-3 px-4 font-mono font-bold text-indigo-600">
                      {c.case_number}
                    </td>
                    <td className="py-3 px-4 font-bold text-slate-900 max-w-xs truncate" title={c.title}>
                      {c.title}
                      {c.investigation_count > 0 && (
                        <span className="ml-2 text-[10px] font-semibold text-slate-500 bg-slate-100 px-1.5 py-0.5 rounded">
                          {c.investigation_count} email(s)
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4">{getSeverityBadge(c.severity)}</td>
                    <td className="py-3 px-4">{getStatusBadge(c.status)}</td>
                    <td className="py-3 px-4 text-slate-700">{c.assigned_analyst}</td>
                    <td className="py-3 px-4 text-slate-500">{new Date(c.created_at).toLocaleDateString()}</td>
                    <td className="py-3 px-4 text-slate-500">{new Date(c.updated_at).toLocaleDateString()}</td>
                    <td className="py-3 px-4 text-right">
                      <ChevronRight className="w-4 h-4 text-slate-400 inline" />
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Create Case Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-slate-900/50 backdrop-blur-sm flex items-center justify-center p-4 z-50 animate-in fade-in duration-200">
          <div className="bg-white rounded-xl shadow-2xl border border-slate-200 w-full max-w-lg overflow-hidden">
            <div className="bg-slate-900 text-white px-5 py-4 flex items-center justify-between">
              <h3 className="font-bold text-sm flex items-center gap-2">
                <Folder className="w-4 h-4 text-indigo-400" />
                Initialize New Case Container
              </h3>
              <button 
                onClick={() => setShowCreateModal(false)}
                className="text-slate-400 hover:text-white font-bold text-base"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateCase} className="p-5 space-y-4 text-xs">
              <div className="space-y-1">
                <label className="font-bold text-slate-700">Case Title *</label>
                <input
                  type="text"
                  required
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  placeholder="e.g. Operation Finance Spear-Phishing Campaign"
                  className="w-full p-2.5 border border-slate-200 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:outline-none"
                />
              </div>

              <div className="space-y-1">
                <label className="font-bold text-slate-700">Description</label>
                <textarea
                  rows={3}
                  value={newDescription}
                  onChange={(e) => setNewDescription(e.target.value)}
                  placeholder="Case objectives, scope, and initial threat notes..."
                  className="w-full p-2.5 border border-slate-200 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:outline-none"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="font-bold text-slate-700">Severity</label>
                  <select
                    value={newSeverity}
                    onChange={(e) => setNewSeverity(e.target.value)}
                    className="w-full p-2 border border-slate-200 rounded-lg font-medium"
                  >
                    <option value="Low">Low</option>
                    <option value="Medium">Medium</option>
                    <option value="High">High</option>
                    <option value="Critical">Critical</option>
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="font-bold text-slate-700">Initial Status</label>
                  <select
                    value={newStatus}
                    onChange={(e) => setNewStatus(e.target.value)}
                    className="w-full p-2 border border-slate-200 rounded-lg font-medium"
                  >
                    <option value="Open">Open</option>
                    <option value="Investigating">Investigating</option>
                    <option value="Resolved">Resolved</option>
                    <option value="Closed">Closed</option>
                  </select>
                </div>
              </div>

              <div className="space-y-1">
                <label className="font-bold text-slate-700">Assigned Analyst</label>
                <input
                  type="text"
                  value={newAnalyst}
                  onChange={(e) => setNewAnalyst(e.target.value)}
                  className="w-full p-2.5 border border-slate-200 rounded-lg font-medium"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-slate-100">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 rounded-lg text-slate-600 font-semibold hover:bg-slate-100"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creating || !newTitle.trim()}
                  className="bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white font-bold px-4 py-2 rounded-lg shadow-sm transition-colors"
                >
                  {creating ? 'Creating...' : 'Create Case'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
