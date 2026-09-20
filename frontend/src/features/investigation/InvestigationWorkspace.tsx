import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { ChevronRight, ShieldAlert, Loader2, FileText, Search, Shield, Zap, GitCommit, Network, Database } from 'lucide-react';
import type { EmailRecord } from '../../types';

// Tab components (stubs for now, will be implemented separately)
import { OverviewTab } from './OverviewTab';
import { HeadersTab } from './HeadersTab';
import { AuthTab } from './AuthTab';
import { IOCsTab } from './IOCsTab';
import { TraceTab } from './TraceTab';
import { GraphTab } from './GraphTab';
import { EvidenceTab } from './EvidenceTab';

type TabId = 'overview' | 'headers' | 'auth' | 'iocs' | 'trace' | 'graph' | 'evidence';

export const InvestigationWorkspace: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [emailData, setEmailData] = useState<EmailRecord | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabId>('overview');

  useEffect(() => {
    const fetchInvestigation = async () => {
      try {
        const response = await fetch(`/api/v1/emails/${id}`);
        if (!response.ok) {
          throw new Error('Failed to load investigation data');
        }
        const data = await response.json();
        setEmailData(data);
      } catch (err: any) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    if (id) {
      fetchInvestigation();
    }
  }, [id]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <Loader2 className="w-8 h-8 text-blue-600 animate-spin" />
      </div>
    );
  }

  if (error || !emailData) {
    return (
      <div className="p-8 text-center text-red-600">
        <ShieldAlert className="w-12 h-12 mx-auto mb-4 opacity-50" />
        <h2 className="text-xl font-semibold mb-2">Investigation Not Found</h2>
        <p className="text-slate-600">{error || 'The requested investigation record could not be loaded.'}</p>
      </div>
    );
  }

  const tabs: { id: TabId; label: string; icon: React.ReactNode }[] = [
    { id: 'overview', label: 'Overview', icon: <Search className="w-4 h-4" /> },
    { id: 'headers', label: 'Headers', icon: <FileText className="w-4 h-4" /> },
    { id: 'auth', label: 'Authentication', icon: <Shield className="w-4 h-4" /> },
    { id: 'iocs', label: 'IOCs', icon: <Zap className="w-4 h-4" /> },
    { id: 'trace', label: 'Trace', icon: <GitCommit className="w-4 h-4" /> },
    { id: 'graph', label: 'Graph', icon: <Network className="w-4 h-4" /> },
    { id: 'evidence', label: 'Evidence', icon: <Database className="w-4 h-4" /> },
  ];

  return (
    <div className="flex flex-col h-full bg-slate-50 overflow-hidden">
      {/* Top Header / Breadcrumbs */}
      <div className="px-6 py-4 bg-white border-b border-slate-200">
        <div className="flex items-center text-sm font-medium text-slate-500 mb-4">
          <Link to="/investigations" className="hover:text-slate-900 transition-colors">Investigations</Link>
          <ChevronRight className="w-4 h-4 mx-2" />
          <span className="text-slate-900 truncate max-w-xs" title={emailData.id}>INV-{emailData.id.split('-')[0].toUpperCase()}</span>
        </div>

        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="flex-1 min-w-0">
            <h1 className="text-2xl font-bold text-slate-900 truncate" title={emailData.subject}>
              {emailData.subject || '(No Subject)'}
            </h1>
            
            <div className="flex flex-wrap items-center gap-3 mt-3">
              <div className="flex items-center px-2.5 py-1 rounded-md text-xs font-semibold bg-slate-100 text-slate-700 border border-slate-200">
                Risk: {Math.round(emailData.overall_threat_score)} / 100
              </div>
              <div className={`flex items-center px-2.5 py-1 rounded-md text-xs font-semibold border ${
                emailData.threat_level === 'Critical' ? 'bg-red-50 text-red-700 border-red-200' :
                emailData.threat_level === 'High' ? 'bg-orange-50 text-orange-700 border-orange-200' :
                emailData.threat_level === 'Medium' ? 'bg-amber-50 text-amber-700 border-amber-200' :
                'bg-green-50 text-green-700 border-green-200'
              }`}>
                Severity: {emailData.threat_level}
              </div>
              <div className="flex items-center px-2.5 py-1 rounded-md text-xs font-semibold bg-blue-50 text-blue-700 border border-blue-200">
                {emailData.ai_analysis?.classification || 'Unclassified'}
              </div>
              <div className="flex items-center px-2.5 py-1 rounded-md text-xs font-medium bg-slate-50 text-slate-600 border border-slate-200">
                Confidence: {Math.round((emailData.ai_analysis?.confidence || 0) * 100)}%
              </div>
            </div>
          </div>

          <div>
            <button
              onClick={async () => {
                try {
                  const res = await fetch('/api/v1/cases/create-from-investigation', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                      email_id: emailData.id,
                      title: `Case: ${emailData.subject ? emailData.subject.slice(0, 60) : 'Threat Email'}`,
                      severity: emailData.threat_level || 'High',
                      status: 'Open'
                    })
                  });
                  if (res.ok) {
                    alert('Successfully created case from investigation! View it under Cases tab.');
                  }
                } catch (e) {
                  console.error(e);
                }
              }}
              className="bg-indigo-600 hover:bg-indigo-700 text-white font-bold px-3.5 py-2 rounded-lg text-xs transition-colors flex items-center gap-1.5 shadow-sm"
            >
              + Create Case from Investigation
            </button>
          </div>
        </div>
      </div>

      {/* Tabs Navigation */}
      <div className="px-6 bg-white border-b border-slate-200">
        <nav className="flex space-x-1" aria-label="Tabs">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
                activeTab === tab.id
                  ? 'border-blue-600 text-blue-600'
                  : 'border-transparent text-slate-500 hover:text-slate-700 hover:border-slate-300'
              }`}
            >
              {tab.icon}
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab Content Area */}
      <div className="flex-1 overflow-y-auto p-6">
        {activeTab === 'overview' && <OverviewTab data={emailData} />}
        {activeTab === 'headers' && <HeadersTab data={emailData} />}
        {activeTab === 'auth' && <AuthTab data={emailData} />}
        {activeTab === 'iocs' && <IOCsTab data={emailData} />}
        {activeTab === 'trace' && <TraceTab data={emailData} />}
        {activeTab === 'graph' && <GraphTab data={emailData} />}
        {activeTab === 'evidence' && <EvidenceTab data={emailData} />}
      </div>
    </div>
  );
};
