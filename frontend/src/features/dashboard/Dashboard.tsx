import React from 'react';
import { Mail, ShieldAlert, FolderOpen, Activity, ArrowRight, ShieldCheck } from 'lucide-react';
import { StatSummary } from '../../components/common/StatSummary';
import { DataTable } from '../../components/common/DataTable';
import { SectionHeader } from '../../components/common/SectionHeader';
import { RiskBadge } from '../../components/common/RiskBadge';
import { StatusBadge } from '../../components/common/StatusBadge';
import { recentInvestigations, recentAlerts, threatDistribution } from './mockData';


export const Dashboard: React.FC = () => {
  return (
    <div className="space-y-6 max-w-[1600px] mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-800">SOC Incident Overview</h1>
          <p className="text-sm text-slate-500 flex items-center gap-2 mt-1">
            <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
            STREAM ACTIVE • CLUSTER US-EAST-01
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-sm text-slate-500">Sync window: <strong className="text-slate-700">Live (0.4s)</strong></span>
          <button className="bg-white border border-slate-200 text-slate-700 px-3 py-1.5 rounded-md text-sm font-medium">
            Feed Filters
          </button>
        </div>
      </div>

      {/* Top Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatSummary title="Emails Analyzed Today" value="1,428" icon={Mail} trend="+12% vs 7d avg" trendUp={true} />
        <StatSummary title="High / Critical Threats" value="37" icon={ShieldAlert} trend="8 immediate action" trendUp={false} />
        <StatSummary title="Active Investigations" value="6" icon={FolderOpen} trend="2 in peer review" trendUp={true} />
        <StatSummary title="Mean Time To Respond" value="14.2 min" icon={Activity} trend="-2.1m target delta" trendUp={true} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Content (Left & Center) */}
        <div className="lg:col-span-2 space-y-6">
          
          <div className="bg-white border border-slate-200 rounded-lg p-5">
            <SectionHeader 
              title="Active Incident Investigations" 
              description="Forensic dockets under active triage • 5 items loaded"
              action={
                <input type="text" placeholder="Filter cases, IOCs..." className="border border-slate-200 rounded px-3 py-1.5 text-sm" />
              }
            />
            <DataTable 
              data={recentInvestigations}
              keyExtractor={(item) => item.id}
              columns={[
                { key: 'id', header: 'Case ID', render: (i) => <span className="font-semibold text-primary">{i.id}</span> },
                { key: 'subject', header: 'Incident Title', render: (i) => (
                    <div>
                      <div className="font-medium text-slate-900">{i.subject}</div>
                      <div className="text-xs text-slate-500">hash: {i.id.toLowerCase()}...</div>
                    </div>
                )},
                { key: 'classification', header: 'Classification', render: (i) => <span className="text-xs bg-slate-100 text-slate-700 px-2 py-1 rounded">{i.classification}</span> },
                { key: 'risk', header: 'Severity', render: (i) => <RiskBadge level={i.risk as any} score={i.score} /> },
                { key: 'status', header: 'Status', render: (i) => <StatusBadge status={i.status as any} /> }
              ]}
            />
          </div>

          <div className="bg-white border border-slate-200 rounded-lg p-5">
            <SectionHeader 
              title="Recent Ingestion Stream & Quick Triage" 
              badge="Auto-Ingest Healthy"
            />
            <div className="space-y-3">
              {recentAlerts.map((alert) => (
                <div key={alert.id} className="flex items-start justify-between p-4 border border-slate-100 rounded-md bg-slate-50/50">
                  <div className="flex gap-4">
                    {alert.severity === 'Critical' ? <ShieldAlert className="w-5 h-5 text-red-500 mt-1" /> : <ShieldCheck className="w-5 h-5 text-emerald-500 mt-1" />}
                    <div>
                      <h4 className="font-medium text-slate-800">{alert.type}</h4>
                      <p className="text-sm text-slate-600 mt-1">{alert.detail}</p>
                      <p className="text-xs text-slate-400 mt-2">{alert.time}</p>
                    </div>
                  </div>
                  <button className="flex items-center gap-1 text-sm text-primary font-medium hover:text-primary-hover">
                    Inspect <ArrowRight className="w-4 h-4" />
                  </button>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right Sidebar content */}
        <div className="space-y-6">
          <div className="bg-gradient-to-br from-primary to-blue-700 text-white rounded-lg p-6 shadow-md relative overflow-hidden">
            <div className="relative z-10">
              <div className="flex items-center gap-2 text-blue-100 text-xs font-bold uppercase tracking-wider mb-2">
                <ShieldAlert className="w-4 h-4" /> Forensic Parser
              </div>
              <h2 className="text-xl font-bold mb-2">Initiate Deep Header Analysis</h2>
              <p className="text-blue-100 text-sm mb-6">
                Drop raw MIME strings, RFC-822 headers, or exported .EML payloads for deterministic DKIM/SPF tracing.
              </p>
              <div className="flex gap-3">
                <button className="bg-white text-primary px-4 py-2 rounded font-semibold text-sm hover:bg-slate-50 transition-colors shadow-sm">
                  + Analyze New Email (.EML)
                </button>
                <button className="border border-blue-300 text-white px-4 py-2 rounded font-semibold text-sm hover:bg-blue-600 transition-colors">
                  Paste Raw
                </button>
              </div>
            </div>
            {/* Background pattern */}
            <div className="absolute -bottom-12 -right-12 w-48 h-48 border-[20px] border-white/10 rounded-full blur-xl"></div>
          </div>

          <div className="bg-white border border-slate-200 rounded-lg p-5">
            <SectionHeader title="Threat Vector Distribution" description="Last 30 Days" />
            
            <div className="space-y-4 mt-4">
              {/* Progress bar composite */}
              <div className="flex h-3 rounded-full overflow-hidden mb-6">
                {threatDistribution.map(item => (
                  <div key={item.name} style={{ width: `${item.percentage}%`, backgroundColor: item.color }}></div>
                ))}
              </div>

              {/* Legend */}
              <div className="space-y-3">
                {threatDistribution.map(item => (
                  <div key={item.name} className="flex items-center justify-between text-sm">
                    <div className="flex items-center gap-3">
                      <span className="w-3 h-3 rounded-full" style={{ backgroundColor: item.color }}></span>
                      <span className="text-slate-700 font-medium">{item.name}</span>
                    </div>
                    <div className="text-right">
                      <div className="font-bold text-slate-800">{item.percentage}%</div>
                      <div className="text-xs text-slate-500">{item.count} cases</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="bg-white border border-slate-200 rounded-lg p-5">
            <SectionHeader title="Origin Network Infrastructure" description="Relay Telemetry" />
            <div className="bg-slate-100 rounded-md h-40 flex items-center justify-center mb-3 border border-slate-200">
              {/* Placeholder for real Leaflet Map */}
              <p className="text-slate-400 font-medium flex flex-col items-center gap-2">
                <Activity className="w-6 h-6 text-slate-300" />
                Map Visualization Loading...
              </p>
            </div>
            <div className="bg-blue-50 border border-blue-100 p-3 rounded-md text-xs text-blue-800 flex gap-2">
              <ShieldAlert className="w-4 h-4 text-blue-500 shrink-0" />
              <p>
                Estimated infrastructure geolocation represents network relay telemetry and does <strong>not</strong> establish the attacker's physical location.
              </p>
            </div>
          </div>

        </div>
      </div>
    </div>
  );
};
