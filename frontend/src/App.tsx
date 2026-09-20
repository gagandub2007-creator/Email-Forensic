import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { Sidebar } from './components/common/Sidebar';
import { Topbar } from './components/common/Topbar';
import { Dashboard } from './features/dashboard/Dashboard';
import { AnalyzeEmail } from './features/analyze/AnalyzeEmail';

import { InvestigationWorkspace } from './features/investigation/InvestigationWorkspace';
import { CasesManager } from './features/cases/CasesManager';

// Stub components for other routes
const Reports = () => <div className="p-6 text-slate-500">Reports Placeholder</div>;

const AppLayout: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <div className="flex h-screen bg-slate-50 overflow-hidden">
    <Sidebar />
    <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
      <Topbar />
      <main className="flex-1 overflow-y-auto p-6">
        {children}
      </main>
    </div>
  </div>
);

function App() {
  return (
    <Router>
      <AppLayout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/analyze" element={<AnalyzeEmail />} />
          <Route path="/investigations" element={<Navigate to="/" replace />} />
          <Route path="/investigations/:id" element={<InvestigationWorkspace />} />
          <Route path="/cases" element={<CasesManager />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AppLayout>
    </Router>
  );
}

export default App;
