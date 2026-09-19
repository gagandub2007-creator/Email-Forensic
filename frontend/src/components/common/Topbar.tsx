import React from 'react';
import { Search, Bell, HelpCircle, User, ChevronRight } from 'lucide-react';

export const Topbar: React.FC = () => {
  return (
    <header className="h-16 bg-white border-b border-slate-200 flex items-center justify-between px-6 shrink-0">
      <div className="flex items-center text-sm">
        <span className="text-slate-500">Workspace</span>
        <ChevronRight className="w-4 h-4 text-slate-300 mx-1" />
        <span className="text-slate-500">Investigations</span>
        <ChevronRight className="w-4 h-4 text-slate-300 mx-1" />
        <span className="font-semibold text-primary bg-blue-50 px-2 py-0.5 rounded text-xs">INV-1024</span>
      </div>

      <div className="flex-1 max-w-2xl px-8">
        <div className="relative">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            placeholder="Search IOCs, hashes, case IDs, sender domains..."
            className="w-full pl-9 pr-4 py-2 bg-slate-50 border border-slate-200 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-primary/20 focus:border-primary transition-all"
          />
          <div className="absolute right-3 top-1/2 -translate-y-1/2 flex items-center gap-1">
            <kbd className="px-1.5 py-0.5 text-[10px] font-semibold text-slate-400 bg-white border border-slate-200 rounded">⌘</kbd>
            <kbd className="px-1.5 py-0.5 text-[10px] font-semibold text-slate-400 bg-white border border-slate-200 rounded">K</kbd>
          </div>
        </div>
      </div>

      <div className="flex items-center gap-4">
        <button className="bg-primary hover:bg-primary-hover text-white px-4 py-2 rounded-md text-sm font-medium transition-colors">
          + New Case
        </button>
        <button className="flex items-center gap-2 border border-slate-200 hover:bg-slate-50 text-slate-700 px-4 py-2 rounded-md text-sm font-medium transition-colors">
          Export STIX 2.1
        </button>
        <div className="flex items-center gap-3 ml-2 border-l border-slate-200 pl-4">
          <button className="text-slate-400 hover:text-slate-600 relative">
            <Bell className="w-5 h-5" />
            <span className="absolute 0 right-0 w-2 h-2 bg-red-500 rounded-full border-2 border-white"></span>
          </button>
          <button className="text-slate-400 hover:text-slate-600">
            <HelpCircle className="w-5 h-5" />
          </button>
          <button className="bg-slate-100 text-slate-600 hover:bg-slate-200 p-1.5 rounded-full transition-colors">
            <User className="w-5 h-5" />
          </button>
        </div>
      </div>
    </header>
  );
};
