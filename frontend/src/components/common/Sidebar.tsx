import React from 'react';
import { NavLink } from 'react-router-dom';
import { LayoutDashboard, Mail, Search, Folder, FileText, Settings, UserCircle, ShieldCheck } from 'lucide-react';

export const Sidebar: React.FC = () => {
  const navItems = [
    { name: 'Dashboard', path: '/', icon: LayoutDashboard },
    { name: 'Analyze Email', path: '/analyze', icon: Mail },
    { name: 'Investigations', path: '/investigations', icon: Search, badge: '12' },
    { name: 'Cases', path: '/cases', icon: Folder },
    { name: 'Reports', path: '/reports', icon: FileText },
  ];

  return (
    <aside className="w-64 bg-white border-r border-slate-200 flex flex-col h-full">
      <div className="p-5 flex items-center gap-3 border-b border-slate-100">
        <ShieldCheck className="w-7 h-7 text-primary" />
        <div>
          <h2 className="font-bold text-slate-800 text-lg leading-tight tracking-tight">MailTrace <span className="text-primary">AI</span></h2>
          <p className="text-[10px] uppercase text-slate-500 font-semibold tracking-wider">DFIR Workstation</p>
        </div>
      </div>
      
      <div className="p-4 uppercase text-xs font-semibold text-slate-400 tracking-wider">
        Investigations
      </div>

      <nav className="flex-1 px-3 space-y-1">
        {navItems.map((item) => (
          <NavLink
            key={item.name}
            to={item.path}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2.5 rounded-md text-sm font-medium transition-colors ${
                isActive
                  ? 'bg-blue-50 text-primary'
                  : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900'
              }`
            }
          >
            <item.icon className="w-5 h-5" />
            <span className="flex-1">{item.name}</span>
            {item.badge && (
              <span className="bg-slate-100 text-slate-600 text-xs font-semibold px-2 py-0.5 rounded-full">
                {item.badge}
              </span>
            )}
          </NavLink>
        ))}
      </nav>

      <div className="p-4 border-t border-slate-200 space-y-1">
        <NavLink to="/settings" className="flex items-center gap-3 px-3 py-2.5 rounded-md text-sm font-medium text-slate-600 hover:bg-slate-50 hover:text-slate-900">
          <Settings className="w-5 h-5" />
          Settings
        </NavLink>
        <div className="flex items-center gap-3 px-3 py-2.5 mt-2 bg-slate-50 rounded-md border border-slate-200">
          <UserCircle className="w-8 h-8 text-slate-400" />
          <div className="flex-1 min-w-0">
            <p className="text-sm font-medium text-slate-900 truncate">Marcus K.</p>
            <p className="text-xs text-slate-500 truncate">SOC L2 Analyst</p>
          </div>
        </div>
      </div>
    </aside>
  );
};
