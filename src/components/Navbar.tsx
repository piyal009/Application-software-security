import React from 'react';
import { ShieldCheck, BookOpen, Layers, Terminal, Award } from 'lucide-react';

export type ActiveTab = 'overview' | 'studio' | 'threat-sandbox' | 'audit-lab' | 'certificate';

interface NavbarProps {
  activeTab: ActiveTab;
  setActiveTab: (tab: ActiveTab) => void;
  completedCount: number;
  totalSets: number;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  completedCount,
  totalSets,
}) => {
  const percent = Math.round((completedCount / totalSets) * 100);

  return (
    <header className="sticky top-0 z-50 bg-slate-950/90 backdrop-blur-md border-b border-slate-800">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between gap-8 h-16">
          {/* Zone 1: Single text element wordmark */}
          <button
            onClick={() => setActiveTab('overview')}
            className="flex items-center gap-2.5 text-lg font-bold tracking-tight text-white whitespace-nowrap shrink-0 hover:text-cyan-400 transition-colors"
          >
            <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <span>AppSec Master</span>
          </button>

          {/* Zone 2: 4-5 concise single-line text navigation links */}
          <nav className="hidden md:flex items-center gap-6 text-sm font-medium">
            <button
              onClick={() => setActiveTab('overview')}
              className={`transition-colors whitespace-nowrap shrink-0 pb-1 border-b-2 ${
                activeTab === 'overview'
                  ? 'border-cyan-400 text-white font-semibold'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              Curriculum (75 Sets)
            </button>

            <button
              onClick={() => setActiveTab('studio')}
              className={`transition-colors whitespace-nowrap shrink-0 pb-1 border-b-2 ${
                activeTab === 'studio'
                  ? 'border-cyan-400 text-white font-semibold'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              Learning Studio
            </button>

            <button
              onClick={() => setActiveTab('threat-sandbox')}
              className={`transition-colors whitespace-nowrap shrink-0 pb-1 border-b-2 ${
                activeTab === 'threat-sandbox'
                  ? 'border-cyan-400 text-white font-semibold'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              STRIDE Sandbox
            </button>

            <button
              onClick={() => setActiveTab('audit-lab')}
              className={`transition-colors whitespace-nowrap shrink-0 pb-1 border-b-2 ${
                activeTab === 'audit-lab'
                  ? 'border-cyan-400 text-white font-semibold'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              Audit Playground
            </button>

            <button
              onClick={() => setActiveTab('certificate')}
              className={`transition-colors whitespace-nowrap shrink-0 pb-1 border-b-2 ${
                activeTab === 'certificate'
                  ? 'border-cyan-400 text-white font-semibold'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              Certificate & Syllabus
            </button>
          </nav>

          {/* Zone 3: 1 primary action */}
          <div className="flex items-center gap-3 shrink-0">
            <button
              onClick={() => setActiveTab('studio')}
              className="px-4 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 rounded-lg hover:bg-cyan-300 transition-colors whitespace-nowrap shrink-0 shadow-sm shadow-cyan-500/20"
            >
              Resume Learning ({percent}%)
            </button>
          </div>
        </div>
      </div>
    </header>
  );
};
