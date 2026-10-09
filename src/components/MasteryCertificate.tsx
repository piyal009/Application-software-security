import React, { useState } from 'react';
import { UserProgress } from '../types/curriculum';
import { getAllChapters, ALL_LEARNING_SETS } from '../data/curriculum';
import { Award, Printer, Download, CheckCircle2, Copy, Shield, Sparkles, FileText, RotateCcw } from 'lucide-react';

interface MasteryCertificateProps {
  progress: UserProgress;
  onUpdateUserName: (name: string) => void;
  onResetProgress: () => void;
}

export const MasteryCertificate: React.FC<MasteryCertificateProps> = ({
  progress,
  onUpdateUserName,
  onResetProgress,
}) => {
  const [isEditingName, setIsEditingName] = useState(false);
  const [copiedSyllabus, setCopiedSyllabus] = useState(false);
  const [showResetConfirm, setShowResetConfirm] = useState(false);

  const chapters = getAllChapters();
  const totalSets = ALL_LEARNING_SETS.length; // 75
  const completedCount = progress.completedSets.length;
  const progressPercent = Math.round((completedCount / totalSets) * 100);

  const certificateId = `SEC-2026-75-${(progress.userName.length * 997 + completedCount * 1337).toString(16).toUpperCase().padStart(8, '0')}`;
  const currentDate = new Date().toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });

  const handlePrint = () => {
    window.print();
  };

  const handleCopySyllabus = () => {
    let md = `# Application Software Security Curriculum\n15 Chapters × 5 Sets = 75 Learning Sets\n\n`;

    chapters.forEach((ch) => {
      md += `## Chapter ${ch.id}: ${ch.title}\n*${ch.tagline}*\n\n`;
      const sets = ALL_LEARNING_SETS.filter((s) => s.chapterId === ch.id);
      sets.forEach((s) => {
        const isDone = progress.completedSets.includes(s.id) ? '[x]' : '[ ]';
        md += `- ${isDone} Set ${s.id}: ${s.title} (${s.duration}, ${s.cwe || 'Core Standard'})\n`;
      });
      md += `\n`;
    });

    navigator.clipboard.writeText(md);
    setCopiedSyllabus(true);
    setTimeout(() => setCopiedSyllabus(false), 3000);
  };

  return (
    <div className="space-y-10 pb-20">
      {/* Intro Header */}
      <div className="p-6 rounded-xl border border-slate-800 bg-slate-900/80 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 font-semibold uppercase">
            <Award className="w-4 h-4" />
            <span>Curriculum Certification & Syllabus</span>
          </div>
          <h1 className="text-2xl font-bold text-white tracking-tight mt-1">
            Mastery Credential & Complete Syllabus
          </h1>
          <p className="text-sm text-slate-300 mt-1">
            Current completion: <span className="text-cyan-400 font-bold tabular-nums">{completedCount} of {totalSets} Sets ({progressPercent}%)</span>.
          </p>
        </div>

        <div className="flex items-center gap-3 shrink-0">
          <button
            onClick={handleCopySyllabus}
            className="px-3 py-2 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors flex items-center gap-1.5"
          >
            {copiedSyllabus ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
            <span>{copiedSyllabus ? 'Syllabus Copied!' : 'Export Syllabus (Markdown)'}</span>
          </button>

          <button
            onClick={handlePrint}
            className="px-4 py-2 rounded-lg text-xs font-semibold bg-cyan-400 hover:bg-cyan-300 text-slate-950 transition-colors flex items-center gap-1.5 shadow-sm"
          >
            <Printer className="w-4 h-4" />
            <span>Print Certificate</span>
          </button>
        </div>
      </div>

      {/* Official Certificate Canvas Frame */}
      <div className="print:m-0 print:border-none print:shadow-none bg-gradient-to-b from-slate-900 to-slate-950 rounded-2xl border-2 border-amber-500/30 p-8 sm:p-12 shadow-2xl relative overflow-hidden">
        {/* Subtle decorative security background patterns */}
        <div className="absolute inset-0 opacity-5 pointer-events-none bg-[radial-gradient(#38bdf8_1px,transparent_1px)] [background-size:16px_16px]" />

        <div className="relative z-10 max-w-3xl mx-auto text-center space-y-6">
          {/* Certificate Badge Lockup */}
          <div className="flex justify-center">
            <div className="w-16 h-16 rounded-2xl bg-amber-500/10 border-2 border-amber-500/40 flex items-center justify-center text-amber-400 shadow-lg shadow-amber-500/10">
              <Award className="w-9 h-9" />
            </div>
          </div>

          <div className="space-y-1">
            <div className="text-xs font-mono tracking-widest text-amber-400 uppercase font-semibold">
              Certificate of Curriculum Completion
            </div>
            <h2 className="text-2xl sm:text-4xl font-extrabold tracking-tight text-white font-serif">
              Application Software Security Engineering
            </h2>
            <div className="text-xs text-slate-400 tracking-wider uppercase font-mono">
              75-Set Master Syllabus & Hands-On Code Audits
            </div>
          </div>

          <div className="text-sm text-slate-300">
            This certifies that
          </div>

          {/* Student Name */}
          <div className="py-2">
            {isEditingName ? (
              <div className="flex items-center justify-center gap-2">
                <input
                  type="text"
                  value={progress.userName}
                  onChange={(e) => onUpdateUserName(e.target.value)}
                  className="px-4 py-1.5 bg-slate-950 border border-cyan-500 rounded-lg text-lg sm:text-2xl font-bold text-center text-white focus:outline-none"
                  autoFocus
                />
                <button
                  onClick={() => setIsEditingName(false)}
                  className="px-3 py-1.5 bg-cyan-400 text-slate-950 text-xs font-bold rounded-lg"
                >
                  Save
                </button>
              </div>
            ) : (
              <div
                onClick={() => setIsEditingName(true)}
                title="Click to edit recipient name"
                className="text-2xl sm:text-3xl font-bold text-cyan-300 border-b border-dashed border-cyan-500/50 inline-block px-4 pb-1 cursor-pointer hover:text-cyan-200 transition-colors"
              >
                {progress.userName}
              </div>
            )}
          </div>

          <p className="text-xs sm:text-sm text-slate-300 max-w-xl mx-auto leading-relaxed">
            has completed the structured curriculum spanning 15 comprehensive chapters in application software
            security, encompassing foundational CIA risk modeling, SSDLC gates, STRIDE threat analysis,
            zero-trust architecture, advanced cryptographic engineering, web/API injection defense, mobile platform
            hardening, and DevSecOps runtime protection.
          </p>

          {/* 15 Chapters Verified Grid */}
          <div className="pt-4 border-t border-slate-800/80">
            <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider mb-3">
              Mastered Curriculum Domains
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-left text-[11px] text-slate-300 font-mono">
              {chapters.map((ch) => (
                <div key={ch.id} className="flex items-center gap-1.5 truncate">
                  <span className="text-amber-400">✓</span>
                  <span className="truncate">Ch {ch.id}: {ch.title.split(' ')[0]} {ch.title.split(' ')[1] || ''}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Certificate Footer Stamp & ID */}
          <div className="pt-6 border-t border-slate-800/80 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs font-mono text-slate-500">
            <div>
              <span>Date: </span>
              <span className="text-slate-300">{currentDate}</span>
            </div>
            <div>
              <span>Verification ID: </span>
              <span className="text-amber-400/90 font-bold">{certificateId}</span>
            </div>
            <div className="flex items-center gap-1 text-slate-400">
              <Shield className="w-3.5 h-3.5 text-cyan-400" />
              <span>AppSec Master Accredited</span>
            </div>
          </div>
        </div>
      </div>

      {/* Comprehensive 15-Chapter Curriculum Reference Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-white font-bold text-base">
            <FileText className="w-4 h-4 text-cyan-400" />
            <span>Complete 15-Chapter Syllabus Matrix (75 Sets)</span>
          </div>

          <button
            onClick={() => setShowResetConfirm(true)}
            className="text-xs text-rose-400 hover:text-rose-300 flex items-center gap-1 transition-colors"
          >
            <RotateCcw className="w-3 h-3" />
            <span>Reset Progress</span>
          </button>
        </div>

        <div className="space-y-4 pt-2">
          {chapters.map((ch) => {
            const sets = ALL_LEARNING_SETS.filter((s) => s.chapterId === ch.id);
            return (
              <div key={ch.id} className="p-4 rounded-lg bg-slate-950/70 border border-slate-800/80 space-y-2">
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="font-bold text-white">Chapter {ch.id}: {ch.title}</span>
                  <span className="text-slate-500">{ch.categoryLabel}</span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-5 gap-2 pt-1">
                  {sets.map((s) => {
                    const isDone = progress.completedSets.includes(s.id);
                    return (
                      <div
                        key={s.id}
                        className={`p-2 rounded border text-xs flex items-center gap-1.5 ${
                          isDone
                            ? 'bg-emerald-950/30 border-emerald-900/50 text-emerald-200'
                            : 'bg-slate-900/60 border-slate-800 text-slate-400'
                        }`}
                      >
                        <span className="font-mono text-cyan-400 font-semibold">{s.id}</span>
                        <span className="truncate">{s.title.split(',')[0]}</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Reset Confirmation Dialog */}
      {showResetConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-sm p-4">
          <div className="max-w-md w-full p-6 rounded-xl border border-rose-900 bg-slate-900 space-y-4 shadow-2xl">
            <h3 className="text-lg font-bold text-white">Reset Learning Progress?</h3>
            <p className="text-sm text-slate-300">
              This will reset all 75 completion checkmarks, quiz scores, and bookmarks back to default. This action cannot be undone.
            </p>
            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                onClick={() => setShowResetConfirm(false)}
                className="px-4 py-2 rounded-lg text-xs font-medium bg-slate-800 text-slate-300 hover:text-white"
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  onResetProgress();
                  setShowResetConfirm(false);
                }}
                className="px-4 py-2 rounded-lg text-xs font-bold bg-rose-600 hover:bg-rose-500 text-white"
              >
                Reset Everything
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
