import React, { useState } from 'react';
import { LearningSet, UserProgress } from '../types/curriculum';
import { getChapterById, getAdjacentSetIds, ALL_LEARNING_SETS } from '../data/curriculum';
import {
  CheckCircle2,
  Bookmark,
  ChevronLeft,
  ChevronRight,
  BookOpen,
  Code2,
  HelpCircle,
  ListChecks,
  Play,
  RotateCcw,
  AlertTriangle,
  ShieldCheck,
  ExternalLink,
  Layers
} from 'lucide-react';

interface LearningStudioProps {
  currentSet: LearningSet;
  progress: UserProgress;
  onSelectSet: (setId: string) => void;
  onToggleCompleted: (setId: string) => void;
  onToggleBookmark: (setId: string) => void;
  onRecordQuiz: (setId: string, selected: number, isCorrect: boolean) => void;
  onToggleChecklistItem: (setId: string, text: string) => void;
}

type StudioTab = 'theory' | 'audit-lab' | 'quiz' | 'checklist';

export const LearningStudio: React.FC<LearningStudioProps> = ({
  currentSet,
  progress,
  onSelectSet,
  onToggleCompleted,
  onToggleBookmark,
  onRecordQuiz,
  onToggleChecklistItem,
}) => {
  const [activeTab, setActiveTab] = useState<StudioTab>('theory');
  const [codeViewMode, setCodeViewMode] = useState<'side-by-side' | 'vulnerable' | 'remediated'>('side-by-side');
  const [exploitSimulated, setExploitSimulated] = useState(false);
  const [selectedQuizOption, setSelectedQuizOption] = useState<number | null>(
    progress.quizScores[currentSet.id]?.selected ?? null
  );

  const chapter = getChapterById(currentSet.chapterId);
  const { prevId, nextId } = getAdjacentSetIds(currentSet.id);
  const isCompleted = progress.completedSets.includes(currentSet.id);
  const isBookmarked = progress.bookmarkedSets.includes(currentSet.id);

  const handleQuizSelect = (index: number) => {
    setSelectedQuizOption(index);
    const isCorrect = index === currentSet.quiz.correctAnswer;
    onRecordQuiz(currentSet.id, index, isCorrect);
  };

  const handleSimulateExploit = () => {
    setExploitSimulated(true);
  };

  const resetExploit = () => {
    setExploitSimulated(false);
  };

  // Reset local state when currentSet changes
  React.useEffect(() => {
    setExploitSimulated(false);
    setSelectedQuizOption(progress.quizScores[currentSet.id]?.selected ?? null);
  }, [currentSet.id, progress.quizScores]);

  return (
    <div className="space-y-6 pb-20">
      {/* Top Header & Breadcrumb Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-xl border border-slate-800 bg-slate-900/90 shadow-md">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-slate-400 mb-1">
            <span>Chapter {currentSet.chapterId}: {chapter?.title}</span>
            <span aria-hidden="true">·</span>
            <span className="text-cyan-400 font-semibold">Set {currentSet.id}</span>
            <span aria-hidden="true">·</span>
            <span>{currentSet.duration}</span>
            {currentSet.cwe && (
              <>
                <span aria-hidden="true">·</span>
                <span className="text-amber-400">{currentSet.cwe.split(':')[0]}</span>
              </>
            )}
          </div>

          <h1 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
            {currentSet.title}
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1">
            {currentSet.summary}
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2 self-start md:self-center shrink-0">
          <button
            onClick={() => onToggleBookmark(currentSet.id)}
            className={`p-2 rounded-lg border text-xs font-medium transition-colors flex items-center gap-1.5 ${
              isBookmarked
                ? 'bg-amber-500/10 border-amber-500/40 text-amber-400'
                : 'bg-slate-800 border-slate-700 text-slate-300 hover:text-white'
            }`}
          >
            <Bookmark className="w-4 h-4" />
            <span className="hidden sm:inline">{isBookmarked ? 'Bookmarked' : 'Bookmark'}</span>
          </button>

          <button
            onClick={() => onToggleCompleted(currentSet.id)}
            className={`px-3 py-2 rounded-lg border text-xs font-semibold transition-colors flex items-center gap-1.5 ${
              isCompleted
                ? 'bg-emerald-500/20 border-emerald-500/40 text-emerald-300'
                : 'bg-cyan-500/10 border-cyan-500/30 text-cyan-300 hover:bg-cyan-500/20'
            }`}
          >
            <CheckCircle2 className="w-4 h-4" />
            <span>{isCompleted ? 'Completed' : 'Mark Complete'}</span>
          </button>

          {/* Previous / Next Navigation */}
          <div className="flex items-center gap-1 ml-2 border-l border-slate-800 pl-3">
            <button
              disabled={!prevId}
              onClick={() => prevId && onSelectSet(prevId)}
              title={prevId ? `Go to Set ${prevId}` : 'First Set'}
              className="p-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-300 hover:text-white disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <button
              disabled={!nextId}
              onClick={() => nextId && onSelectSet(nextId)}
              title={nextId ? `Go to Set ${nextId}` : 'Last Set'}
              className="p-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-300 hover:text-white disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Primary Studio Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-2 overflow-x-auto">
        <button
          onClick={() => setActiveTab('theory')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
            activeTab === 'theory'
              ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/30'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
          }`}
        >
          <BookOpen className="w-4 h-4" />
          <span>1. Architecture & Theory</span>
        </button>

        <button
          onClick={() => setActiveTab('audit-lab')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
            activeTab === 'audit-lab'
              ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/30'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
          }`}
        >
          <Code2 className="w-4 h-4" />
          <span>2. Interactive Code Audit Lab</span>
        </button>

        <button
          onClick={() => setActiveTab('quiz')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
            activeTab === 'quiz'
              ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/30'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
          }`}
        >
          <HelpCircle className="w-4 h-4" />
          <span>3. Knowledge Check</span>
          {progress.quizScores[currentSet.id] && (
            <span className="w-2 h-2 rounded-full bg-emerald-400" />
          )}
        </button>

        <button
          onClick={() => setActiveTab('checklist')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
            activeTab === 'checklist'
              ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/30'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
          }`}
        >
          <ListChecks className="w-4 h-4" />
          <span>4. Defense Checklist</span>
        </button>
      </div>

      {/* TAB 1: THEORY & ARCHITECTURE */}
      {activeTab === 'theory' && (
        <div className="space-y-6">
          {/* Architectural Diagram Spotlights for Ch 3 / 4 */}
          {currentSet.chapterId === 3 && (
            <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/70 overflow-hidden">
              <div className="flex items-center gap-2 text-xs font-semibold text-amber-400 mb-2">
                <Layers className="w-4 h-4" />
                <span>Threat Modeling Architecture: Trust Boundaries & Adversary Vectors</span>
              </div>
              <img
                src="/src/assets/images/diagram_threat_modeling_1791566730542.jpg"
                alt="Threat modeling trust boundaries diagram"
                className="w-full max-h-96 object-contain rounded-lg border border-slate-800 bg-slate-950"
                referrerPolicy="no-referrer"
              />
            </div>
          )}

          {currentSet.chapterId === 4 && (
            <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/70 overflow-hidden">
              <div className="flex items-center gap-2 text-xs font-semibold text-cyan-400 mb-2">
                <Layers className="w-4 h-4" />
                <span>Layered Defense-in-Depth Security Rings Blueprint</span>
              </div>
              <img
                src="/src/assets/images/diagram_defense_in_depth_1791566743891.jpg"
                alt="Defense in depth security rings diagram"
                className="w-full max-h-96 object-contain rounded-lg border border-slate-800 bg-slate-950"
                referrerPolicy="no-referrer"
              />
            </div>
          )}

          {/* Deep Concept Blocks */}
          <div className="grid grid-cols-1 gap-6">
            {currentSet.concepts.map((concept, idx) => (
              <div
                key={idx}
                className="p-6 rounded-xl border border-slate-800 bg-slate-900/70 space-y-3"
              >
                <h3 className="text-base sm:text-lg font-bold text-white flex items-center gap-2">
                  <span className="w-6 h-6 rounded-md bg-cyan-500/10 text-cyan-400 text-xs flex items-center justify-center font-mono">
                    {idx + 1}
                  </span>
                  <span>{concept.title}</span>
                </h3>

                <p className="text-sm text-slate-300 leading-relaxed">
                  {concept.content}
                </p>

                {concept.bulletPoints && concept.bulletPoints.length > 0 && (
                  <ul className="space-y-1.5 pt-2 border-t border-slate-800/80">
                    {concept.bulletPoints.map((pt, pIdx) => (
                      <li key={pIdx} className="text-xs text-slate-400 flex items-start gap-2">
                        <span className="text-cyan-400 mt-1 font-bold">›</span>
                        <span>{pt}</span>
                      </li>
                    ))}
                  </ul>
                )}

                {concept.keyPrinciple && (
                  <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 text-xs text-cyan-300 font-medium">
                    <span className="text-slate-400 font-semibold mr-1.5">Architectural Invariant:</span>
                    {concept.keyPrinciple}
                  </div>
                )}
              </div>
            ))}
          </div>

          {/* Vulnerability Anatomy Card */}
          <div className="p-6 rounded-xl border border-rose-900/40 bg-gradient-to-br from-slate-950 via-slate-900 to-rose-950/20 space-y-4">
            <div className="flex items-center gap-2 text-rose-400 font-bold text-sm">
              <AlertTriangle className="w-4 h-4" />
              <span>Vulnerability Anatomy & Threat Vector Analysis</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="p-3.5 rounded-lg bg-slate-950/60 border border-slate-800">
                <div className="text-xs text-slate-400 font-medium mb-1">Standard / CWE Classification</div>
                <div className="text-sm font-semibold text-rose-300 font-mono">
                  {currentSet.vulnerabilityAnatomy.cweOrStandard}
                </div>
              </div>

              <div className="p-3.5 rounded-lg bg-slate-950/60 border border-slate-800">
                <div className="text-xs text-slate-400 font-medium mb-1">Real-World Threat Vector</div>
                <div className="text-sm text-slate-200">
                  {currentSet.vulnerabilityAnatomy.threatVector}
                </div>
              </div>

              <div className="p-3.5 rounded-lg bg-slate-950/60 border border-slate-800">
                <div className="text-xs text-slate-400 font-medium mb-1">Security Impact</div>
                <div className="text-sm text-slate-200">
                  {currentSet.vulnerabilityAnatomy.impact}
                </div>
              </div>

              <div className="p-3.5 rounded-lg bg-slate-950/60 border border-slate-800">
                <div className="text-xs text-slate-400 font-medium mb-1">Real-World Scenario Case</div>
                <div className="text-sm text-slate-200">
                  {currentSet.vulnerabilityAnatomy.realWorldScenario}
                </div>
              </div>
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setActiveTab('audit-lab')}
                className="px-4 py-2 text-xs font-semibold bg-cyan-400 text-slate-950 rounded-lg hover:bg-cyan-300 transition-colors flex items-center gap-2"
              >
                <span>Proceed to Code Audit Lab</span>
                <Code2 className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: INTERACTIVE CODE AUDIT LAB */}
      {activeTab === 'audit-lab' && (
        <div className="space-y-6">
          <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/80">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-2">
              <div>
                <span className="text-xs font-mono text-cyan-400 font-semibold uppercase">
                  {currentSet.codeAuditLab.language} Lab
                </span>
                <h2 className="text-lg font-bold text-white">
                  {currentSet.codeAuditLab.title}
                </h2>
              </div>

              {/* View Switcher */}
              <div className="flex items-center gap-1 p-1 bg-slate-950 rounded-lg border border-slate-800 text-xs">
                <button
                  onClick={() => setCodeViewMode('side-by-side')}
                  className={`px-2.5 py-1 rounded-md font-medium transition-colors ${
                    codeViewMode === 'side-by-side' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  Side-by-Side
                </button>
                <button
                  onClick={() => setCodeViewMode('vulnerable')}
                  className={`px-2.5 py-1 rounded-md font-medium transition-colors ${
                    codeViewMode === 'vulnerable' ? 'bg-rose-950/80 text-rose-300' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  Vulnerable Only
                </button>
                <button
                  onClick={() => setCodeViewMode('remediated')}
                  className={`px-2.5 py-1 rounded-md font-medium transition-colors ${
                    codeViewMode === 'remediated' ? 'bg-emerald-950/80 text-emerald-300' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  Remediated Only
                </button>
              </div>
            </div>

            <p className="text-sm text-slate-300">
              {currentSet.codeAuditLab.description}
            </p>
          </div>

          {/* Interactive Code Diff Stage */}
          <div
            className={`grid gap-4 ${
              codeViewMode === 'side-by-side' ? 'grid-cols-1 lg:grid-cols-2' : 'grid-cols-1'
            }`}
          >
            {/* Vulnerable Code Panel */}
            {(codeViewMode === 'side-by-side' || codeViewMode === 'vulnerable') && (
              <div className="rounded-xl border border-rose-900/50 bg-slate-950 overflow-hidden shadow-lg">
                <div className="px-4 py-2.5 bg-rose-950/40 border-b border-rose-900/50 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full bg-rose-500" />
                    <span className="text-xs font-mono font-bold text-rose-300 uppercase tracking-wider">
                      Vulnerable Implementation (Flawed)
                    </span>
                  </div>
                  <span className="text-[11px] font-mono text-slate-500">
                    {currentSet.codeAuditLab.language}
                  </span>
                </div>

                <div className="p-4 font-mono text-xs overflow-x-auto text-slate-300 leading-relaxed max-h-[460px] scrollbar-thin">
                  <pre className="whitespace-pre">
                    {currentSet.codeAuditLab.vulnerableCode}
                  </pre>
                </div>

                {/* Exploit Analysis box */}
                <div className="p-3.5 bg-rose-950/20 border-t border-rose-900/30 text-xs text-rose-200">
                  <span className="font-bold text-rose-400 mr-1.5">Vulnerability Mechanism:</span>
                  {currentSet.codeAuditLab.flawExplanation}
                </div>
              </div>
            )}

            {/* Remediated Code Panel */}
            {(codeViewMode === 'side-by-side' || codeViewMode === 'remediated') && (
              <div className="rounded-xl border border-emerald-900/50 bg-slate-950 overflow-hidden shadow-lg">
                <div className="px-4 py-2.5 bg-emerald-950/40 border-b border-emerald-900/50 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
                    <span className="text-xs font-mono font-bold text-emerald-300 uppercase tracking-wider">
                      Remediated Implementation (Secure)
                    </span>
                  </div>
                  <span className="text-[11px] font-mono text-slate-500">
                    {currentSet.codeAuditLab.language}
                  </span>
                </div>

                <div className="p-4 font-mono text-xs overflow-x-auto text-slate-300 leading-relaxed max-h-[460px] scrollbar-thin">
                  <pre className="whitespace-pre">
                    {currentSet.codeAuditLab.remediatedCode}
                  </pre>
                </div>

                {/* Secure Fix Analysis box */}
                <div className="p-3.5 bg-emerald-950/20 border-t border-emerald-900/30 text-xs text-emerald-200">
                  <span className="font-bold text-emerald-400 mr-1.5">Defensive Architecture:</span>
                  {currentSet.codeAuditLab.fixExplanation}
                </div>
              </div>
            )}
          </div>

          {/* Interactive Threat Execution Simulator */}
          <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/90 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-sm font-bold text-white">
                <Play className="w-4 h-4 text-cyan-400" />
                <span>Simulate Threat Vector Execution</span>
              </div>

              {!exploitSimulated ? (
                <button
                  onClick={handleSimulateExploit}
                  className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-cyan-400 text-slate-950 hover:bg-cyan-300 transition-colors flex items-center gap-1.5"
                >
                  <Play className="w-3.5 h-3.5" />
                  <span>Run Adversary Payload</span>
                </button>
              ) : (
                <button
                  onClick={resetExploit}
                  className="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 text-slate-300 hover:text-white transition-colors flex items-center gap-1.5"
                >
                  <RotateCcw className="w-3.5 h-3.5" />
                  <span>Reset Simulator</span>
                </button>
              )}
            </div>

            <p className="text-xs text-slate-400">
              Execute test payloads against the vulnerable versus remediated implementations to verify runtime containment.
            </p>

            {exploitSimulated && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
                {/* Vulnerable Result */}
                <div className="p-3.5 rounded-lg border border-rose-900/60 bg-rose-950/30 space-y-1.5 font-mono text-xs">
                  <div className="text-rose-400 font-bold flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse" />
                    <span>Vulnerable Version: COMPROMISED</span>
                  </div>
                  <div className="text-slate-300 text-[11px]">
                    Payload injected: <code className="text-rose-300">{currentSet.codeAuditLab.attackVectorExample || "' OR '1'='1"}</code>
                  </div>
                  <div className="text-rose-300 text-[11px] bg-slate-950/70 p-2 rounded border border-rose-900/40">
                    STATUS: 200 OK — Execution allowed. Security boundary bypassed. Data exfiltrated or corrupted.
                  </div>
                </div>

                {/* Remediated Result */}
                <div className="p-3.5 rounded-lg border border-emerald-900/60 bg-emerald-950/30 space-y-1.5 font-mono text-xs">
                  <div className="text-emerald-400 font-bold flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-emerald-500" />
                    <span>Remediated Version: DEFENDED</span>
                  </div>
                  <div className="text-slate-300 text-[11px]">
                    Payload neutralized by boundary validation & cryptographic check.
                  </div>
                  <div className="text-emerald-300 text-[11px] bg-slate-950/70 p-2 rounded border border-emerald-900/40">
                    STATUS: 400 Bad Request / 403 Forbidden — Payload rejected safely. Audit alert triggered in SIEM.
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 3: KNOWLEDGE CHECK QUIZ */}
      {activeTab === 'quiz' && (
        <div className="max-w-3xl mx-auto space-y-6">
          <div className="p-6 rounded-xl border border-slate-800 bg-slate-900/80 space-y-6">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <span className="text-xs font-mono text-cyan-400 font-semibold">
                Set {currentSet.id} Assessment
              </span>
              <span className="text-xs text-slate-400">
                Multiple Choice · Immediate Feedback
              </span>
            </div>

            <h3 className="text-base sm:text-lg font-bold text-white leading-snug">
              {currentSet.quiz.question}
            </h3>

            {/* Quiz Options */}
            <div className="space-y-3">
              {currentSet.quiz.options.map((option, optIdx) => {
                const isSelected = selectedQuizOption === optIdx;
                const isCorrect = optIdx === currentSet.quiz.correctAnswer;
                const showResults = selectedQuizOption !== null;

                let buttonClass = 'border-slate-800 bg-slate-950/60 hover:bg-slate-800/80 text-slate-200';

                if (showResults) {
                  if (isCorrect) {
                    buttonClass = 'border-emerald-500/80 bg-emerald-950/40 text-emerald-200 font-semibold';
                  } else if (isSelected && !isCorrect) {
                    buttonClass = 'border-rose-500/80 bg-rose-950/40 text-rose-200';
                  } else {
                    buttonClass = 'border-slate-800/50 bg-slate-950/30 text-slate-500';
                  }
                }

                return (
                  <button
                    key={optIdx}
                    onClick={() => handleQuizSelect(optIdx)}
                    className={`w-full text-left p-4 rounded-xl border transition-all text-sm flex items-start gap-3 ${buttonClass}`}
                  >
                    <span className="w-6 h-6 rounded-md bg-slate-800/80 text-xs font-mono flex items-center justify-center shrink-0 mt-0.5">
                      {String.fromCharCode(65 + optIdx)}
                    </span>
                    <span className="flex-1">{option}</span>
                  </button>
                );
              })}
            </div>

            {/* Explanation box after selection */}
            {selectedQuizOption !== null && (
              <div
                className={`p-4 rounded-xl border text-sm space-y-1.5 ${
                  selectedQuizOption === currentSet.quiz.correctAnswer
                    ? 'border-emerald-500/40 bg-emerald-950/30 text-emerald-200'
                    : 'border-rose-500/40 bg-rose-950/30 text-rose-200'
                }`}
              >
                <div className="font-bold flex items-center gap-1.5">
                  {selectedQuizOption === currentSet.quiz.correctAnswer ? (
                    <>
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                      <span>Correct Answer!</span>
                    </>
                  ) : (
                    <>
                      <AlertTriangle className="w-4 h-4 text-rose-400" />
                      <span>Incorrect — Review the Engineering Rationale</span>
                    </>
                  )}
                </div>
                <p className="text-xs text-slate-300 leading-relaxed">
                  {currentSet.quiz.explanation}
                </p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 4: DEFENSE CHECKLIST */}
      {activeTab === 'checklist' && (
        <div className="max-w-3xl mx-auto space-y-6">
          <div className="p-6 rounded-xl border border-slate-800 bg-slate-900/80 space-y-4">
            <div className="border-b border-slate-800 pb-3">
              <h3 className="text-base sm:text-lg font-bold text-white">
                Defensive Engineering Checklist
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Verifiable architectural and coding standards to enforce for Set {currentSet.id}.
              </p>
            </div>

            <div className="space-y-3">
              {currentSet.defenseChecklist.map((item, idx) => {
                const checkedList = progress.checkedItems[currentSet.id] || [];
                const isChecked = checkedList.includes(item);

                return (
                  <label
                    key={idx}
                    onClick={() => onToggleChecklistItem(currentSet.id, item)}
                    className="flex items-start gap-3 p-3.5 rounded-xl border border-slate-800 bg-slate-950/50 hover:bg-slate-900 cursor-pointer select-none transition-colors"
                  >
                    <input
                      type="checkbox"
                      checked={isChecked}
                      readOnly
                      className="mt-1 w-4 h-4 rounded border-slate-700 text-cyan-500 focus:ring-0 bg-slate-900"
                    />
                    <span className={`text-sm ${isChecked ? 'line-through text-slate-500' : 'text-slate-200'}`}>
                      {item}
                    </span>
                  </label>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* Bottom Set Navigation Bar */}
      <div className="flex items-center justify-between pt-6 border-t border-slate-800">
        <div>
          {prevId && (
            <button
              onClick={() => onSelectSet(prevId)}
              className="px-4 py-2 rounded-lg text-xs font-semibold bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 flex items-center gap-2"
            >
              <ChevronLeft className="w-4 h-4" />
              <span>Previous: Set {prevId}</span>
            </button>
          )}
        </div>

        <div>
          {nextId && (
            <button
              onClick={() => onSelectSet(nextId)}
              className="px-4 py-2 rounded-lg text-xs font-semibold bg-cyan-400 hover:bg-cyan-300 text-slate-950 flex items-center gap-2"
            >
              <span>Next: Set {nextId}</span>
              <ChevronRight className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
