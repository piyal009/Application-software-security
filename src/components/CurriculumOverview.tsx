import React, { useState, useMemo } from 'react';
import { Chapter, LearningSet, UserProgress } from '../types/curriculum';
import { getAllChapters, getSetsForChapter, ALL_LEARNING_SETS } from '../data/curriculum';
import {
  Search,
  CheckCircle2,
  Bookmark,
  ChevronDown,
  ChevronUp,
  ArrowRight,
  Shield,
  GitPullRequest,
  Crosshair,
  Layers,
  Key,
  Lock,
  FileCode,
  Binary,
  Globe,
  Server,
  Smartphone,
  Cpu,
  Code,
  Terminal,
  Clock,
  Sparkles
} from 'lucide-react';

interface CurriculumOverviewProps {
  progress: UserProgress;
  onSelectSet: (setId: string) => void;
  onToggleBookmark: (setId: string) => void;
}

const CATEGORY_TABS = [
  { id: 'all', label: 'All 75 Sets' },
  { id: 'foundations', label: 'Foundations & SDLC' },
  { id: 'threat-modeling', label: 'Threat Modeling' },
  { id: 'architecture', label: 'Architecture & Zero Trust' },
  { id: 'identity-access', label: 'Identity & Access' },
  { id: 'vulnerabilities', label: 'Injections & Validation' },
  { id: 'cryptography', label: 'Cryptography' },
  { id: 'client-api', label: 'API & Web Security' },
  { id: 'platforms', label: 'Mobile & IoT' },
  { id: 'testing-devsecops', label: 'Testing & DevSecOps' },
];

export const CurriculumOverview: React.FC<CurriculumOverviewProps> = ({
  progress,
  onSelectSet,
  onToggleBookmark,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('all');
  const [expandedChapters, setExpandedChapters] = useState<number[]>([1, 2, 3]);

  const chapters = useMemo(() => getAllChapters(), []);

  const toggleChapterExpand = (chapterId: number) => {
    setExpandedChapters((prev) =>
      prev.includes(chapterId)
        ? prev.filter((id) => id !== chapterId)
        : [...prev, chapterId]
    );
  };

  const expandAll = () => setExpandedChapters(chapters.map((c) => c.id));
  const collapseAll = () => setExpandedChapters([]);

  // Compute statistics
  const totalSets = ALL_LEARNING_SETS.length; // 75
  const completedCount = progress.completedSets.length;
  const progressPercent = Math.round((completedCount / totalSets) * 100);

  // Filtered chapters and sets
  const filteredData = useMemo(() => {
    const q = searchQuery.toLowerCase().trim();

    return chapters.map((chapter) => {
      const allChapterSets = getSetsForChapter(chapter.id);
      const filteredSets = allChapterSets.filter((set) => {
        const matchesCategory =
          selectedCategory === 'all' ||
          chapter.category === selectedCategory ||
          (selectedCategory === 'foundations' && (chapter.category === 'foundations' || chapter.category === 'lifecycle'));

        if (!matchesCategory) return false;

        if (!q) return true;
        return (
          set.title.toLowerCase().includes(q) ||
          set.id.toLowerCase().includes(q) ||
          set.summary.toLowerCase().includes(q) ||
          (set.cwe && set.cwe.toLowerCase().includes(q))
        );
      });

      return {
        chapter,
        sets: filteredSets,
        hasMatches: filteredSets.length > 0,
        completedCount: allChapterSets.filter((s) => progress.completedSets.includes(s.id)).length,
      };
    }).filter((item) => (searchQuery ? item.hasMatches : true));
  }, [chapters, selectedCategory, searchQuery, progress.completedSets]);

  const getChapterIcon = (iconName: string) => {
    const props = { className: 'w-5 h-5' };
    switch (iconName) {
      case 'Shield': return <Shield {...props} />;
      case 'GitPullRequest': return <GitPullRequest {...props} />;
      case 'Crosshair': return <Crosshair {...props} />;
      case 'Layers': return <Layers {...props} />;
      case 'Key': return <Key {...props} />;
      case 'Lock': return <Lock {...props} />;
      case 'FileCode': return <FileCode {...props} />;
      case 'Binary': return <Binary {...props} />;
      case 'Globe': return <Globe {...props} />;
      case 'Server': return <Server {...props} />;
      case 'Smartphone': return <Smartphone {...props} />;
      case 'Cpu': return <Cpu {...props} />;
      case 'Code': return <Code {...props} />;
      case 'Terminal': return <Terminal {...props} />;
      default: return <Shield {...props} />;
    }
  };

  return (
    <div className="space-y-10 pb-16">
      {/* Editorial Hero Banner */}
      <section className="relative rounded-2xl overflow-hidden border border-slate-800 bg-slate-900 shadow-xl">
        <div className="absolute inset-0 z-0">
          <img
            src="/src/assets/images/hero_appsec_curriculum_1791566717528.jpg"
            alt="Application Software Security Architecture Blueprint"
            className="w-full h-full object-cover opacity-25"
            referrerPolicy="no-referrer"
          />
          <div className="absolute inset-0 bg-gradient-to-r from-slate-950 via-slate-950/90 to-slate-950/60" />
        </div>

        <div className="relative z-10 px-6 py-12 md:py-16 md:px-12 max-w-4xl">
          <div className="flex items-center gap-2 text-xs font-semibold text-cyan-400 tracking-wide uppercase mb-3">
            <span>Engineering Master Curriculum</span>
            <span aria-hidden="true">·</span>
            <span>15 Chapters</span>
            <span aria-hidden="true">·</span>
            <span>75 Learning Sets</span>
          </div>

          <h1 className="text-3xl md:text-5xl font-extrabold tracking-tight text-white mb-4 text-balance">
            Application Software Security
          </h1>

          <p className="text-base md:text-lg text-slate-300 mb-8 leading-relaxed max-w-3xl">
            A comprehensive, production-grade syllabus covering the full lifecycle of secure software
            engineering: from threat modeling and SSDLC gates to advanced cryptography, API vulnerability auditing,
            mobile sandboxing, and DevSecOps runtime protection.
          </p>

          {/* Quick Metrics Bar */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 p-4 rounded-xl bg-slate-950/70 border border-slate-800/80 backdrop-blur-md">
            <div>
              <div className="text-xs text-slate-400 font-medium">Curriculum Scope</div>
              <div className="text-2xl font-bold text-white tabular-nums">75 Sets</div>
              <div className="text-xs text-slate-500">15 Deep Chapters</div>
            </div>
            <div>
              <div className="text-xs text-slate-400 font-medium">Your Progress</div>
              <div className="text-2xl font-bold text-cyan-400 tabular-nums">
                {completedCount} <span className="text-xs text-slate-400 font-normal">/ 75</span>
              </div>
              <div className="text-xs text-slate-500 tabular-nums">{progressPercent}% Mastered</div>
            </div>
            <div>
              <div className="text-xs text-slate-400 font-medium">Interactive Labs</div>
              <div className="text-2xl font-bold text-emerald-400 tabular-nums">75 Audits</div>
              <div className="text-xs text-slate-500">Side-by-side code fixes</div>
            </div>
            <div>
              <div className="text-xs text-slate-400 font-medium">Knowledge Checks</div>
              <div className="text-2xl font-bold text-amber-400 tabular-nums">
                {Object.keys(progress.quizScores).length} <span className="text-xs text-slate-400 font-normal">/ 75</span>
              </div>
              <div className="text-xs text-slate-500">Scenario quizzes</div>
            </div>
          </div>
        </div>
      </section>

      {/* Control Strip: Search & Category Filter */}
      <section className="space-y-4">
        <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-4">
          {/* Search Box */}
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search concepts, CWEs, CVEs, topics (e.g. JWT, SQLi, STRIDE)..."
              className="w-full pl-10 pr-4 py-2 bg-slate-900 border border-slate-800 rounded-lg text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-slate-400 hover:text-white"
              >
                Clear
              </button>
            )}
          </div>

          {/* Quick Accordion Controls */}
          <div className="flex items-center gap-2 text-xs text-slate-400 shrink-0">
            <button
              onClick={expandAll}
              className="px-3 py-1.5 rounded-md bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 transition-colors"
            >
              Expand All
            </button>
            <button
              onClick={collapseAll}
              className="px-3 py-1.5 rounded-md bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 transition-colors"
            >
              Collapse All
            </button>
          </div>
        </div>

        {/* Category Filter Tabs */}
        <div className="flex items-center gap-1.5 overflow-x-auto pb-2 scrollbar-none">
          {CATEGORY_TABS.map((tab) => {
            const isActive = selectedCategory === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setSelectedCategory(tab.id)}
                className={`px-3 py-1.5 text-xs font-medium rounded-lg whitespace-nowrap transition-colors shrink-0 ${
                  isActive
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                    : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
                }`}
              >
                {tab.label}
              </button>
            );
          })}
        </div>
      </section>

      {/* Chapters & 75 Learning Sets Grid */}
      <section className="space-y-6">
        {filteredData.length === 0 ? (
          <div className="py-16 text-center rounded-xl border border-slate-800 bg-slate-900/50">
            <Search className="w-10 h-10 text-slate-600 mx-auto mb-3" />
            <h3 className="text-base font-semibold text-slate-300 mb-1">No matching learning sets found</h3>
            <p className="text-sm text-slate-500 mb-4">Try searching for other keywords like "CWE", "OAuth", or "Defense".</p>
            <button
              onClick={() => { setSearchQuery(''); setSelectedCategory('all'); }}
              className="px-4 py-2 text-xs font-medium bg-slate-800 text-slate-200 rounded-lg hover:bg-slate-700"
            >
              Reset Filters
            </button>
          </div>
        ) : (
          filteredData.map(({ chapter, sets, completedCount }) => {
            const isExpanded = expandedChapters.includes(chapter.id);
            const isChapterMastered = completedCount === 5;

            return (
              <div
                key={chapter.id}
                className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden transition-all duration-200 hover:border-slate-700"
              >
                {/* Chapter Header */}
                <div
                  onClick={() => toggleChapterExpand(chapter.id)}
                  className="px-6 py-5 flex items-start sm:items-center justify-between gap-4 cursor-pointer select-none bg-slate-900/80 hover:bg-slate-800/60 transition-colors"
                >
                  <div className="flex items-start sm:items-center gap-4">
                    <div
                      className="w-10 h-10 rounded-lg flex items-center justify-center shrink-0 border"
                      style={{
                        backgroundColor: `${chapter.accentColor}15`,
                        borderColor: `${chapter.accentColor}40`,
                        color: chapter.accentColor,
                      }}
                    >
                      {getChapterIcon(chapter.icon)}
                    </div>

                    <div>
                      <div className="flex items-center gap-2 text-xs font-mono text-slate-400 mb-1">
                        <span>Chapter {chapter.id.toString().padStart(2, '0')}</span>
                        <span aria-hidden="true">·</span>
                        <span className="text-slate-500">{chapter.categoryLabel}</span>
                        {isChapterMastered && (
                          <>
                            <span aria-hidden="true">·</span>
                            <span className="text-emerald-400 font-sans font-medium flex items-center gap-1">
                              <CheckCircle2 className="w-3.5 h-3.5" /> Complete
                            </span>
                          </>
                        )}
                      </div>

                      <h2 className="text-base sm:text-lg font-bold text-white tracking-tight">
                        {chapter.title}
                      </h2>
                      <p className="text-xs sm:text-sm text-slate-400 mt-0.5 line-clamp-1">
                        {chapter.tagline}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 shrink-0">
                    {/* Chapter Progress */}
                    <div className="hidden sm:flex flex-col items-end">
                      <span className="text-xs font-mono tabular-nums text-slate-400">
                        {completedCount} / 5 Sets
                      </span>
                      <div className="w-20 h-1.5 bg-slate-800 rounded-full mt-1.5 overflow-hidden">
                        <div
                          className="h-full bg-cyan-400 rounded-full transition-all duration-300"
                          style={{ width: `${(completedCount / 5) * 100}%` }}
                        />
                      </div>
                    </div>

                    <div className="p-1 rounded-lg text-slate-400 hover:text-white">
                      {isExpanded ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
                    </div>
                  </div>
                </div>

                {/* Chapter Sets List */}
                {isExpanded && (
                  <div className="divide-y divide-slate-800/80 border-t border-slate-800/80 bg-slate-950/40">
                    {sets.map((set) => {
                      const isCompleted = progress.completedSets.includes(set.id);
                      const isBookmarked = progress.bookmarkedSets.includes(set.id);
                      const hasQuiz = Boolean(progress.quizScores[set.id]);

                      return (
                        <div
                          key={set.id}
                          className="px-6 py-4 flex flex-col md:flex-row md:items-center justify-between gap-3 hover:bg-slate-800/30 transition-colors"
                        >
                          <div className="flex items-start gap-3 flex-1 min-w-0">
                            {/* Checkmark Status indicator */}
                            <div className="mt-1 shrink-0">
                              {isCompleted ? (
                                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                              ) : (
                                <div className="w-4 h-4 rounded-full border border-slate-700 bg-slate-900" />
                              )}
                            </div>

                            <div className="min-w-0 flex-1">
                              <div className="flex items-center gap-2 text-xs text-slate-400 mb-0.5">
                                <span className="font-mono text-cyan-400 font-semibold">{set.id}</span>
                                <span aria-hidden="true">·</span>
                                <span className="flex items-center gap-1">
                                  <Clock className="w-3 h-3 text-slate-500" />
                                  <span>{set.duration}</span>
                                </span>
                                <span aria-hidden="true">·</span>
                                <span>{set.difficulty}</span>
                                {set.cwe && (
                                  <>
                                    <span aria-hidden="true">·</span>
                                    <span className="text-amber-400 font-mono text-[11px] truncate max-w-[200px]">
                                      {set.cwe.split(':')[0]}
                                    </span>
                                  </>
                                )}
                              </div>

                              <h3
                                onClick={() => onSelectSet(set.id)}
                                className="text-sm font-semibold text-slate-200 hover:text-cyan-300 transition-colors cursor-pointer"
                              >
                                {set.title}
                              </h3>

                              <p className="text-xs text-slate-400 mt-0.5 line-clamp-1">
                                {set.summary}
                              </p>
                            </div>
                          </div>

                          {/* Action Buttons */}
                          <div className="flex items-center gap-2 self-end md:self-center shrink-0">
                            <button
                              onClick={() => onToggleBookmark(set.id)}
                              title={isBookmarked ? 'Remove bookmark' : 'Bookmark set'}
                              className={`p-1.5 rounded-lg border transition-colors ${
                                isBookmarked
                                  ? 'bg-amber-500/10 border-amber-500/40 text-amber-400'
                                  : 'bg-slate-900 border-slate-800 text-slate-500 hover:text-slate-300'
                              }`}
                            >
                              <Bookmark className="w-4 h-4" />
                            </button>

                            <button
                              onClick={() => onSelectSet(set.id)}
                              className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-cyan-500/20 text-slate-200 hover:text-cyan-300 border border-slate-700 hover:border-cyan-500/40 transition-colors flex items-center gap-1.5"
                            >
                              <span>Study Set</span>
                              <ArrowRight className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            );
          })
        )}
      </section>
    </div>
  );
};
