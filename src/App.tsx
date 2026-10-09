/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { Navbar, ActiveTab } from './components/Navbar';
import { CurriculumOverview } from './components/CurriculumOverview';
import { LearningStudio } from './components/LearningStudio';
import { ThreatModelingSandbox } from './components/ThreatModelingSandbox';
import { AuditPlayground } from './components/AuditPlayground';
import { MasteryCertificate } from './components/MasteryCertificate';
import { useUserProgress } from './hooks/useUserProgress';
import { getLearningSetById, ALL_LEARNING_SETS } from './data/curriculum';

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('overview');
  const [selectedSetId, setSelectedSetId] = useState<string>('1.1');

  const {
    progress,
    toggleSetCompleted,
    toggleBookmark,
    recordQuizScore,
    toggleChecklistItem,
    setUserName,
    resetAllProgress,
  } = useUserProgress();

  const handleSelectSet = (setId: string) => {
    setSelectedSetId(setId);
    setActiveTab('studio');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const currentSet = getLearningSetById(selectedSetId) || ALL_LEARNING_SETS[0];

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      {/* Top Navigation conforming to Top Bar Contract */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        completedCount={progress.completedSets.length}
        totalSets={ALL_LEARNING_SETS.length}
      />

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 pt-8">
        {activeTab === 'overview' && (
          <CurriculumOverview
            progress={progress}
            onSelectSet={handleSelectSet}
            onToggleBookmark={toggleBookmark}
          />
        )}

        {activeTab === 'studio' && (
          <LearningStudio
            currentSet={currentSet}
            progress={progress}
            onSelectSet={handleSelectSet}
            onToggleCompleted={toggleSetCompleted}
            onToggleBookmark={toggleBookmark}
            onRecordQuiz={recordQuizScore}
            onToggleChecklistItem={toggleChecklistItem}
          />
        )}

        {activeTab === 'threat-sandbox' && (
          <ThreatModelingSandbox />
        )}

        {activeTab === 'audit-lab' && (
          <AuditPlayground />
        )}

        {activeTab === 'certificate' && (
          <MasteryCertificate
            progress={progress}
            onUpdateUserName={setUserName}
            onResetProgress={resetAllProgress}
          />
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/80 py-8 px-4 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-slate-400">AppSec Master</span>
            <span aria-hidden="true">·</span>
            <span>15 Chapters</span>
            <span aria-hidden="true">·</span>
            <span>75 Learning Sets</span>
          </div>

          <div className="flex items-center gap-4 text-slate-400">
            <span>Aligned with OWASP Top 10</span>
            <span aria-hidden="true">·</span>
            <span>CWE / SANS Top 25</span>
            <span aria-hidden="true">·</span>
            <span>NIST SP 800-207 Zero Trust</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
