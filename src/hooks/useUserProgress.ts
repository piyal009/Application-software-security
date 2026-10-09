import { useState, useEffect } from 'react';
import { UserProgress } from '../types/curriculum';

const STORAGE_KEY = 'appsec_curriculum_progress_v1';

const defaultProgress: UserProgress = {
  completedSets: ['1.1'], // Start with first set ready/introductory
  bookmarkedSets: [],
  quizScores: {},
  checkedItems: {},
  userName: 'Application Security Engineer',
};

export function useUserProgress() {
  const [progress, setProgress] = useState<UserProgress>(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved) {
        return JSON.parse(saved);
      }
    } catch (e) {
      console.warn('Failed to load user progress from storage:', e);
    }
    return defaultProgress;
  });

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(progress));
    } catch (e) {
      console.warn('Failed to save user progress:', e);
    }
  }, [progress]);

  const toggleSetCompleted = (setId: string) => {
    setProgress((prev) => {
      const isCompleted = prev.completedSets.includes(setId);
      const updated = isCompleted
        ? prev.completedSets.filter((id) => id !== setId)
        : [...prev.completedSets, setId];
      return { ...prev, completedSets: updated };
    });
  };

  const toggleBookmark = (setId: string) => {
    setProgress((prev) => {
      const isBookmarked = prev.bookmarkedSets.includes(setId);
      const updated = isBookmarked
        ? prev.bookmarkedSets.filter((id) => id !== setId)
        : [...prev.bookmarkedSets, setId];
      return { ...prev, bookmarkedSets: updated };
    });
  };

  const recordQuizScore = (setId: string, selected: number, isCorrect: boolean) => {
    setProgress((prev) => ({
      ...prev,
      quizScores: {
        ...prev.quizScores,
        [setId]: { selected, isCorrect },
      },
    }));
  };

  const toggleChecklistItem = (setId: string, itemText: string) => {
    setProgress((prev) => {
      const currentList = prev.checkedItems[setId] || [];
      const hasItem = currentList.includes(itemText);
      const updated = hasItem
        ? currentList.filter((t) => t !== itemText)
        : [...currentList, itemText];
      return {
        ...prev,
        checkedItems: {
          ...prev.checkedItems,
          [setId]: updated,
        },
      };
    });
  };

  const setUserName = (name: string) => {
    setProgress((prev) => ({ ...prev, userName: name }));
  };

  const resetAllProgress = () => {
    setProgress({
      completedSets: ['1.1'],
      bookmarkedSets: [],
      quizScores: {},
      checkedItems: {},
      userName: progress.userName || 'Application Security Engineer',
    });
  };

  return {
    progress,
    toggleSetCompleted,
    toggleBookmark,
    recordQuizScore,
    toggleChecklistItem,
    setUserName,
    resetAllProgress,
  };
}
