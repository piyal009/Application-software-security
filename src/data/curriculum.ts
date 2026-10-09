import { Chapter, LearningSet } from '../types/curriculum';
import { CHAPTERS } from './chapters';
import { SETS_CHAPTER_1_3 } from './setsChapter1_3';
import { SETS_CHAPTER_4_6 } from './setsChapter4_6';
import { SETS_CHAPTER_7_9 } from './setsChapter7_9';
import { SETS_CHAPTER_10_12 } from './setsChapter10_12';
import { SETS_CHAPTER_13_15 } from './setsChapter13_15';

export const ALL_LEARNING_SETS: LearningSet[] = [
  ...SETS_CHAPTER_1_3,
  ...SETS_CHAPTER_4_6,
  ...SETS_CHAPTER_7_9,
  ...SETS_CHAPTER_10_12,
  ...SETS_CHAPTER_13_15,
];

export function getAllChapters(): Chapter[] {
  return CHAPTERS;
}

export function getChapterById(id: number): Chapter | undefined {
  return CHAPTERS.find((c) => c.id === id);
}

export function getSetsForChapter(chapterId: number): LearningSet[] {
  return ALL_LEARNING_SETS.filter((s) => s.chapterId === chapterId);
}

export function getLearningSetById(id: string): LearningSet | undefined {
  return ALL_LEARNING_SETS.find((s) => s.id === id);
}

export function getAdjacentSetIds(currentId: string): { prevId: string | null; nextId: string | null } {
  const index = ALL_LEARNING_SETS.findIndex((s) => s.id === currentId);
  if (index === -1) return { prevId: null, nextId: null };
  const prevId = index > 0 ? ALL_LEARNING_SETS[index - 1].id : null;
  const nextId = index < ALL_LEARNING_SETS.length - 1 ? ALL_LEARNING_SETS[index + 1].id : null;
  return { prevId, nextId };
}

export function searchLearningSets(query: string, categoryFilter?: string): LearningSet[] {
  const q = query.trim().toLowerCase();
  return ALL_LEARNING_SETS.filter((set) => {
    if (categoryFilter && categoryFilter !== 'all') {
      const chapter = getChapterById(set.chapterId);
      if (chapter && chapter.category !== categoryFilter) {
        return false;
      }
    }

    if (!q) return true;

    return (
      set.id.toLowerCase().includes(q) ||
      set.title.toLowerCase().includes(q) ||
      set.summary.toLowerCase().includes(q) ||
      (set.cwe && set.cwe.toLowerCase().includes(q)) ||
      set.codeAuditLab.title.toLowerCase().includes(q) ||
      set.concepts.some((c) => c.title.toLowerCase().includes(q) || c.content.toLowerCase().includes(q))
    );
  });
}
