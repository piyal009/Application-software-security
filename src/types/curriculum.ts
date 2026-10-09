export type ChapterCategory =
  | 'foundations'
  | 'lifecycle'
  | 'threat-modeling'
  | 'architecture'
  | 'identity-access'
  | 'vulnerabilities'
  | 'cryptography'
  | 'client-api'
  | 'platforms'
  | 'testing-devsecops';

export interface Chapter {
  id: number;
  title: string;
  tagline: string;
  description: string;
  category: ChapterCategory;
  categoryLabel: string;
  badge: string;
  accentColor: string;
  icon: string;
}

export interface ConceptBlock {
  title: string;
  content: string;
  keyPrinciple?: string;
  bulletPoints?: string[];
}

export interface VulnerabilityAnatomy {
  threatVector: string;
  cweOrStandard: string;
  impact: string;
  realWorldScenario: string;
}

export interface CodeAuditLab {
  language: string;
  title: string;
  description: string;
  vulnerableCode: string;
  remediatedCode: string;
  flawExplanation: string;
  fixExplanation: string;
  attackVectorExample?: string;
}

export interface QuizQuestion {
  question: string;
  options: string[];
  correctAnswer: number;
  explanation: string;
}

export interface LearningSet {
  id: string; // e.g. "1.1", "1.2", ... "15.5"
  chapterId: number;
  setIndex: number; // 1 to 5
  title: string;
  summary: string;
  domain: ChapterCategory;
  duration: string;
  difficulty: 'Fundamental' | 'Intermediate' | 'Advanced';
  cwe?: string;
  owaspTop10?: string;
  concepts: ConceptBlock[];
  vulnerabilityAnatomy: VulnerabilityAnatomy;
  codeAuditLab: CodeAuditLab;
  quiz: QuizQuestion;
  defenseChecklist: string[];
}

export interface UserProgress {
  completedSets: string[]; // array of set IDs
  bookmarkedSets: string[];
  quizScores: Record<string, { selected: number; isCorrect: boolean }>;
  checkedItems: Record<string, string[]>; // set id -> checklist items
  userName: string;
}
