export interface DepsDevProjectData {
  projectKey?: {
    id?: string;
  };
  openIssuesCount?: number;
  starsCount?: number;
  forksCount?: number;
  license?: string;
  description?: string;
  homepage?: string;
  scorecard?: {
    date?: string;
    repository?: {
      name?: string;
      commit?: string;
    };
    overallScore?: number;
    version?: string;
    checks?: Array<{
      name?: string;
      score?: number;
      reason?: string;
      details?: string;
      documentation?: {
        url?: string;
      };
    }>;
  };
}
