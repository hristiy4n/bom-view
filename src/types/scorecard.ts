export interface Scorecard {
  date: string;
  repo: {
    name: string;
    commit: string;
  };
  score: number;
  checks: ScorecardCheck[];
}

export interface ScorecardCheck {
  name: string;
  score: number;
  reason: string;
  details: string[];
  documentation: {
    short: string;
    url: string;
  };
}
