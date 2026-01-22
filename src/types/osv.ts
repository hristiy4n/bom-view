export type Severity = "critical" | "high" | "medium" | "low" | "unknown";

export interface OSVulnerability {
  id: string;
  summary: string;
  details: string;
  aliases: string[];
  modified: string;
  published: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  database_specific: any;
  references: { type: string; url: string }[];
  affected: {
    package: {
      name: string;
      ecosystem: string;
    };
    versions: string[];
  }[];
  severity: {
    type: string;
    score: string;
  }[];
}

export interface OSVResponse {
  vulns: OSVulnerability[];
}
