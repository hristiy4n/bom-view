import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";
import { CVSS30, CVSS31 } from "@pandatix/js-cvss";
import { Severity } from "@/types/osv";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export const getCVSS = (
  severity: { type: string; score: string }[],
): number | null => {
  const cvss = severity?.find((s) => s.type === "CVSS_V3");
  if (!cvss?.score) return null;
  try {
    if (cvss.score.startsWith("CVSS:3.1")) {
      const cvssObject = new CVSS31(cvss.score);
      return cvssObject.BaseScore();
    } else if (cvss.score.startsWith("CVSS:3.0")) {
      const cvssObject = new CVSS30(cvss.score);
      return cvssObject.BaseScore();
    }
    return null;
  } catch (error) {
    console.error("Error parsing CVSS vector for:", cvss.score, error);
    return null;
  }
};

export const getSeverity = (
  severity: { type: string; score: string }[],
): Severity => {
  const cvss = getCVSS(severity);
  if (cvss === null) return "unknown";
  if (cvss >= 9.0) return "critical";
  if (cvss >= 7.0) return "high";
  if (cvss >= 4.0) return "medium";
  if (cvss > 0) return "low";
  return "unknown";
};
