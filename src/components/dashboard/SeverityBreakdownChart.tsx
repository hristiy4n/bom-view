import { ShieldAlert } from "lucide-react";
import { Severity } from "@/types/osv";
import { BreakdownEntry } from "@/lib/dashboard-utils";
import { BreakdownBarChart } from "./BreakdownBarChart";

interface SeverityBreakdownChartProps {
  counts: Record<Severity, number>;
}

const severityOrder: { key: Severity; label: string; colorVar: string }[] = [
  { key: "critical", label: "Critical", colorVar: "--severity-critical" },
  { key: "high", label: "High", colorVar: "--severity-high" },
  { key: "medium", label: "Medium", colorVar: "--severity-medium" },
  { key: "low", label: "Low", colorVar: "--severity-low" },
  { key: "unknown", label: "Unknown", colorVar: "--severity-info" },
];

export function SeverityBreakdownChart({
  counts,
}: SeverityBreakdownChartProps) {
  const data: BreakdownEntry[] = severityOrder
    .map(({ label, key }) => ({ label, count: counts[key] }))
    .filter((entry) => entry.count > 0);

  const colorByLabel = new Map(
    severityOrder.map(({ label, colorVar }) => [label, colorVar]),
  );

  return (
    <BreakdownBarChart
      title="Vulnerabilities by Severity"
      icon={ShieldAlert}
      data={data}
      emptyMessage="No scanned vulnerabilities yet"
      colorForEntry={(entry) =>
        `hsl(var(${colorByLabel.get(entry.label) ?? "--severity-info"}))`
      }
    />
  );
}
