import { Severity } from "@/types/osv";
import { cn } from "@/lib/utils";

interface SeverityBadgeProps {
  severity: Severity;
  className?: string;
}

const severityConfig: Record<Severity, { label: string; className: string }> = {
  critical: { label: "Critical", className: "severity-badge-critical" },
  high: { label: "High", className: "severity-badge-high" },
  medium: { label: "Medium", className: "severity-badge-medium" },
  low: { label: "Low", className: "severity-badge-low" },
  unknown: { label: "Unknown", className: "severity-badge-unknown" },
};

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  const config = severityConfig[severity];

  if (!config) {
    return null;
  }

  return (
    <span
      className={cn(
        "inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border",
        config.className,
        className,
      )}
    >
      {config.label}
    </span>
  );
}
