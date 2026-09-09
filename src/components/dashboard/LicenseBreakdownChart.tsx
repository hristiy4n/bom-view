import { Scale } from "lucide-react";
import { BreakdownEntry, UNKNOWN_LICENSE_LABEL } from "@/lib/dashboard-utils";
import { BreakdownBarChart } from "./BreakdownBarChart";

interface LicenseBreakdownChartProps {
  data: BreakdownEntry[];
}

export function LicenseBreakdownChart({ data }: LicenseBreakdownChartProps) {
  return (
    <BreakdownBarChart
      title="Packages by License"
      icon={Scale}
      data={data}
      emptyMessage="No license data available"
      colorForEntry={(entry) =>
        entry.label === UNKNOWN_LICENSE_LABEL
          ? "hsl(var(--muted-foreground))"
          : "hsl(var(--primary))"
      }
    />
  );
}
