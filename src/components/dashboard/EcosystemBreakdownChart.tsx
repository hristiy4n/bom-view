import { Boxes } from "lucide-react";
import { BreakdownEntry, UNKNOWN_ECOSYSTEM_LABEL } from "@/lib/dashboard-utils";
import { BreakdownBarChart } from "./BreakdownBarChart";

interface EcosystemBreakdownChartProps {
  data: BreakdownEntry[];
}

export function EcosystemBreakdownChart({
  data,
}: EcosystemBreakdownChartProps) {
  return (
    <BreakdownBarChart
      title="Packages by Ecosystem"
      icon={Boxes}
      data={data}
      emptyMessage="No ecosystem data available"
      colorForEntry={(entry) =>
        entry.label === UNKNOWN_ECOSYSTEM_LABEL
          ? "hsl(var(--muted-foreground))"
          : "hsl(var(--primary))"
      }
    />
  );
}
