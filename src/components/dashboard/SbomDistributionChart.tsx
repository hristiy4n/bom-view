import { FileStack } from "lucide-react";
import { BreakdownEntry } from "@/lib/dashboard-utils";
import { BreakdownBarChart } from "./BreakdownBarChart";

interface SbomDistributionChartProps {
  data: BreakdownEntry[];
}

export function SbomDistributionChart({ data }: SbomDistributionChartProps) {
  return (
    <BreakdownBarChart
      title="Packages per SBOM"
      icon={FileStack}
      data={data}
      emptyMessage="No SBOMs loaded"
      colorForEntry={() => "hsl(var(--primary))"}
    />
  );
}
