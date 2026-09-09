import {
  Bar,
  BarChart,
  Cell,
  LabelList,
  ResponsiveContainer,
  Tooltip,
  TooltipProps,
  XAxis,
  YAxis,
} from "recharts";
import { LucideIcon } from "lucide-react";
import { BreakdownEntry } from "@/lib/dashboard-utils";

interface BreakdownBarChartProps {
  title: string;
  icon: LucideIcon;
  data: BreakdownEntry[];
  colorForEntry: (entry: BreakdownEntry) => string;
  emptyMessage?: string;
}

function ChartTooltip({ active, payload }: TooltipProps<number, string>) {
  if (!active || !payload || payload.length === 0) return null;
  const entry = payload[0].payload as BreakdownEntry;

  return (
    <div className="rounded-md border border-border bg-popover px-3 py-2 shadow-lg">
      <p className="text-sm font-semibold text-foreground">{entry.count}</p>
      <p className="text-xs text-muted-foreground">{entry.label}</p>
    </div>
  );
}

export function BreakdownBarChart({
  title,
  icon: Icon,
  data,
  colorForEntry,
  emptyMessage = "No data available",
}: BreakdownBarChartProps) {
  const rowHeight = 32;
  const chartHeight = Math.max(data.length * rowHeight, rowHeight * 2);

  return (
    <div
      className="surface-elevated rounded-lg border border-border p-4 select-none [&_*]:!outline-none [&_*]:focus:!ring-0"
      style={{
        userSelect: "none",
        WebkitUserSelect: "none",
        WebkitTapHighlightColor: "transparent",
      }}
    >
      <div className="flex items-center gap-2 mb-4">
        <Icon className="h-4 w-4 text-primary" />
        <h3 className="text-sm font-semibold text-foreground">{title}</h3>
      </div>
      {data.length === 0 ? (
        <p className="text-sm text-muted-foreground py-8 text-center">
          {emptyMessage}
        </p>
      ) : (
        <ResponsiveContainer width="100%" height={chartHeight}>
          <BarChart
            data={data}
            layout="vertical"
            margin={{ top: 0, right: 44, bottom: 0, left: 0 }}
            barCategoryGap={8}
            accessibilityLayer={false}
          >
            <XAxis
              type="number"
              hide
              allowDecimals={false}
              domain={[0, (dataMax: number) => Math.ceil(dataMax * 1.15)]}
            />
            <YAxis
              type="category"
              dataKey="label"
              width={140}
              tickLine={false}
              axisLine={false}
              tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 12 }}
              tickFormatter={(value: string) =>
                value.length > 20 ? `${value.slice(0, 19)}…` : value
              }
            />
            <Tooltip
              cursor={false}
              isAnimationActive={false}
              content={<ChartTooltip />}
            />
            <Bar
              dataKey="count"
              barSize={20}
              radius={[0, 4, 4, 0]}
              style={{ cursor: "default" }}
              activeBar={false}
              isAnimationActive={false}
            >
              {data.map((entry) => (
                <Cell
                  key={entry.label}
                  fill={colorForEntry(entry)}
                  style={{ cursor: "default" }}
                />
              ))}
              <LabelList
                dataKey="count"
                position="right"
                style={{ fill: "hsl(var(--foreground))", fontSize: 12 }}
              />
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
