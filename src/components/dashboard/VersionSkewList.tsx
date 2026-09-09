import { useState } from "react";
import { GitCompareArrows } from "lucide-react";
import { VersionSkewEntry } from "@/lib/dashboard-utils";
import { VersionSkewDetail } from "./VersionSkewDetail";

interface VersionSkewListProps {
  data: VersionSkewEntry[];
}

export function VersionSkewList({ data }: VersionSkewListProps) {
  const [selectedEntry, setSelectedEntry] = useState<VersionSkewEntry | null>(
    null,
  );
  const [detailOpen, setDetailOpen] = useState(false);

  const handleRowClick = (entry: VersionSkewEntry) => {
    setSelectedEntry(entry);
    setDetailOpen(true);
  };

  return (
    <div className="surface-elevated rounded-lg border border-border p-4">
      <div className="flex items-center gap-2 mb-4">
        <GitCompareArrows className="h-4 w-4 text-primary" />
        <h3 className="text-sm font-semibold text-foreground">
          Version Skew
        </h3>
        {data.length > 0 && (
          <span className="text-xs px-2 py-0.5 rounded-full bg-primary/15 text-primary">
            {data.length}
          </span>
        )}
      </div>
      {data.length === 0 ? (
        <p className="text-sm text-muted-foreground py-8 text-center">
          No packages with conflicting versions across SBOMs
        </p>
      ) : (
        <div className="max-h-80 overflow-y-auto">
          {data.map((entry) => (
            <button
              key={entry.name}
              type="button"
              onClick={() => handleRowClick(entry)}
              className="table-row-interactive flex w-full items-start justify-between gap-3 rounded-md px-2 py-2 text-left border-b border-border last:border-b-0"
            >
              <div className="min-w-0">
                <p className="font-mono text-sm text-foreground truncate">
                  {entry.name}
                </p>
                <p className="text-xs text-muted-foreground truncate">
                  {entry.versions.join(", ")}
                </p>
              </div>
              <span className="shrink-0 text-xs font-medium px-2 py-0.5 rounded-full bg-secondary text-muted-foreground">
                {entry.versions.length} versions
              </span>
            </button>
          ))}
        </div>
      )}

      <VersionSkewDetail
        entry={selectedEntry}
        open={detailOpen}
        onClose={() => setDetailOpen(false)}
      />
    </div>
  );
}
