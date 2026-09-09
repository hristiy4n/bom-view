import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { VersionSkewEntry } from "@/lib/dashboard-utils";

interface VersionSkewDetailProps {
  entry: VersionSkewEntry | null;
  open: boolean;
  onClose: () => void;
}

export function VersionSkewDetail({
  entry,
  open,
  onClose,
}: VersionSkewDetailProps) {
  if (!entry) return null;

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-lg bg-card border-border">
        <DialogHeader>
          <DialogTitle className="font-mono">{entry.name}</DialogTitle>
          <DialogDescription>
            {entry.occurrences.length} different versions found across your
            SBOMs
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-3 max-h-96 overflow-y-auto">
          {entry.occurrences.map((occurrence) => (
            <div
              key={occurrence.version}
              className="rounded-lg border border-border bg-secondary/30 p-3"
            >
              <p className="font-mono text-sm font-medium text-foreground">
                {occurrence.version}
              </p>
              <div className="mt-2 flex flex-wrap gap-1.5">
                {occurrence.sources.map((source) => (
                  <span
                    key={source}
                    className="text-xs px-2 py-0.5 rounded-full bg-secondary text-muted-foreground"
                  >
                    {source}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </DialogContent>
    </Dialog>
  );
}
