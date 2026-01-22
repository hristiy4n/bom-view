import { Package } from "./PackageTable";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { DependencyTree } from "./DependencyTree";
import { VulnerabilityList } from "./VulnerabilityList";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Package as PackageIcon,
  GitBranch,
  Shield,
  AlertTriangle,
} from "lucide-react";
import { CVSS31, CVSS30 } from "@pandatix/js-cvss";
import { cn } from "@/lib/utils";
import { OSVulnerability, Severity } from "@/types/osv";

interface PackageDetailProps {
  pkg: Package | null;
  open: boolean;
  onClose: () => void;
}
const getCVSS = (
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
    console.error("Error parsing CVSS vector:", error);
    return null;
  }
};

const getSeverity = (severity: { type: string; score: string }[]): Severity => {
  const cvss = getCVSS(severity);
  if (cvss === null) return "unknown";
  if (cvss >= 9.0) return "critical";
  if (cvss >= 7.0) return "high";
  if (cvss >= 4.0) return "medium";
  if (cvss > 0) return "low";
  return "unknown";
};
export function PackageDetail({ pkg, open, onClose }: PackageDetailProps) {
  if (!pkg) return null;

  const hasVulnerabilities = pkg.vulnerabilities.length > 0;
  const criticalCount = pkg.vulnerabilities.filter(
    (v) => getSeverity(v.severity) === "critical",
  ).length;
  const highCount = pkg.vulnerabilities.filter(
    (v) => getSeverity(v.severity) === "high",
  ).length;

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-3xl max-h-[90vh] overflow-y-auto bg-card border-border">
        <DialogHeader className="space-y-4">
          <div className="flex items-start justify-between">
            <div className="space-y-2">
              <DialogTitle className="text-xl font-semibold text-foreground flex items-center gap-2">
                <PackageIcon className="h-5 w-5 text-primary" />
                <span className="font-mono">{pkg.name}</span>
              </DialogTitle>
              <div className="flex items-center gap-3">
                <span className="font-mono text-sm text-muted-foreground">
                  v{pkg.version}
                </span>
                <span className="text-xs px-2 py-0.5 rounded bg-secondary text-muted-foreground">
                  {pkg.license}
                </span>
              </div>
            </div>
          </div>
        </DialogHeader>

        <div className="mt-4">
          <DialogDescription asChild>
            <p className="text-sm text-muted-foreground mb-6">
              {pkg.description}
            </p>
          </DialogDescription>

          {pkg.scanned && (
            <div className="grid grid-cols-3 gap-4 mb-6">
              <div
                className={cn(
                  "rounded-lg border p-3",
                  hasVulnerabilities
                    ? "border-destructive/30 bg-destructive/5"
                    : "border-severity-low/30 bg-severity-low/5",
                )}
              >
                <div className="flex items-center gap-2">
                  <Shield
                    className={cn(
                      "h-4 w-4",
                      hasVulnerabilities
                        ? "text-destructive"
                        : "text-severity-low",
                    )}
                  />
                  <span className="text-lg font-bold text-foreground">
                    {pkg.vulnerabilities.length}
                  </span>
                </div>
                <p className="text-xs text-muted-foreground mt-1">
                  Vulnerabilities
                </p>
              </div>
              {criticalCount > 0 && (
                <div className="rounded-lg border border-severity-critical/30 bg-severity-critical/5 p-3">
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4 text-severity-critical" />
                    <span className="text-lg font-bold text-foreground">
                      {criticalCount}
                    </span>
                  </div>
                  <p className="text-xs text-muted-foreground mt-1">Critical</p>
                </div>
              )}
              {highCount > 0 && (
                <div className="rounded-lg border border-severity-high/30 bg-severity-high/5 p-3">
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4 text-severity-high" />
                    <span className="text-lg font-bold text-foreground">
                      {highCount}
                    </span>
                  </div>
                  <p className="text-xs text-muted-foreground mt-1">High</p>
                </div>
              )}
            </div>
          )}

          <Tabs defaultValue="vulnerabilities" className="w-full">
            <TabsList className="w-full bg-secondary">
              <TabsTrigger value="vulnerabilities" className="flex-1">
                <Shield className="h-4 w-4 mr-2" />
                Vulnerabilities
                {pkg.scanned && pkg.vulnerabilities.length > 0 && (
                  <span className="ml-2 px-1.5 py-0.5 text-xs rounded bg-destructive/20 text-destructive">
                    {pkg.vulnerabilities.length}
                  </span>
                )}
              </TabsTrigger>
              <TabsTrigger value="dependencies" className="flex-1">
                <GitBranch className="h-4 w-4 mr-2" />
                Dependency Tree
              </TabsTrigger>
            </TabsList>

            <TabsContent value="vulnerabilities" className="mt-4">
              {!pkg.scanned ? (
                <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
                  <p className="text-sm">
                    Run a scan to check for vulnerabilities
                  </p>
                </div>
              ) : (
                <VulnerabilityList vulnerabilities={pkg.vulnerabilities} />
              )}
            </TabsContent>

            <TabsContent value="dependencies" className="mt-4">
              <DependencyTree rootDependency={pkg.dependencies} />
            </TabsContent>
          </Tabs>
        </div>
      </DialogContent>
    </Dialog>
  );
}
