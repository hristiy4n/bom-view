import { useState, useEffect } from "react";
import { Package } from "@/lib/sbom/types";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/table";
import { DependencyTree } from "./DependencyTree";
import { VulnerabilityList } from "./VulnerabilityList";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Package as PackageIcon,
  GitBranch,
  Shield,
  AlertTriangle,
  Star,
  CheckCircle2,
  XCircle,
  Home,
  GitFork,
} from "lucide-react";
import { cn, getSeverity } from "@/lib/utils";
import { Scorecard } from "@/types/scorecard";
import { DepsDevProjectData } from "@/types/deps-dev";
import { getRepoUrl, PURL_REGEX, PackageType } from "@/lib/repo-url-resolver";

interface PackageDetailProps {
  pkg: Package | null;
  open: boolean;
  onClose: () => void;
}

export function PackageDetail({ pkg, open, onClose }: PackageDetailProps) {
  const [scorecard, setScorecard] = useState<Scorecard | null>(null);
  const [depsDevData, setDepsDevData] = useState<DepsDevProjectData | null>(
    null,
  );
  const [isLoadingScorecard, setIsLoadingScorecard] = useState<boolean>(false);
  const [scorecardError, setScorecardError] = useState<string | null>(null);

  useEffect(() => {
    setScorecard(null);
    setScorecardError(null);
    setDepsDevData(null);

    const fetchScorecardData = async () => {
      if (!pkg?.bomRef) return;

      const purlParts = pkg.bomRef.match(PURL_REGEX);
      if (!purlParts) {
        setScorecardError("Package type not supported.");
        return;
      }
      setIsLoadingScorecard(true);

      try {
        const [, pkgType, pkgPath] = purlParts;
        const decodedPath = decodeURIComponent(pkgPath);
        const atIndex = decodedPath.lastIndexOf("@");
        const pkgName =
          atIndex !== -1 ? decodedPath.substring(0, atIndex) : decodedPath;

        let repoUrl = await getRepoUrl(
          pkgType as PackageType,
          pkgName,
          pkg.version,
        );
        if (!repoUrl) {
          setScorecardError("Package type not supported.");
          return;
        }

        repoUrl = repoUrl.replace(/^git\+/, "").replace(/\.git(?=#|$)/, "");
        const url = new URL(repoUrl);

        let projectKeyId = "";
        if (url.hostname === "github.com") {
          const pathParts = url.pathname.split("/").filter((p) => p);
          if (pathParts.length < 2) throw new Error("Invalid GitHub URL path");
          projectKeyId = `github.com/${pathParts[0]}/${pathParts[1]}`;
        } else if (url.hostname === "gitlab.com") {
          const pathParts = url.pathname.split("/").filter((p) => p);
          if (pathParts.length < 2) throw new Error("Invalid GitLab URL path");
          projectKeyId = `gitlab.com/${pathParts[0]}/${pathParts[1]}`;
        } else if (url.hostname === "bitbucket.org") {
          const pathParts = url.pathname.split("/").filter((p) => p);
          if (pathParts.length < 2)
            throw new Error("Invalid Bitbucket URL path");
          projectKeyId = `bitbucket.org/${pathParts[0]}/${pathParts[1]}`;
        } else {
          throw new Error(
            "Repository is not on GitHub.com, GitLab.com, or Bitbucket.org",
          );
        }

        const scorecardResponse = await fetch(
          `https://api.deps.dev/v3/projects/${encodeURIComponent(projectKeyId)}`,
        );
        if (!scorecardResponse.ok) {
          if (scorecardResponse.status === 404) {
            setScorecardError("No OpenSSF Scorecard found for this package.");
            return;
          }
          throw new Error(
            `Scorecard request failed (Status: ${scorecardResponse.status})`,
          );
        }
        const scorecardData = await scorecardResponse.json();
        setDepsDevData(scorecardData);

        if (!scorecardData.scorecard) {
          setScorecardError("No OpenSSF Scorecard found for this package.");
          return;
        }

        const mappedScorecard = {
          ...scorecardData.scorecard,
          score: scorecardData.scorecard.overallScore,
        };
        setScorecard(mappedScorecard);
      } catch (err) {
        const message =
          err instanceof Error ? err.message : "An unknown error occurred";
        setScorecardError(message);
        console.error("Scorecard fetch error:", message);
      } finally {
        setIsLoadingScorecard(false);
      }
    };

    if (open) {
      fetchScorecardData();
    }
  }, [pkg, open]);

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
      <DialogContent className="max-w-4xl max-h-[90vh] flex flex-col bg-card border-border">
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
                {depsDevData?.starsCount && (
                  <span className="flex items-center gap-1 text-sm text-muted-foreground">
                    <Star className="h-4 w-4" /> {depsDevData.starsCount}
                  </span>
                )}
                {depsDevData?.forksCount && (
                  <span className="flex items-center gap-1 text-sm text-muted-foreground">
                    <GitFork className="h-4 w-4" /> {depsDevData.forksCount}
                  </span>
                )}
                {depsDevData &&
                  (depsDevData.projectKey?.id?.startsWith("github.com/") ||
                    depsDevData.homepage) && (
                    <a
                      href={
                        depsDevData.projectKey?.id?.startsWith("github.com/")
                          ? `https://${depsDevData.projectKey.id}`
                          : depsDevData.homepage
                      }
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-primary hover:underline text-sm flex items-center gap-1"
                    >
                      <Home className="h-4 w-4" /> Repository
                    </a>
                  )}
              </div>
            </div>
          </div>
        </DialogHeader>

        <div className="mt-4 flex-grow overflow-y-auto">
          <DialogDescription asChild>
            <p className="text-sm text-muted-foreground mb-6">
              {depsDevData?.description ||
                pkg.description ||
                "No description available."}
            </p>
          </DialogDescription>

          {pkg.scanned && <div className="grid grid-cols-3 gap-4 mb-6"></div>}

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
              <TabsTrigger value="scorecard" className="flex-1">
                <Star className="h-4 w-4 mr-2" />
                Scorecard
                {scorecard && (
                  <span className="ml-2 px-1.5 py-0.5 text-xs rounded bg-primary/20 text-primary">
                    {scorecard.score}
                  </span>
                )}
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

            <TabsContent value="scorecard" className="mt-4">
              {isLoadingScorecard && (
                <div className="text-center py-8 text-muted-foreground">
                  <p>Loading OpenSSF Scorecard...</p>
                </div>
              )}
              {!isLoadingScorecard &&
                scorecardError ===
                  "No OpenSSF Scorecard found for this package." && (
                  <div className="text-center py-8 text-muted-foreground">
                    <p>No OpenSSF Scorecard available for this package.</p>
                  </div>
                )}
              {!isLoadingScorecard &&
                scorecardError &&
                scorecardError !==
                  "No OpenSSF Scorecard found for this package." && (
                  <div className="text-center py-8 text-destructive">
                    <p>Could not load OpenSSF Scorecard.</p>
                    <p className="text-xs text-muted-foreground">
                      {scorecardError}
                    </p>
                  </div>
                )}
              {!isLoadingScorecard && !scorecardError && scorecard && (
                <div className="space-y-4">
                  <div className="flex justify-between items-center p-4 rounded-lg bg-secondary">
                    <div>
                      <h3 className="font-semibold">Overall Score</h3>
                      <p className="text-sm text-muted-foreground">
                        Date: {new Date(scorecard.date).toLocaleDateString()}
                      </p>
                    </div>
                    <p className="text-4xl font-bold text-primary">
                      {scorecard.score}
                    </p>
                  </div>
                  <div className="border rounded-lg">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Check</TableHead>
                          <TableHead className="text-right">Score</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {scorecard.checks.map((check) => (
                          <TableRow key={check.name}>
                            <TableCell>
                              <div className="font-medium flex items-center gap-2">
                                {check.score > 0 ? (
                                  <CheckCircle2 className="h-4 w-4 text-green-500" />
                                ) : (
                                  <XCircle className="h-4 w-4 text-destructive" />
                                )}
                                <a
                                  href={check.documentation.url}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="hover:underline"
                                >
                                  {check.name}
                                </a>
                              </div>
                              <p className="text-xs text-muted-foreground mt-1">
                                {check.reason}
                              </p>
                            </TableCell>
                            <TableCell className="text-right font-mono">
                              {check.score}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                </div>
              )}
            </TabsContent>
          </Tabs>
        </div>
      </DialogContent>
    </Dialog>
  );
}
