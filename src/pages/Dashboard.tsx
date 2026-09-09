import { useMemo } from "react";
import { AppHeader } from "@/components/AppHeader";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { SeverityBreakdownChart } from "@/components/dashboard/SeverityBreakdownChart";
import { LicenseBreakdownChart } from "@/components/dashboard/LicenseBreakdownChart";
import { EcosystemBreakdownChart } from "@/components/dashboard/EcosystemBreakdownChart";
import { SbomDistributionChart } from "@/components/dashboard/SbomDistributionChart";
import { VersionSkewList } from "@/components/dashboard/VersionSkewList";
import {
  FileStack,
  Package as PackageIcon,
  Shield,
  AlertTriangle,
  Loader2,
} from "lucide-react";
import { useSbomData } from "@/hooks/useSbomData";
import { usePackageFiltering } from "@/hooks/usePackageFiltering";
import { computeSeverityCounts } from "@/lib/vulnerability-utils";
import {
  computeLicenseBreakdown,
  computeEcosystemBreakdown,
  computeSbomDistribution,
  computeVersionSkew,
} from "@/lib/dashboard-utils";

interface DashboardProps {
  sbomData: ReturnType<typeof useSbomData>;
}

const Dashboard = ({ sbomData }: DashboardProps) => {
  const { packages, sbomFiles, isLoading, error } = sbomData;

  const { selectedSbom, setSelectedSbom, filteredData } = usePackageFiltering({
    packages,
  });

  const scannedFiltered = useMemo(
    () => filteredData.filter((p) => p.scanned),
    [filteredData],
  );

  const totalVulnerabilities = useMemo(
    () =>
      scannedFiltered.reduce(
        (acc, p) => acc + p.vulnerabilities.length + p.sbomVulnerabilities.length,
        0,
      ),
    [scannedFiltered],
  );

  const severityCounts = useMemo(
    () =>
      computeSeverityCounts(
        scannedFiltered.flatMap((p) => p.vulnerabilities),
        scannedFiltered.flatMap((p) => p.sbomVulnerabilities),
      ),
    [scannedFiltered],
  );

  const licenseBreakdown = useMemo(
    () => computeLicenseBreakdown(filteredData),
    [filteredData],
  );

  const ecosystemBreakdown = useMemo(
    () => computeEcosystemBreakdown(filteredData),
    [filteredData],
  );

  const sbomDistribution = useMemo(
    () => computeSbomDistribution(packages, sbomFiles),
    [packages, sbomFiles],
  );

  const versionSkew = useMemo(() => computeVersionSkew(packages), [packages]);

  const totalSboms = selectedSbom === "all" ? sbomFiles.length : 1;

  if (error) {
    return (
      <div className="min-h-screen bg-background">
        <AppHeader />
        <main className="container mx-auto px-4 py-8">
          <div className="text-destructive">Error: {error}</div>
        </main>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <AppHeader />

      <main className="container mx-auto px-4 py-8 space-y-6">
        <div className="flex flex-col sm:flex-row gap-4 items-start sm:items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-foreground">Overview</h2>
            <p className="text-sm text-muted-foreground">
              Aggregated status across all loaded SBOMs
            </p>
          </div>
          <div className="w-full sm:w-64">
            <Select value={selectedSbom} onValueChange={setSelectedSbom}>
              <SelectTrigger className="bg-secondary border-border">
                <SelectValue placeholder="Select SBOM" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All SBOMs</SelectItem>
                {sbomFiles.map((file) => (
                  <SelectItem key={file} value={file}>
                    {file}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="surface-elevated rounded-lg border border-border p-4 flex items-center gap-4">
            <div className="h-12 w-12 rounded-lg bg-primary/10 flex items-center justify-center">
              <FileStack className="h-6 w-6 text-primary" />
            </div>
            <div>
              <p className="text-2xl font-bold text-foreground">
                {isLoading ? "—" : totalSboms}
              </p>
              <p className="text-sm text-muted-foreground">SBOMs</p>
            </div>
          </div>
          <div className="surface-elevated rounded-lg border border-border p-4 flex items-center gap-4">
            <div className="h-12 w-12 rounded-lg bg-primary/10 flex items-center justify-center">
              <PackageIcon className="h-6 w-6 text-primary" />
            </div>
            <div>
              <p className="text-2xl font-bold text-foreground">
                {isLoading ? "—" : filteredData.length}
              </p>
              <p className="text-sm text-muted-foreground">Total Packages</p>
            </div>
          </div>
          <div className="surface-elevated rounded-lg border border-border p-4 flex items-center gap-4">
            <div className="h-12 w-12 rounded-lg bg-destructive/10 flex items-center justify-center">
              <Shield className="h-6 w-6 text-destructive" />
            </div>
            <div>
              <p className="text-2xl font-bold text-foreground">
                {isLoading ? "—" : totalVulnerabilities}
              </p>
              <p className="text-sm text-muted-foreground">Vulnerabilities</p>
              {!isLoading && (
                <p className="text-xs text-muted-foreground/70 mt-0.5">
                  {scannedFiltered.length} of {filteredData.length} packages
                  scanned
                </p>
              )}
            </div>
          </div>
          <div className="surface-elevated rounded-lg border border-border p-4 flex items-center gap-4">
            <div className="h-12 w-12 rounded-lg bg-severity-critical/10 flex items-center justify-center">
              <AlertTriangle className="h-6 w-6 text-severity-critical" />
            </div>
            <div>
              <p className="text-2xl font-bold text-foreground">
                {isLoading ? "—" : severityCounts.critical}
              </p>
              <p className="text-sm text-muted-foreground">Critical</p>
            </div>
          </div>
        </div>

        {isLoading ? (
          <div className="surface-elevated rounded-lg border border-border p-4 flex flex-col items-center justify-center py-24">
            <Loader2 className="h-6 w-6 animate-spin text-primary mb-3" />
            <p className="text-sm text-muted-foreground">
              Loading SBOM data…
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 items-start">
            <SeverityBreakdownChart counts={severityCounts} />
            <LicenseBreakdownChart data={licenseBreakdown} />
            <EcosystemBreakdownChart data={ecosystemBreakdown} />
            {selectedSbom === "all" && (
              <>
                <SbomDistributionChart data={sbomDistribution} />
                <div className="lg:col-span-2">
                  <VersionSkewList data={versionSkew} />
                </div>
              </>
            )}
          </div>
        )}
      </main>
    </div>
  );
};

export default Dashboard;
