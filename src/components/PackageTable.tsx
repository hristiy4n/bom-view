import { useState, useEffect } from "react";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { PackageDetail } from "./PackageDetail";
import { FilterSidebar } from "./FilterSidebar";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { CVSS31, CVSS30 } from "@pandatix/js-cvss";
import {
  Search,
  SlidersHorizontal,
  Radar,
  ChevronLeft,
  ChevronRight,
  Package as PackageIcon,
  Shield,
  AlertTriangle,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Dependency } from "./DependencyTree";
import { columns } from "@/data/columns";

import {
  Package,
  SbomFormat,
  CycloneDXBom,
  SpdxBom,
} from "@/lib/sbom/types";
import {
  identifySbomFormat,
  processCycloneDxData,
  processSpdxData,
} from "@/lib/sbom/parser";
import { ecosystemMapping } from "@/lib/ecosystems";
import { OSVResponse, OSVulnerability, Severity } from "@/types/osv";

const ITEMS_PER_PAGE = 8;

const getPaginationRange = (
  totalPages: number,
  currentPage: number,
  siblings = 1,
) => {
  const totalNumbers = siblings * 2 + 3;
  const totalBlocks = totalNumbers + 2;

  if (totalPages <= totalBlocks) {
    return Array.from({ length: totalPages }, (_, i) => i + 1);
  }

  const leftSiblingIndex = Math.max(currentPage - siblings, 1);
  const rightSiblingIndex = Math.min(currentPage + siblings, totalPages);

  const shouldShowLeftDots = leftSiblingIndex > 2;
  const shouldShowRightDots = rightSiblingIndex < totalPages - 2;

  const firstPageIndex = 1;
  const lastPageIndex = totalPages;

  if (!shouldShowLeftDots && shouldShowRightDots) {
    const leftItemCount = 3 + 2 * siblings;
    const leftRange = Array.from({ length: leftItemCount }, (_, i) => i + 1);
    return [...leftRange, "...", totalPages];
  }

  if (shouldShowLeftDots && !shouldShowRightDots) {
    const rightItemCount = 3 + 2 * siblings;
    const rightRange = Array.from(
      { length: rightItemCount },
      (_, i) => totalPages - rightItemCount + i + 1,
    );
    return [firstPageIndex, "...", ...rightRange];
  }

  if (shouldShowLeftDots && shouldShowRightDots) {
    const middleRange = Array.from(
      { length: rightSiblingIndex - leftSiblingIndex + 1 },
      (_, i) => leftSiblingIndex + i,
    );
    return [firstPageIndex, "...", ...middleRange, "...", lastPageIndex];
  }

  return [];
};

export function PackageTable() {
  const [packages, setPackages] = useState<Package[]>([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedPackage, setSelectedPackage] = useState<Package | null>(null);
  const [detailOpen, setDetailOpen] = useState(false);
  const [filterOpen, setFilterOpen] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const [scanningAll, setScanningAll] = useState(false);
  const [scanningIds, setScanningIds] = useState<Set<string>>(new Set());
  const [selectedSbom, setSelectedSbom] = useState<string>("all");
  const [sbomFiles, setSbomFiles] = useState<string[]>([]);

  useEffect(() => {
    const fetchSbomIndex = async () => {
      try {
        const response = await fetch("/sboms/index.json");
        const data = await response.json();
        setSbomFiles(data);
      } catch (error) {
        console.error("Could not load SBOM index:", error);
      }
    };
    fetchSbomIndex();
  }, []);

  useEffect(() => {
    const loadBoms = async () => {
      if (sbomFiles.length === 0) {
        return;
      }

      let sbomsToLoad: string[] = [];
      if (selectedSbom === "all") {
        sbomsToLoad = sbomFiles;
      } else if (selectedSbom) {
        sbomsToLoad = [selectedSbom];
      }

      if (sbomsToLoad.length === 0) {
        setPackages([]);
        return;
      }

      const allPackages: Package[] = [];
      for (const sbomFile of sbomsToLoad) {
        try {
          const response = await fetch(`/sboms/${sbomFile}`);
          const data = await response.json();
          const format = identifySbomFormat(data);
          let loadedPackages: Package[] = [];

          if (format === SbomFormat.CycloneDX) {
            loadedPackages = processCycloneDxData(
              data as CycloneDXBom,
              sbomFile,
            );
          } else if (format === SbomFormat.SPDX) {
            loadedPackages = processSpdxData(data as SpdxBom, sbomFile);
          } else {
            console.error(`Invalid SBOM format for file: ${sbomFile}`);
          }

          allPackages.push(...loadedPackages);
        } catch (error) {
          console.error(
            `Error loading or processing SBOM file ${sbomFile}:`,
            error,
          );
        }
      }
      setPackages(allPackages);
    };
    loadBoms();
  }, [selectedSbom, sbomFiles]);

  useEffect(() => {
    setCurrentPage(1);
  }, [selectedSbom]);

  // Filters
  const [visibleColumns, setVisibleColumns] = useState<string[]>(
    columns.filter((c) => c.visible).map((c) => c.id),
  );
  const [showVulnerableOnly, setShowVulnerableOnly] = useState(false);

  const filteredData = packages.filter((pkg) => {
    const matchesSbom = selectedSbom === "all" || pkg.source === selectedSbom;
    const matchesSearch =
      searchQuery === "" ||
      pkg.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      pkg.license.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesVulnerable =
      !showVulnerableOnly || (pkg.scanned && pkg.vulnerabilities.length > 0);

    return matchesSbom && matchesSearch && matchesVulnerable;
  });

  const totalPages = Math.ceil(filteredData.length / ITEMS_PER_PAGE);
  const paginatedData = filteredData.slice(
    (currentPage - 1) * ITEMS_PER_PAGE,
    currentPage * ITEMS_PER_PAGE,
  );

  const handleRowClick = (pkg: Package) => {
    setSelectedPackage(pkg);
    setDetailOpen(true);
  };

  const handleScan = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setScanningIds((prev) => new Set(prev).add(id));

    const pkg = packages.find((p) => p.id === id);
    if (!pkg) return;

    const purlType = pkg.bomRef.match(/pkg:([^/]+)/)?.[1];
    const ecosystem = purlType ? ecosystemMapping[purlType] : "";

    if (!ecosystem) {
      console.warn(`Ecosystem not found for package: ${pkg.name}`);
      setScanningIds((prev) => {
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
      return;
    }

    try {
      const response = await fetch("https://api.osv.dev/v1/query", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          version: pkg.version,
          package: {
            name: pkg.name,
            ecosystem: ecosystem,
          },
        }),
      });
      const results: OSVResponse = await response.json();
      setPackages((prev) =>
        prev.map((p) =>
          p.id === id
            ? { ...p, vulnerabilities: results.vulns || [], scanned: true }
            : p,
        ),
      );
    } catch (error) {
      console.error("Error fetching vulnerabilities:", error);
    } finally {
      setScanningIds((prev) => {
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
    }
  };

  const handleScanAll = async () => {
    setScanningAll(true);
    const packagesToScan =
      selectedSbom === "all"
        ? packages
        : packages.filter((p) => p.source === selectedSbom);

    const scannablePackages = packagesToScan.filter((pkg) => {
      const purlType = pkg.bomRef.match(/pkg:([^/]+)/)?.[1];
      return purlType ? ecosystemMapping[purlType] : "";
    });

    const promises = scannablePackages.map((pkg) => {
      const mockEvent = { stopPropagation: () => {} } as React.MouseEvent;
      return handleScan(pkg.id, mockEvent);
    });
    await Promise.all(promises);
    setScanningAll(false);
  };
  const handleColumnChange = (columnId: string) => {
    setVisibleColumns((prev) =>
      prev.includes(columnId)
        ? prev.filter((c) => c !== columnId)
        : [...prev, columnId],
    );
  };

  const isColumnVisible = (columnId: string) =>
    visibleColumns.includes(columnId);

  const activeFiltersCount = showVulnerableOnly ? 1 : 0;

  const scannedPackages = filteredData.filter((p) => p.scanned);

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
      console.error("Error parsing CVSS vector for:", cvss.score, error);
      return null;
    }
  };

  const getSeverity = (
    severity: { type: string; score: string }[],
  ): Severity => {
    const cvss = getCVSS(severity);
    if (cvss === null) return "unknown";
    if (cvss >= 9.0) return "critical";
    if (cvss >= 7.0) return "high";
    if (cvss >= 4.0) return "medium";
    if (cvss > 0) return "low";
    return "unknown";
  };

  const totalVulnerabilities = scannedPackages.reduce(
    (acc, p) => acc + p.vulnerabilities.length,
    0,
  );

  const criticalCount = scannedPackages.reduce(
    (acc, p) =>
      acc +
      p.vulnerabilities.filter((v) => getSeverity(v.severity) === "critical")
        .length,
    0,
  );

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="surface-elevated rounded-lg border border-border p-4 flex items-center gap-4">
          <div className="h-12 w-12 rounded-lg bg-primary/10 flex items-center justify-center">
            <PackageIcon className="h-6 w-6 text-primary" />
          </div>
          <div>
            <p className="text-2xl font-bold text-foreground">
              {filteredData.length}
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
              {totalVulnerabilities}
            </p>
            <p className="text-sm text-muted-foreground">Vulnerabilities</p>
          </div>
        </div>
        <div className="surface-elevated rounded-lg border border-border p-4 flex items-center gap-4">
          <div className="h-12 w-12 rounded-lg bg-severity-critical/10 flex items-center justify-center">
            <AlertTriangle className="h-6 w-6 text-severity-critical" />
          </div>
          <div>
            <p className="text-2xl font-bold text-foreground">
              {criticalCount}
            </p>
            <p className="text-sm text-muted-foreground">Critical</p>
          </div>
        </div>
      </div>

      <div className="flex flex-col sm:flex-row gap-4 items-start sm:items-center justify-between">
        <div className="flex-1 max-w-md">
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
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search packages..."
            value={searchQuery}
            onChange={(e) => {
              setSearchQuery(e.target.value);
              setCurrentPage(1);
            }}
            className="pl-10 bg-secondary border-border"
          />
        </div>
        <div className="flex gap-3">
          <Button
            variant="outline"
            onClick={() => setFilterOpen(true)}
            className="border-border"
          >
            <SlidersHorizontal className="h-4 w-4 mr-2" />
            Filters
            {activeFiltersCount > 0 && (
              <span className="ml-2 h-5 w-5 rounded-full bg-primary text-primary-foreground text-xs flex items-center justify-center">
                {activeFiltersCount}
              </span>
            )}
          </Button>
          <Button
            onClick={handleScanAll}
            disabled={scanningAll}
            className={cn("glow-primary-hover", scanningAll && "animate-scan")}
          >
            <Radar
              className={cn("h-4 w-4 mr-2", scanningAll && "animate-spin")}
            />
            {scanningAll ? "Scanning..." : "Scan All"}
          </Button>
        </div>
      </div>

      <div className="rounded-lg border border-border overflow-hidden">
        <TooltipProvider>
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent border-border">
                {isColumnVisible("name") && (
                  <TableHead className="text-muted-foreground">
                    Package
                  </TableHead>
                )}
                {isColumnVisible("version") && (
                  <TableHead className="text-muted-foreground">
                    Version
                  </TableHead>
                )}
                {isColumnVisible("source") && (
                  <TableHead className="text-muted-foreground">
                    Source
                  </TableHead>
                )}
                {isColumnVisible("license") && (
                  <TableHead className="text-muted-foreground">
                    License
                  </TableHead>
                )}
                {isColumnVisible("vulnerabilities") && (
                  <TableHead className="text-muted-foreground">
                    Vulnerabilities
                  </TableHead>
                )}
                <TableHead className="text-muted-foreground text-right">
                  Actions
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {paginatedData.map((pkg) => {
                const hasVulnerabilities =
                  pkg.scanned && pkg.vulnerabilities.length > 0;
                const purlType = pkg.bomRef.match(/pkg:([^/]+)/)?.[1];
                const ecosystem = purlType ? ecosystemMapping[purlType] : "";
                const isScannable = !!ecosystem;

                return (
                  <TableRow
                    key={pkg.id}
                    className="table-row-interactive border-border"
                    onClick={() => handleRowClick(pkg)}
                  >
                    {isColumnVisible("name") && (
                      <TableCell className="font-mono font-medium text-foreground">
                        {pkg.name}
                      </TableCell>
                    )}
                    {isColumnVisible("version") && (
                      <TableCell className="font-mono text-sm text-muted-foreground">
                        {pkg.version}
                      </TableCell>
                    )}
                    {isColumnVisible("source") && (
                      <TableCell className="font-mono text-sm text-muted-foreground">
                        {pkg.source}
                      </TableCell>
                    )}
                    {isColumnVisible("license") && (
                      <TableCell className="text-sm text-muted-foreground">
                        {pkg.license}
                      </TableCell>
                    )}
                    {isColumnVisible("vulnerabilities") && (
                      <TableCell>
                        {!pkg.scanned ? (
                          <span className="text-sm text-muted-foreground">
                            —
                          </span>
                        ) : hasVulnerabilities ? (
                          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium bg-destructive/15 text-destructive border border-destructive/30">
                            <AlertTriangle className="h-3 w-3" />
                            {pkg.vulnerabilities.length}
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium bg-severity-low/15 text-severity-low border border-severity-low/30">
                            <Shield className="h-3 w-3" />0
                          </span>
                        )}
                      </TableCell>
                    )}
                    <TableCell className="text-right">
                      {isScannable ? (
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={(e) => handleScan(pkg.id, e)}
                          disabled={scanningIds.has(pkg.id)}
                          className="hover:bg-primary/10 hover:text-primary"
                        >
                          <Radar
                            className={cn(
                              "h-4 w-4",
                              scanningIds.has(pkg.id) && "animate-spin",
                            )}
                          />
                          <span className="ml-1">
                            {scanningIds.has(pkg.id) ? "Scanning" : "Scan"}
                          </span>
                        </Button>
                      ) : (
                        <TooltipProvider>
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <div className="inline-block">
                                <Button
                                  size="sm"
                                  variant="ghost"
                                  disabled
                                  className="text-muted-foreground/50"
                                >
                                  <Radar className="h-4 w-4" />
                                  <span className="ml-1">Scan</span>
                                </Button>
                              </div>
                            </TooltipTrigger>
                            <TooltipContent>
                              <p>Ecosystem does not exist</p>
                            </TooltipContent>
                          </Tooltip>
                        </TooltipProvider>
                      )}
                    </TableCell>
                  </TableRow>
                );
              })}
              {paginatedData.length === 0 && (
                <TableRow>
                  <TableCell
                    colSpan={visibleColumns.length + 1}
                    className="h-32 text-center text-muted-foreground"
                  >
                    No packages found matching your criteria.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </TooltipProvider>
      </div>

      {totalPages > 1 && (
        <div className="flex items-center justify-between">
          <p className="text-sm text-muted-foreground">
            Showing {paginatedData.length} of {filteredData.length} packages
          </p>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              disabled={currentPage === 1}
              className="border-border"
            >
              <ChevronLeft className="h-4 w-4" />
            </Button>
            <div className="flex items-center gap-1">
              {getPaginationRange(totalPages, currentPage).map((page, index) =>
                typeof page === "number" ? (
                  <Button
                    key={index}
                    variant={page === currentPage ? "default" : "ghost"}
                    size="sm"
                    onClick={() => setCurrentPage(page)}
                    className={cn(
                      "w-8 h-8",
                      page === currentPage && "glow-primary",
                    )}
                  >
                    {page}
                  </Button>
                ) : (
                  <span key={index} className="px-2 py-1 text-muted-foreground">
                    ...
                  </span>
                ),
              )}
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
              disabled={currentPage === totalPages}
              className="border-border"
            >
              <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      )}

      <PackageDetail
        pkg={
          selectedPackage
            ? packages.find((p) => p.id === selectedPackage.id) ||
              selectedPackage
            : null
        }
        open={detailOpen}
        onClose={() => setDetailOpen(false)}
      />

      <FilterSidebar
        open={filterOpen}
        onClose={() => setFilterOpen(false)}
        visibleColumns={visibleColumns}
        onColumnChange={handleColumnChange}
        showOutdatedOnly={false}
        onShowOutdatedChange={() => {}}
        showVulnerableOnly={showVulnerableOnly}
        onShowVulnerableChange={setShowVulnerableOnly}
      />
    </div>
  );
}
