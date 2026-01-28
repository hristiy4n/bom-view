import { useState, useEffect, useMemo } from "react";
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
import { cn, getSeverity } from "@/lib/utils";
import { Dependency } from "./DependencyTree";
import { columns } from "@/data/columns";
import { Package } from "@/lib/sbom/types";
import { ecosystemMapping } from "@/lib/ecosystems";
import { useSbomData } from "@/hooks/useSbomData";
import { useOsvScanner } from "@/hooks/useOsvScanner";
import { usePagination } from "@/hooks/usePagination";
import { usePackageFiltering } from "@/hooks/usePackageFiltering";

const ITEMS_PER_PAGE = 8;

export function PackageTable() {
  const { packages, setPackages, sbomFiles, isLoading, error } = useSbomData();
  const { scanningIds, isScanningAll, scanPackage, scanAllPackages } =
    useOsvScanner({ packages, setPackages });

  const {
    searchQuery,
    setSearchQuery,
    showVulnerableOnly,
    setShowVulnerableOnly,
    selectedSbom,
    setSelectedSbom,
    filteredData,
  } = usePackageFiltering({ packages });

  const [selectedPackage, setSelectedPackage] = useState<Package | null>(null);
  const [detailOpen, setDetailOpen] = useState(false);
  const [filterOpen, setFilterOpen] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const [visibleColumns, setVisibleColumns] = useState<string[]>(
    columns.filter((c) => c.visible).map((c) => c.id),
  );

  useEffect(() => {
    setCurrentPage(1);
  }, [selectedSbom, searchQuery, showVulnerableOnly]);

  const handleScan = async (pkg: Package, e: React.MouseEvent) => {
    e.stopPropagation();
    const updatedPackage = await scanPackage(pkg);
    setPackages((prev) =>
      prev.map((p) => (p.id === updatedPackage.id ? updatedPackage : p)),
    );
  };

  const handleScanAll = async () => {
    const packagesToScan =
      selectedSbom === "all"
        ? packages
        : packages.filter((p) => p.source === selectedSbom);

    const updatedPackages = await scanAllPackages(packagesToScan);
    setPackages(updatedPackages);
  };



  const { paginationRange, totalPages, paginatedData } = usePagination({
    totalItems: filteredData.length,
    itemsPerPage: ITEMS_PER_PAGE,
    currentPage,
  });

  const paginatedItems = useMemo(
    () => filteredData.slice(paginatedData.startIndex, paginatedData.endIndex),
    [filteredData, paginatedData],
  );

  const handleRowClick = (pkg: Package) => {
    setSelectedPackage(pkg);
    setDetailOpen(true);
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

  const scannedPackages = useMemo(
    () => filteredData.filter((p) => p.scanned),
    [filteredData],
  );

  const totalVulnerabilities = useMemo(
    () => scannedPackages.reduce((acc, p) => acc + p.vulnerabilities.length, 0),
    [scannedPackages],
  );

  const criticalCount = useMemo(
    () =>
      scannedPackages.reduce(
        (acc, p) =>
          acc +
          p.vulnerabilities.filter(
            (v) => getSeverity(v.severity) === "critical",
          ).length,
        0,
      ),
    [scannedPackages],
  );

  if (error) {
    return <div className="text-destructive">Error: {error}</div>;
  }

  return (
    <div className="relative">
      <div className={cn("space-y-6")}>
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
                <span className="ml-2 h-5 w-5 flex items-center justify-center rounded-full bg-primary text-xs text-primary-foreground">
                  {activeFiltersCount}
                </span>
              )}
            </Button>
            <Button
              onClick={handleScanAll}
              disabled={isScanningAll}
              className={cn(
                "glow-primary-hover",
                isScanningAll && "animate-scan",
              )}
            >
              <Radar
                className={cn("h-4 w-4 mr-2", isScanningAll && "animate-spin")}
              />
              {isScanningAll ? "Scanning..." : "Scan All"}
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
                {paginatedItems.length > 0 &&
                  paginatedItems.map((pkg) => {
                    const hasVulnerabilities =
                      pkg.scanned && pkg.vulnerabilities.length > 0;
                    const purlType = pkg.bomRef.match(/pkg:([^/]+)/)?.[1];
                    const ecosystem = purlType
                      ? ecosystemMapping[purlType]
                      : "";
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
                              <span className="inline-flex items-center gap-1.5 rounded-full bg-destructive/15 px-2 py-0.5 text-xs font-medium text-destructive">
                                <AlertTriangle className="h-3 w-3" />
                                {pkg.vulnerabilities.length}
                              </span>
                            ) : (
                              <span className="inline-flex items-center gap-1.5 rounded-full bg-severity-low/15 px-2 py-0.5 text-xs font-medium text-severity-low">
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
                              onClick={(e) => handleScan(pkg, e)}
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
                {paginatedItems.length === 0 && !isLoading && (
                  <TableRow>
                    <TableCell
                      colSpan={visibleColumns.length + 1}
                      className="h-32 text-center text-muted-foreground"
                    >
                      No packages found.
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
              Showing {paginatedItems.length} of {filteredData.length} packages
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
                {paginationRange.map((page, index) =>
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
                    <span
                      key={index}
                      className="px-2 py-1 text-muted-foreground"
                    >
                      ...
                    </span>
                  ),
                )}
              </div>
              <Button
                variant="outline"
                size="sm"
                onClick={() =>
                  setCurrentPage((p) => Math.min(totalPages, p + 1))
                }
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
    </div>
  );
}
