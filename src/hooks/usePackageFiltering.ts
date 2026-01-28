import { useState, useMemo } from "react";
import { Package } from "@/lib/sbom/types";

interface UsePackageFilteringOptions {
  packages: Package[];
}

export const usePackageFiltering = ({
  packages,
}: UsePackageFilteringOptions) => {
  const [searchQuery, setSearchQuery] = useState("");
  const [showVulnerableOnly, setShowVulnerableOnly] = useState(false);
  const [selectedSbom, setSelectedSbom] = useState("all");

  const filteredData = useMemo(
    () =>
      packages.filter((pkg) => {
        const matchesSbom =
          selectedSbom === "all" || pkg.source === selectedSbom;
        const matchesSearch =
          searchQuery === "" ||
          pkg.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
          (pkg.license &&
            pkg.license.toLowerCase().includes(searchQuery.toLowerCase()));

        const matchesVulnerable =
          !showVulnerableOnly ||
          (pkg.scanned && pkg.vulnerabilities.length > 0);

        return matchesSbom && matchesSearch && matchesVulnerable;
      }),
    [packages, selectedSbom, searchQuery, showVulnerableOnly],
  );

  return {
    searchQuery,
    setSearchQuery,
    showVulnerableOnly,
    setShowVulnerableOnly,
    selectedSbom,
    setSelectedSbom,
    filteredData,
  };
};
