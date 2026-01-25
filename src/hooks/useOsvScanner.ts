import { useState, useCallback } from "react";
import { Package } from "@/lib/sbom/types";
import { OSVResponse } from "@/types/osv";
import { ecosystemMapping } from "@/lib/ecosystems";

export function useOsvScanner() {
  const [scanningIds, setScanningIds] = useState<Set<string>>(new Set());
  const [isScanningAll, setIsScanningAll] = useState<boolean>(false);

  const scanPackage = useCallback(async (pkg: Package): Promise<Package> => {
    setScanningIds((prev) => new Set(prev).add(pkg.id));

    const purlType = pkg.bomRef.match(/pkg:([^/]+)/)?.[1];
    const ecosystem = purlType ? ecosystemMapping[purlType] : "";

    if (!ecosystem) {
      console.warn(`Ecosystem not found for package: ${pkg.name}`);
      setScanningIds((prev) => {
        const next = new Set(prev);
        next.delete(pkg.id);
        return next;
      });
      return { ...pkg, scanned: true };
    }

    try {
      const response = await fetch("https://api.osv.dev/v1/query", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          version: pkg.version,
          package: { name: pkg.name, ecosystem: ecosystem },
        }),
      });
      if (!response.ok) {
        throw new Error(
          `OSV API request failed with status ${response.status}`,
        );
      }
      const results: OSVResponse = await response.json();
      return { ...pkg, vulnerabilities: results.vulns || [], scanned: true };
    } catch (error) {
      console.error(`Error fetching vulnerabilities for ${pkg.name}:`, error);
      return { ...pkg, vulnerabilities: [], scanned: true }; // Mark as scanned even on error
    } finally {
      setScanningIds((prev) => {
        const next = new Set(prev);
        next.delete(pkg.id);
        return next;
      });
    }
  }, []);

  const scanAllPackages = useCallback(
    async (pkgs: Package[]): Promise<Package[]> => {
      setIsScanningAll(true);
      const scannablePackages = pkgs.filter((pkg) => {
        const purlType = pkg.bomRef.match(/pkg:([^/]+)/)?.[1];
        return purlType ? ecosystemMapping[purlType] : "";
      });
      const results = await Promise.all(
        scannablePackages.map((p) => scanPackage(p)),
      );
      setIsScanningAll(false);
      const updatedPackagesMap = new Map(results.map((p) => [p.id, p]));

      return pkgs.map((p) => updatedPackagesMap.get(p.id) || p);
    },
    [scanPackage],
  );

  return { scanningIds, isScanningAll, scanPackage, scanAllPackages };
}
