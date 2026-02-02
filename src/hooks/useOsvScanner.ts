import { useState, useCallback } from "react";
import { Package, SBOMVulnerability } from "@/lib/sbom/types";
import { OSVResponse, OSVulnerability } from "@/types/osv";
import { ecosystemMapping } from "@/lib/ecosystems";

interface UseOsvScannerProps {
  packages: Package[];
  setPackages: React.Dispatch<React.SetStateAction<Package[]>>;
}

export function useOsvScanner({ packages, setPackages }: UseOsvScannerProps) {
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
      const osvVulns = results.vulns || [];

      const sbomVulnIds = new Set<string>();
      pkg.sbomVulnerabilities.forEach((sbomVuln) => {
        if (sbomVuln.id) sbomVulnIds.add(sbomVuln.id);
      });

      const uniqueOsvVulns = osvVulns.filter((osvVuln) => {
        if (osvVuln.id && sbomVulnIds.has(osvVuln.id)) {
          return false;
        }
        if (osvVuln.aliases) {
          for (const alias of osvVuln.aliases) {
            if (sbomVulnIds.has(alias)) {
              return false;
            }
          }
        }
        return true;
      });

      return { ...pkg, vulnerabilities: uniqueOsvVulns, scanned: true };
    } catch (error) {
      console.error(`Error fetching vulnerabilities for ${pkg.name}:`, error);
      return { ...pkg, vulnerabilities: [], scanned: true };
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
