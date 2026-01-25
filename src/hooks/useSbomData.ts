import { useState, useEffect } from "react";
import { Package, SbomFormat, CycloneDXBom, SpdxBom } from "@/lib/sbom/types";
import {
  identifySbomFormat,
  processCycloneDxData,
  processSpdxData,
} from "@/lib/sbom/parser";

export function useSbomData() {
  const [packages, setPackages] = useState<Package[]>([]);
  const [sbomFiles, setSbomFiles] = useState<string[]>([]);
  const [selectedSbom, setSelectedSbom] = useState<string>("all");
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchSbomIndex = async () => {
      setIsLoading(true);
      try {
        const response = await fetch("/sboms/index.json");
        if (!response.ok) {
          throw new Error("Failed to fetch SBOM index");
        }
        const data = await response.json();
        setSbomFiles(data);
      } catch (err) {
        const message =
          err instanceof Error ? err.message : "An unknown error occurred";
        console.error("Could not load SBOM index:", message);
        setError(message);
      } finally {
        setIsLoading(false);
      }
    };
    fetchSbomIndex();
  }, []);

  useEffect(() => {
    if (sbomFiles.length === 0) return;

    const loadBoms = async () => {
      setIsLoading(true);
      setError(null);

      let sbomsToLoad: string[] = [];
      if (selectedSbom === "all") {
        sbomsToLoad = sbomFiles;
      } else if (selectedSbom) {
        sbomsToLoad = [selectedSbom];
      }

      if (sbomsToLoad.length === 0) {
        setPackages([]);
        setIsLoading(false);
        return;
      }

      const allPackages: Package[] = [];
      try {
        for (const sbomFile of sbomsToLoad) {
          const response = await fetch(`/sboms/${sbomFile}`);
          if (!response.ok) {
            throw new Error(`Failed to fetch SBOM file: ${sbomFile}`);
          }
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
            throw new Error(`Invalid SBOM format: ${sbomFile}`);
          }

          allPackages.push(...loadedPackages);
        }
        setPackages(allPackages);
      } catch (err) {
        const message =
          err instanceof Error ? err.message : "An unknown error occurred";
        console.error(`Error loading or processing SBOMs:`, message);
        setError(message);
      } finally {
        setIsLoading(false);
      }
    };

    loadBoms();
  }, [selectedSbom, sbomFiles]);

  return {
    packages,
    setPackages,
    sbomFiles,
    selectedSbom,
    setSelectedSbom,
    isLoading,
    error,
  };
}
