import { Package } from "@/lib/sbom/types";
import { ecosystemMapping } from "@/lib/ecosystems";

export interface BreakdownEntry {
  label: string;
  count: number;
}

export const UNKNOWN_LICENSE_LABEL = "N/A";
export const UNKNOWN_ECOSYSTEM_LABEL = "Unknown";

const rankWithUnknownLast = (
  counts: Map<string, number>,
  unknownLabel: string,
  unknownCount: number,
  topN: number,
): BreakdownEntry[] => {
  const sorted = [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([label, count]) => ({ label, count }));

  const result =
    sorted.length <= topN
      ? sorted
      : [
          ...sorted.slice(0, topN),
          {
            label: "Other",
            count: sorted
              .slice(topN)
              .reduce((acc, entry) => acc + entry.count, 0),
          },
        ];

  if (unknownCount > 0) {
    result.push({ label: unknownLabel, count: unknownCount });
  }

  return result;
};

export const computeLicenseBreakdown = (
  packages: Package[],
  topN = 7,
): BreakdownEntry[] => {
  const counts = new Map<string, number>();
  let unknownCount = 0;
  packages.forEach((pkg) => {
    if (!pkg.license || pkg.license === UNKNOWN_LICENSE_LABEL) {
      unknownCount++;
      return;
    }
    counts.set(pkg.license, (counts.get(pkg.license) || 0) + 1);
  });

  return rankWithUnknownLast(counts, UNKNOWN_LICENSE_LABEL, unknownCount, topN);
};

export const computeEcosystemBreakdown = (
  packages: Package[],
  topN = 8,
): BreakdownEntry[] => {
  const counts = new Map<string, number>();
  let unknownCount = 0;
  packages.forEach((pkg) => {
    const purlType = pkg.bomRef.match(/pkg:([^/]+)/)?.[1];
    const ecosystem = purlType ? ecosystemMapping[purlType] : undefined;
    if (!ecosystem) {
      unknownCount++;
      return;
    }
    counts.set(ecosystem, (counts.get(ecosystem) || 0) + 1);
  });

  return rankWithUnknownLast(
    counts,
    UNKNOWN_ECOSYSTEM_LABEL,
    unknownCount,
    topN,
  );
};

export interface VersionSkewOccurrence {
  version: string;
  sources: string[];
}

export interface VersionSkewEntry {
  name: string;
  versions: string[];
  occurrences: VersionSkewOccurrence[];
}

export const computeVersionSkew = (packages: Package[]): VersionSkewEntry[] => {
  const versionsByName = new Map<string, Map<string, Set<string>>>();
  packages.forEach((pkg) => {
    if (!versionsByName.has(pkg.name)) {
      versionsByName.set(pkg.name, new Map());
    }
    const versionMap = versionsByName.get(pkg.name)!;
    if (!versionMap.has(pkg.version)) {
      versionMap.set(pkg.version, new Set());
    }
    versionMap.get(pkg.version)!.add(pkg.source);
  });

  return [...versionsByName.entries()]
    .filter(([, versionMap]) => versionMap.size > 1)
    .map(([name, versionMap]) => {
      const occurrences = [...versionMap.entries()]
        .map(([version, sources]) => ({
          version,
          sources: [...sources].sort(),
        }))
        .sort((a, b) => a.version.localeCompare(b.version));

      return {
        name,
        versions: occurrences.map((occurrence) => occurrence.version),
        occurrences,
      };
    })
    .sort(
      (a, b) =>
        b.versions.length - a.versions.length || a.name.localeCompare(b.name),
    );
};

export const computeSbomDistribution = (
  packages: Package[],
  sbomFiles: string[],
): BreakdownEntry[] => {
  const counts = new Map<string, number>();
  sbomFiles.forEach((file) => counts.set(file, 0));
  packages.forEach((pkg) => {
    counts.set(pkg.source, (counts.get(pkg.source) || 0) + 1);
  });

  return [...counts.entries()]
    .map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count);
};
