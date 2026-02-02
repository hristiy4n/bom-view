import { Dependency } from "@/components/DependencyTree";
import {
  CycloneDXBom,
  SpdxBom,
  SbomFormat,
  SbomData,
  Package,
  Component,
  SpdxPackage,
  SpdxRelationship,
  SBOMVulnerability,
} from "./types";

export const identifySbomFormat = (data: SbomData): SbomFormat => {
  if (data.bomFormat === "CycloneDX") {
    return SbomFormat.CycloneDX;
  }
  if (data.spdxVersion) {
    return SbomFormat.SPDX;
  }
  return SbomFormat.Unsupported;
};

export const processCycloneDxData = (
  data: CycloneDXBom,
  sourceName: string,
): Package[] => {
  const componentsMap = new Map<string, Component>();
  data.components.forEach((component) => {
    componentsMap.set(component["bom-ref"], component);
  });

  const dependencyMap = new Map<string, string[]>();
  if (data.dependencies) {
    data.dependencies.forEach((dep) => {
      dependencyMap.set(dep.ref, dep.dependsOn || []);
    });
  }

  const componentVulnerabilitiesMap = new Map<string, SBOMVulnerability[]>();
  if (data.vulnerabilities) {
    data.vulnerabilities.forEach((sbomVulnerability) => {
      if (sbomVulnerability.affects && sbomVulnerability.affects.length > 0) {
        sbomVulnerability.affects.forEach((affected) => {
          if (affected.ref) {
            const bomRef = affected.ref.split("?")[0];
            if (!componentVulnerabilitiesMap.has(bomRef)) {
              componentVulnerabilitiesMap.set(bomRef, []);
            }
            componentVulnerabilitiesMap.get(bomRef)!.push(sbomVulnerability);
          }
        });
      }
    });
  }

  const buildDependencyTree = (
    bomRef: string,
    visited: Set<string> = new Set(),
  ): Dependency => {
    const component = componentsMap.get(bomRef);
    if (!component) {
      return { name: bomRef, version: "unknown", children: [] };
    }

    if (visited.has(bomRef)) {
      return {
        name: component.name,
        version: component.version,
        children: [],
      };
    }
    visited.add(bomRef);

    const dependencyRefs = dependencyMap.get(bomRef) || [];
    const children = dependencyRefs
      .map((childRef) => buildDependencyTree(childRef, new Set(visited)))
      .filter((child) => child !== null) as Dependency[];

    return {
      name: component.name,
      version: component.version,
      children: children,
    };
  };

  return data.components
    .filter((component) => component.type !== "file")
    .map((component) => {
      let license = "N/A";
      if (component.licenses && component.licenses.length > 0) {
        const licenseEntry = component.licenses[0];
        if (licenseEntry.license) {
          license =
            licenseEntry.license.id || licenseEntry.license.name || "N/A";
        } else if (licenseEntry.expression) {
          license = licenseEntry.expression;
        }
      }

      const componentBomRef = component["bom-ref"].split("?")[0];
      const sbomVulnerabilities =
        componentVulnerabilitiesMap.get(componentBomRef) || [];

      return {
        id: `${sourceName}:${component["bom-ref"]}`,
        bomRef: component["bom-ref"],
        name: component.name,
        version: component.version,
        source: sourceName,
        license: license,
        description: component.description || "No description available.",
        dependencies: buildDependencyTree(component["bom-ref"]),
        vulnerabilities: [],
        sbomVulnerabilities: sbomVulnerabilities,
        scanned: data.vulnerabilities && data.vulnerabilities.length > 0,
      };
    });
};

export const processSpdxData = (
  data: SpdxBom,
  sourceName: string,
): Package[] => {
  const spdxPackagesMap = new Map<string, SpdxPackage>();
  data.packages.forEach((pkg) => {
    spdxPackagesMap.set(pkg.SPDXID, pkg);
  });

  const dependencyMap = new Map<string, string[]>();
  if (data.relationships) {
    for (const rel of data.relationships) {
      let parentId: string | undefined;
      let childId: string | undefined;

      if (
        rel.relationshipType === "DEPENDS_ON" ||
        rel.relationshipType === "CONTAINS"
      ) {
        parentId = rel.spdxElementId;
        childId = rel.relatedSpdxElement;
      } else if (rel.relationshipType === "DEPENDENCY_OF") {
        parentId = rel.relatedSpdxElement;
        childId = rel.spdxElementId;
      }

      if (parentId && childId) {
        if (!dependencyMap.has(parentId)) {
          dependencyMap.set(parentId, []);
        }
        dependencyMap.get(parentId)!.push(childId);
      }
    }
  }

  const buildSpdxDependencyTree = (
    spdxElementId: string,
    visited: Set<string> = new Set(),
  ): Dependency => {
    const pkg = spdxPackagesMap.get(spdxElementId);
    if (!pkg) {
      return { name: spdxElementId, version: "unknown", children: [] };
    }

    if (visited.has(spdxElementId)) {
      return { name: pkg.name, version: pkg.versionInfo, children: [] };
    }
    visited.add(spdxElementId);

    const childrenIds = dependencyMap.get(spdxElementId) || [];
    const children = childrenIds
      .filter((childId) => spdxPackagesMap.has(childId))
      .map((childId) => buildSpdxDependencyTree(childId, visited));

    return {
      name: pkg.name,
      version: pkg.versionInfo,
      children: children,
    };
  };

  return data.packages.map((pkg) => {
    const purlRef = pkg.externalRefs?.find(
      (ref) => ref.referenceType === "purl",
    );
    return {
      id: `${sourceName}:${pkg.SPDXID}`,
      bomRef: purlRef?.referenceLocator || pkg.SPDXID,
      name: pkg.name,
      version: pkg.versionInfo,
      source: sourceName,
      license:
        pkg.licenseDeclared === "NOASSERTION"
          ? "N/A"
          : pkg.licenseDeclared || "N/A",
      description: pkg.description || "No description available.",
      dependencies: buildSpdxDependencyTree(pkg.SPDXID),
      vulnerabilities: [],
      sbomVulnerabilities: [],
      scanned: false,
    };
  });
};
