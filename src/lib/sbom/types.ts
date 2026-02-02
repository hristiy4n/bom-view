import { Dependency } from "@/components/DependencyTree";
import { OSVulnerability } from "@/types/osv";

export interface LicenseChoice {
  license?: {
    id?: string;
    name?: string;
  };
  expression?: string;
}

export interface Component {
  type: string;
  name: string;
  version: string;
  licenses?: LicenseChoice[];
  "bom-ref": string;
  description: string;
}

export interface BomDependency {
  ref: string;
  dependsOn?: string[];
}

export interface CycloneDXBom {
  bomFormat: "CycloneDX";
  metadata: {
    component: {
      name: string;
      version: string;
    };
  };
  components: Component[];
  dependencies?: BomDependency[];
  vulnerabilities?: SBOMVulnerability[];
}

export interface SpdxPackage {
  name: string;
  SPDXID: string;
  versionInfo: string;
  licenseDeclared: string;
  description: string;
  externalRefs?: {
    referenceCategory: string;
    referenceType: string;
    referenceLocator: string;
  }[];
}

export interface SpdxRelationship {
  spdxElementId: string;
  relationshipType: string;
  relatedSpdxElement: string;
}

export interface SpdxBom {
  spdxVersion: string;
  packages: SpdxPackage[];
  relationships?: SpdxRelationship[];
}

export interface SBOMVulnerabilityRating {
  source?: {
    name?: string;
    url?: string;
  };
  score?: number;
  severity?: string;
  method?: string;
  vector?: string;
}

export interface SBOMVulnerabilityAdvisory {
  url?: string;
}

export interface SBOMVulnerabilityAffectedVersion {
  version?: string;
  status?: string;
}

export interface SBOMVulnerabilityAffected {
  ref?: string;
  versions?: SBOMVulnerabilityAffectedVersion[];
}

export interface SBOMVulnerability {
  id?: string;
  source?: {
    name?: string;
    url?: string;
  };
  ratings?: SBOMVulnerabilityRating[];
  cwes?: number[];
  description?: string;
  recommendation?: string;
  advisories?: SBOMVulnerabilityAdvisory[];
  published?: string;
  updated?: string;
  affects?: SBOMVulnerabilityAffected[];
}

export interface Package {
  id: string;
  bomRef: string;
  name: string;
  version: string;
  source: string;
  license: string;
  description: string;
  dependencies: Dependency;
  vulnerabilities: OSVulnerability[];
  sbomVulnerabilities: SBOMVulnerability[];
  scanned: boolean;
}

export enum SbomFormat {
  CycloneDX,
  SPDX,
  Unsupported,
}

export type SbomData = {
  bomFormat?: "CycloneDX";
  spdxVersion?: string;
};
