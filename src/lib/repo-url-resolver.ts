const PURL_REGEX = /^pkg:(npm|pypi|gem|nuget|golang|cargo)\/(.*)/;

type PackageType = "npm" | "pypi" | "gem" | "nuget" | "golang" | "cargo";

export const getRepoUrl = async (
  pkgType: PackageType,
  pkgName: string,
  pkgVersion?: string,
): Promise<string | null> => {
  try {
    switch (pkgType) {
      case "npm": {
        const npmResponse = await fetch(
          `https://registry.npmjs.org/${pkgName}/${pkgVersion}`,
        );
        if (!npmResponse.ok) return null;
        const npmData = await npmResponse.json();
        return npmData.repository?.url;
      }
      case "pypi": {
        const pypiResponse = await fetch(
          `https://pypi.org/pypi/${pkgName}/${pkgVersion}/json`,
        );
        if (!pypiResponse.ok) return null;
        const pypiData = await pypiResponse.json();
        const urls = pypiData.info?.project_urls;
        return (
          urls?.["Source"] ||
          urls?.["Source Code"] ||
          urls?.["Homepage"] ||
          null
        );
      }
      case "gem": {
        const gemResponse = await fetch(
          `https://rubygems.org/api/v1/gems/${pkgName}.json`,
        );
        if (!gemResponse.ok) return null;
        const gemData = await gemResponse.json();
        return gemData.source_code_uri || gemData.homepage_uri || null;
      }
      case "nuget": {
        if (!pkgVersion) return null;
        const registrationResponse = await fetch(
          `https://api.nuget.org/v3/registration5-semver1/${pkgName.toLowerCase()}/${pkgVersion}.json`,
        );
        if (!registrationResponse.ok) return null;
        const registrationData = await registrationResponse.json();

        const catalogEntryUrl = registrationData.catalogEntry;
        if (!catalogEntryUrl) return null;

        const catalogEntryResponse = await fetch(catalogEntryUrl);
        if (!catalogEntryResponse.ok) return null;
        const catalogEntryData = await catalogEntryResponse.json();

        return (
          catalogEntryData.repository?.url ||
          catalogEntryData.projectUrl ||
          null
        );
      }
      case "golang": {
        if (pkgName.startsWith("github.com")) {
          return `https://${pkgName}`;
        }
        const goGetResponse = await fetch(`https://${pkgName}?go-get=1`);
        if (!goGetResponse.ok) return null;
        const goGetData = await goGetResponse.text();
        const match = goGetData.match(
          /<meta name="go-import" content="([^ ]+? [^ ]+? [^ ]+?)">/,
        );
        if (match && match[1]) {
          const parts = match[1].split(" ");
          if (parts.length === 3) {
            return parts[2];
          }
        }
        return null;
      }
      case "cargo": {
        if (!pkgVersion) return null;
        const cargoResponse = await fetch(
          `https://crates.io/api/v1/crates/${pkgName}/${pkgVersion}`,
        );
        if (!cargoResponse.ok) return null;
        const cargoData = await cargoResponse.json();
        return cargoData.crate.repository || null;
      }
      default:
        return null;
    }
  } catch {
    return null;
  }
};

export { PURL_REGEX, PackageType };
