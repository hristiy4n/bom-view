import { AppHeader } from "@/components/AppHeader";
import { PackageTable } from "@/components/PackageTable";
import { useSbomData } from "@/hooks/useSbomData";
import { useOsvScanner } from "@/hooks/useOsvScanner";

interface PackagesProps {
  sbomData: ReturnType<typeof useSbomData>;
  osvScanner: ReturnType<typeof useOsvScanner>;
}

const Packages = ({ sbomData, osvScanner }: PackagesProps) => {
  return (
    <div className="min-h-screen bg-background">
      <AppHeader />

      <main className="container mx-auto px-4 py-8">
        <PackageTable sbomData={sbomData} osvScanner={osvScanner} />
      </main>
    </div>
  );
};

export default Packages;
