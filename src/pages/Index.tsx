import { PackageTable } from "@/components/PackageTable";
import { Shield } from "lucide-react";

const Index = () => {
  return (
    <div className="min-h-screen bg-background">
      <header className="border-b border-border surface-elevated">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-lg bg-primary/10 flex items-center justify-center glow-primary">
              <Shield className="h-6 w-6 text-primary" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-foreground">BomView</h1>
              <p className="text-sm text-muted-foreground">
                Dependency Security Dashboard
              </p>
            </div>
          </div>
        </div>
      </header>

      <main className="container mx-auto px-4 py-8">
        <PackageTable />
      </main>
    </div>
  );
};

export default Index;
