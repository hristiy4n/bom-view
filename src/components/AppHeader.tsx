import { NavLink } from "react-router-dom";
import { LayoutDashboard, Package as PackageIcon, Shield } from "lucide-react";
import { cn } from "@/lib/utils";

const navLinkClass = ({ isActive }: { isActive: boolean }) =>
  cn(
    "flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-medium transition-colors",
    isActive
      ? "bg-primary/10 text-primary"
      : "text-muted-foreground hover:text-foreground",
  );

export function AppHeader() {
  return (
    <header className="border-b border-border surface-elevated">
      <div className="container mx-auto px-4 py-4 flex flex-wrap items-center justify-between gap-4">
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
        <nav className="flex items-center gap-1">
          <NavLink to="/" end className={navLinkClass}>
            <LayoutDashboard className="h-4 w-4" />
            Dashboard
          </NavLink>
          <NavLink to="/packages" className={navLinkClass}>
            <PackageIcon className="h-4 w-4" />
            Packages
          </NavLink>
        </nav>
      </div>
    </header>
  );
}
