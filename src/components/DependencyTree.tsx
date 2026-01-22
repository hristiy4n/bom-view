export interface Dependency {
  name: string;
  version: string;
  children?: Dependency[];
}
import { ChevronRight, Package } from "lucide-react";
import { useState } from "react";
import { cn } from "@/lib/utils";

interface DependencyNodeProps {
  dependency: Dependency;
  isRoot?: boolean;
  level?: number;
}

function DependencyNode({
  dependency,
  isRoot = false,
  level = 0,
}: DependencyNodeProps) {
  const [isExpanded, setIsExpanded] = useState(true);
  const hasChildren = dependency.children && dependency.children.length > 0;

  return (
    <div className="select-none">
      <div
        className={cn(
          "flex items-center gap-2 py-2 px-3 rounded-md transition-colors",
          "hover:bg-accent/50 cursor-pointer",
          isRoot && "bg-primary/10 border border-primary/20",
        )}
        style={{ marginLeft: level * 24 }}
        onClick={() => hasChildren && setIsExpanded(!isExpanded)}
      >
        {hasChildren && (
          <ChevronRight
            className={cn(
              "h-4 w-4 text-muted-foreground transition-transform",
              isExpanded && "rotate-90",
            )}
          />
        )}
        {!hasChildren && <div className="w-4" />}

        <Package
          className={cn(
            "h-4 w-4",
            isRoot ? "text-primary" : "text-muted-foreground",
          )}
        />

        <span
          className={cn(
            "font-mono text-sm",
            isRoot ? "text-primary font-medium" : "text-foreground",
          )}
        >
          {dependency.name}
        </span>

        <span className="font-mono text-xs text-muted-foreground">
          @{dependency.version}
        </span>
      </div>

      {hasChildren && isExpanded && (
        <div className="border-l border-border ml-6">
          {dependency.children!.map((child, index) => (
            <DependencyNode
              key={`${child.name}-${index}`}
              dependency={child}
              level={level + 1}
            />
          ))}
        </div>
      )}
    </div>
  );
}

interface DependencyTreeProps {
  rootDependency: Dependency;
}

export function DependencyTree({ rootDependency }: DependencyTreeProps) {
  return (
    <div className="bg-card rounded-lg border border-border p-4">
      <DependencyNode dependency={rootDependency} isRoot />
    </div>
  );
}
