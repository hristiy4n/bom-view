import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from "@/components/ui/sheet";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { columns } from "@/data/columns";

interface FilterSidebarProps {
  open: boolean;
  onClose: () => void;
  visibleColumns: string[];
  onColumnChange: (columnId: string) => void;
  showVulnerableOnly: boolean;
  onShowVulnerableChange: (value: boolean) => void;
}

export function FilterSidebar({
  open,
  onClose,
  visibleColumns,
  onColumnChange,
  showVulnerableOnly,
  onShowVulnerableChange,
}: FilterSidebarProps) {
  return (
    <Sheet open={open} onOpenChange={onClose}>
      <SheetContent className="bg-card border-border w-80">
        <SheetHeader>
          <SheetTitle className="text-foreground">Filters & Columns</SheetTitle>
          <SheetDescription className="text-muted-foreground">
            Manage visible columns and apply filters to the package list.
          </SheetDescription>
        </SheetHeader>

        <div className="mt-6 space-y-6">
          <div className="space-y-3">
            <h3 className="text-sm font-medium text-foreground">Filters</h3>
            <div className="space-y-3">
              <div className="flex items-center space-x-2">
                <Checkbox
                  id="vulnerable-only"
                  checked={showVulnerableOnly}
                  onCheckedChange={(checked) =>
                    onShowVulnerableChange(checked === true)
                  }
                />
                <Label
                  htmlFor="vulnerable-only"
                  className="text-sm text-muted-foreground cursor-pointer"
                >
                  Show vulnerable packages only
                </Label>
              </div>
            </div>
          </div>

          <Separator className="bg-border" />

          <div className="space-y-3">
            <h3 className="text-sm font-medium text-foreground">
              Visible Columns
            </h3>
            <div className="space-y-2">
              {columns.map((column) => (
                <div key={column.id} className="flex items-center space-x-2">
                  <Checkbox
                    id={`column-${column.id}`}
                    checked={visibleColumns.includes(column.id)}
                    onCheckedChange={() => onColumnChange(column.id)}
                  />
                  <Label
                    htmlFor={`column-${column.id}`}
                    className="text-sm text-muted-foreground cursor-pointer"
                  >
                    {column.label}
                  </Label>
                </div>
              ))}
            </div>
          </div>
        </div>
      </SheetContent>
    </Sheet>
  );
}
