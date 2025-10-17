import React from 'react';
import { Filter, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Drawer, DrawerContent, DrawerHeader, DrawerTitle, DrawerTrigger } from '@/components/ui/drawer';
import { Card, CardContent, CardTitle } from '@/components/ui/card';
import { cn } from '@/lib/utils';
import { AlertCategory } from '@/types/alert';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';

type SeverityLevel = 'All' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

interface SeverityOption {
  label: SeverityLevel;
  color: string;
}

interface MobileFilterProps {
  categories: (AlertCategory | 'All')[];
  activeCategory: AlertCategory | 'All';
  setActiveCategory: (category: AlertCategory | 'All') => void;
  severityOptions: SeverityOption[];
  activeSeverity: SeverityLevel;
  setActiveSeverity: (severity: SeverityLevel) => void;
}

const MobileFilter: React.FC<MobileFilterProps> = ({ 
  categories, 
  activeCategory, 
  setActiveCategory,
  severityOptions,
  activeSeverity,
  setActiveSeverity
}) => {
  const [open, setOpen] = React.useState(false);

  const handleCategoryClick = (category: AlertCategory | 'All') => {
    setActiveCategory(category);
    setOpen(false);
  };

  const handleSeverityClick = (severity: SeverityLevel) => {
    setActiveSeverity(severity);
    setOpen(false);
  };

  return (
    <Drawer open={open} onOpenChange={setOpen}>
      <DrawerTrigger asChild>
        <Button variant="outline" className="w-full flex items-center justify-center lg:hidden">
          <Filter className="w-4 h-4 mr-2" />
          Filter Playbooks ({activeCategory === 'All' ? 'All' : activeCategory})
        </Button>
      </DrawerTrigger>
      <DrawerContent>
        <div className="mx-auto w-full max-w-sm">
          <DrawerHeader className="flex justify-between items-center">
            <DrawerTitle className="flex items-center text-lg">
              <Filter className="w-4 h-4 mr-2 text-primary" />
              Filter Categories
            </DrawerTitle>
            <Button variant="ghost" size="icon" onClick={() => setOpen(false)}>
              <X className="w-4 h-4" />
            </Button>
          </DrawerHeader>
          <Card className="border-none shadow-none">
            <CardContent className="p-4 max-h-[70vh] overflow-y-auto">
              
              {/* Severity Filter */}
              <div className="mb-6">
                <h3 className="text-sm font-semibold text-muted-foreground mb-2">Severity</h3>
                <div className="flex flex-wrap gap-2">
                  {severityOptions.map((severity) => (
                    <Badge
                      key={severity.label}
                      className={cn(
                        "cursor-pointer transition-all duration-150 text-xs font-medium uppercase px-3 py-1",
                        severity.label === activeSeverity 
                          ? severity.color + " text-primary-foreground"
                          : "bg-muted text-muted-foreground hover:bg-accent border border-border"
                      )}
                      onClick={() => handleSeverityClick(severity.label)}
                    >
                      {severity.label}
                    </Badge>
                  ))}
                </div>
              </div>
              
              <Separator className="my-4" />

              {/* Category Filter */}
              <div>
                <h3 className="text-sm font-semibold text-muted-foreground mb-2">Category</h3>
                <div className="space-y-1">
                  {categories.map((category) => (
                    <Button
                      key={category}
                      variant="ghost"
                      className={cn(
                        "w-full justify-start text-left h-auto py-2 px-3 transition-all duration-150",
                        activeCategory === category 
                          ? "bg-primary text-primary-foreground hover:bg-primary/90 font-semibold"
                          : "text-muted-foreground hover:bg-accent"
                      )}
                      onClick={() => handleCategoryClick(category)}
                    >
                      {category}
                    </Button>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </DrawerContent>
    </Drawer>
  );
};

export default MobileFilter;