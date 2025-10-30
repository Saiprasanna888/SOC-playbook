import React from 'react';
import { Filter } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { AlertCategory } from '@/types/alert';

type SeverityLevel = 'All' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

interface SeverityOption {
  label: SeverityLevel;
  color: string;
}

interface PlaybookFiltersProps {
  categories: (AlertCategory | 'All')[];
  activeCategory: AlertCategory | 'All';
  setActiveCategory: (category: AlertCategory | 'All') => void;
  severityOptions: SeverityOption[];
  activeSeverity: SeverityLevel;
  setActiveSeverity: (severity: SeverityLevel) => void;
}

const PlaybookFilters: React.FC<PlaybookFiltersProps> = ({
  categories,
  activeCategory,
  setActiveCategory,
  severityOptions,
  activeSeverity,
  setActiveSeverity
}) => {
  return (
    <Card className="sticky top-20 bg-card/80 backdrop-blur-sm border-border">
      <CardHeader>
        <CardTitle className="text-lg flex items-center text-primary">
          <Filter className="w-4 h-4 mr-2" />
          Playbook Filters
        </CardTitle>
        <CardDescription>Filter by security domain and severity level.</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-6">
          {/* Severity Filter */}
          <div>
            <h3 className="text-sm font-semibold text-muted-foreground mb-2">Severity</h3>
            <div className="flex flex-wrap gap-2">
              {severityOptions.map((severity) => (
                <Badge
                  key={severity.label}
                  className={cn(
                    "cursor-pointer transition-all duration-150 text-xs font-medium uppercase px-3 py-1",
                    severity.label === activeSeverity 
                      ? severity.color + " text-primary-foreground shadow-md scale-[1.05]"
                      : "bg-muted text-muted-foreground hover:bg-accent border border-border hover:scale-[1.02]"
                  )}
                  onClick={() => setActiveSeverity(severity.label)}
                >
                  {severity.label}
                </Badge>
              ))}
            </div>
          </div>

          {/* Category Filter */}
          <div>
            <h3 className="text-sm font-semibold text-muted-foreground mb-2">Category</h3>
            <div className="space-y-1 max-h-[40vh] overflow-y-auto pr-2">
              {categories.map((category) => (
                <Button
                  key={category}
                  variant="ghost"
                  className={cn(
                    "w-full justify-start text-left h-auto py-2 px-3 transition-all duration-150",
                    activeCategory === category 
                      ? "bg-primary text-primary-foreground hover:bg-primary/90 font-semibold shadow-md"
                      : "text-muted-foreground hover:bg-accent hover:text-foreground"
                  )}
                  onClick={() => setActiveCategory(category as AlertCategory | 'All')}
                >
                  {category}
                </Button>
              ))}
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

export default PlaybookFilters;