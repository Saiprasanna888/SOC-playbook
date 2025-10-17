import React, { useState, useMemo } from 'react';
import { mockAlerts, categories } from '@/data/mockAlerts';
import { AlertPlaybook, AlertCategory } from '@/types/alert';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Filter, ChevronRight, Zap, Terminal, Wrench, User, BookOpen } from 'lucide-react'; // <-- Added User and BookOpen
import { Link } from 'react-router-dom';
import { cn } from '@/lib/utils';

interface AlertListProps {
  searchTerm: string;
}

// Helper function to determine severity style
const getSeverity = (alert: AlertPlaybook) => {
  const name = alert.name.toLowerCase();
  const description = alert.description.toLowerCase();

  if (name.includes('critical') || name.includes('ransomware') || name.includes('golden ticket') || description.includes('critical') || description.includes('immediate suspension')) {
    return { label: 'CRITICAL', variant: 'destructive', color: 'bg-red-600 hover:bg-red-700' };
  }
  if (name.includes('compromise') || name.includes('lateral movement') || name.includes('web shell') || description.includes('compromise') || description.includes('high priority')) {
    return { label: 'HIGH', variant: 'default', color: 'bg-orange-500 hover:bg-orange-600' };
  }
  if (name.includes('unusual') || name.includes('failed') || description.includes('unusual') || description.includes('medium')) {
    return { label: 'MEDIUM', variant: 'secondary', color: 'bg-yellow-500 hover:bg-yellow-600' };
  }
  return { label: 'LOW', variant: 'outline', color: 'bg-green-500 hover:bg-green-600' };
};

// Helper function to map tools to icons (for visual flair)
const toolIconMap: { [key: string]: React.ElementType } = {
  'SIEM': Zap,
  'EDR': Terminal,
  'Firewall': Wrench,
  'Identity Provider': User,
  'Mail Server': BookOpen,
};

const AlertList: React.FC<AlertListProps> = ({ searchTerm }) => {
  const [activeCategory, setActiveCategory] = useState<AlertCategory | 'All'>('All');

  const filteredAlerts = useMemo(() => {
    let alerts = mockAlerts;

    // 1. Filter by Category
    if (activeCategory !== 'All') {
      alerts = alerts.filter(alert => alert.category === activeCategory);
    }

    // 2. Filter by Search Term
    if (searchTerm.trim()) {
      const lowerCaseSearch = searchTerm.toLowerCase();
      alerts = alerts.filter(alert => 
        alert.name.toLowerCase().includes(lowerCaseSearch) ||
        alert.description.toLowerCase().includes(lowerCaseSearch) ||
        alert.category.toLowerCase().includes(lowerCaseSearch) ||
        alert.tools.some(tool => tool.toLowerCase().includes(lowerCaseSearch))
      );
    }

    return alerts;
  }, [searchTerm, activeCategory]);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
      {/* Sidebar for Filters */}
      <div className="lg:col-span-1">
        <Card className="sticky top-20 bg-card/80 backdrop-blur-sm border-border">
          <CardHeader>
            <CardTitle className="text-lg flex items-center text-primary">
              <Filter className="w-4 h-4 mr-2" />
              Playbook Categories
            </CardTitle>
            <CardDescription>Filter by MITRE ATT&CK stage or security domain.</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-1 max-h-[60vh] overflow-y-auto pr-2">
              {['All', ...categories].map((category) => (
                <Button
                  key={category}
                  variant="ghost"
                  className={cn(
                    "w-full justify-start text-left h-auto py-2 px-3 transition-all duration-150",
                    activeCategory === category 
                      ? "bg-primary text-primary-foreground hover:bg-primary/90 font-semibold"
                      : "text-muted-foreground hover:bg-accent"
                  )}
                  onClick={() => setActiveCategory(category as AlertCategory | 'All')}
                >
                  {category}
                </Button>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Alert Results */}
      <div className="lg:col-span-3">
        <h2 className="text-2xl font-bold mb-6 text-foreground">
          {activeCategory === 'All' ? 'All Playbooks' : `${activeCategory} Alerts`} 
          <span className="text-muted-foreground ml-2 font-normal text-xl">({filteredAlerts.length})</span>
        </h2>
        
        {filteredAlerts.length === 0 ? (
          <div className="text-center py-16 border border-dashed rounded-lg mt-8 bg-muted/20">
            <p className="text-muted-foreground text-lg">
              No playbooks found matching "{searchTerm}" in the {activeCategory} category.
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {filteredAlerts.map((alert) => {
              const severity = getSeverity(alert);
              return (
                <Link key={alert.id} to={`/alert/${alert.id}`}>
                  <Card className="hover:shadow-lg transition-all duration-200 cursor-pointer border-l-4 border-l-primary hover:border-l-4 hover:border-l-primary/80">
                    <CardHeader className="pb-3">
                      <div className="flex justify-between items-start">
                        <CardTitle className="text-xl font-semibold text-foreground">
                          {alert.name}
                        </CardTitle>
                        <Badge className={cn("text-xs font-medium uppercase", severity.color)}>
                          {severity.label}
                        </Badge>
                      </div>
                      <Badge variant="secondary" className="w-fit mt-1 text-xs font-normal">
                        {alert.category}
                      </Badge>
                    </CardHeader>
                    <CardContent className="pt-3">
                      <CardDescription className="line-clamp-2 text-sm mb-3">
                        {alert.description}
                      </CardDescription>
                      <div className="flex items-center justify-between">
                        <div className="flex space-x-2 text-muted-foreground text-sm">
                          <span className="font-medium">Tools:</span>
                          {alert.tools.slice(0, 3).map((tool, index) => {
                            const Icon = toolIconMap[tool.split('/')[0]] || Zap;
                            return (
                              <Badge key={index} variant="outline" className="flex items-center space-x-1">
                                <Icon className="w-3 h-3" />
                                <span>{tool.split('/')[0]}</span>
                              </Badge>
                            );
                          })}
                          {alert.tools.length > 3 && (
                            <span className="text-xs text-muted-foreground self-center">
                              +{alert.tools.length - 3} more
                            </span>
                          )}
                        </div>
                        <Button variant="link" className="p-0 h-auto text-primary">
                          View Playbook <ChevronRight className="w-4 h-4 ml-1" />
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                </Link>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};

export default AlertList;