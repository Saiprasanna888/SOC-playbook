import React from 'react';
import { AlertPlaybook } from '@/types/alert';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { ChevronRight, Zap, Terminal, Wrench, User, Cloud, Database, Mail, Globe, ShieldAlert } from 'lucide-react';
import { Link } from 'react-router-dom';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';

interface AlertListProps {
  filteredAlerts: AlertPlaybook[];
  activeCategory: string;
  searchTerm: string;
}

type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

// Helper function to determine severity style (kept here for rendering logic)
const getSeverity = (alert: AlertPlaybook): { label: SeverityLevel; variant: string; color: string } => {
  const name = alert.name.toLowerCase();
  const description = alert.description.toLowerCase();

  if (name.includes('critical') || name.includes('ransomware') || name.includes('golden ticket') || description.includes('critical') || description.includes('immediate suspension') || description.includes('critical') || name.includes('zero-day') || name.includes('mbr')) {
    return { label: 'CRITICAL', variant: 'destructive', color: 'border-red-600 bg-red-900/10' };
  }
  if (name.includes('compromise') || name.includes('lateral movement') || name.includes('web shell') || description.includes('compromise') || description.includes('high priority') || name.includes('dumping') || name.includes('api key exposed')) {
    return { label: 'HIGH', variant: 'default', color: 'border-orange-500 bg-orange-900/10' };
  }
  if (name.includes('unusual') || name.includes('failed') || description.includes('unusual') || description.includes('medium') || name.includes('scan') || name.includes('vpn')) {
    return { label: 'MEDIUM', variant: 'secondary', color: 'border-yellow-500 bg-yellow-900/10' };
  }
  return { label: 'LOW', variant: 'outline', color: 'border-green-500 bg-green-900/10' };
};

// Helper function to map tools to icons (for visual flair)
const toolIconMap: { [key: string]: React.ElementType } = {
  'SIEM': Zap,
  'EDR': Terminal,
  'Firewall': Wrench,
  'Identity Provider': User,
  'Mail Server': Mail,
  'Cloud Provider Console': Cloud,
  'Database Audit Logs': Database,
  'Threat Intelligence Platform': Globe,
  'SOAR Platform': ShieldAlert,
};


const AlertList: React.FC<AlertListProps> = ({ filteredAlerts, activeCategory }) => {
  return (
    <div className="col-span-4 lg:col-span-3">
      <h2 className="text-2xl font-bold mb-6 text-foreground">
        {activeCategory === 'All' ? 'All Playbooks' : `${activeCategory} Alerts`} 
        <span className="text-muted-foreground ml-2 font-normal text-xl">({filteredAlerts.length})</span>
      </h2>
      
      {filteredAlerts.length === 0 ? (
        <div className="text-center py-16 border border-dashed rounded-lg mt-8 bg-muted/20">
          <p className="text-muted-foreground text-lg">
            No playbooks found matching your criteria.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {filteredAlerts.map((alert) => {
            const severity = getSeverity(alert);
            return (
              <Link key={alert.id} to={`/alert/${alert.id}`}>
                <Card 
                  className={cn(
                    "transition-all duration-300 cursor-pointer border-l-4 hover:shadow-2xl hover:scale-[1.01] hover:border-l-8",
                    severity.color
                  )}
                >
                  <CardHeader className="pb-3">
                    <div className="flex justify-between items-start">
                      <CardTitle className="text-xl font-semibold text-foreground">
                        {alert.name}
                      </CardTitle>
                      <Badge className={cn("text-xs font-medium uppercase", severity.color.split(' ')[0].replace('border-', 'bg-').replace('hover:', ''))}>
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
                        <span className="font-medium hidden sm:inline">Tools:</span>
                        {alert.tools.slice(0, 3).map((tool, index) => {
                          const toolName = tool.split('/')[0];
                          const Icon = toolIconMap[toolName] || Zap;
                          return (
                            <Badge key={index} variant="outline" className="flex items-center space-x-1 transition-colors duration-200 hover:bg-accent">
                              <Icon className="w-3 h-3" />
                              <span className="hidden sm:inline">{toolName}</span>
                            </Badge>
                          );
                        })}
                        {alert.tools.length > 3 && (
                          <span className="text-xs text-muted-foreground self-center hidden sm:inline">
                            +{alert.tools.length - 3} more
                          </span>
                        )}
                      </div>
                      <Button variant="link" className="p-0 h-auto text-primary group-hover:translate-x-1 transition-transform duration-200">
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
  );
};

export default AlertList;