import React from 'react';
import { TerminalSquare, Zap, Shield, AlertTriangle, Flame, Globe, BookOpen, X, Settings, Brain } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { cn } from '@/lib/utils';

interface ToolCategory {
  title: string;
  icon: React.ElementType;
  description: string;
  color: string;
}

const toolCategories: ToolCategory[] = [
  { title: 'SIEM Tools', icon: Brain, description: 'Placeholder for SIEM tool descriptions.', color: 'text-cyan-400' },
  { title: 'SOAR Tools', icon: Settings, description: 'Placeholder for SOAR tool descriptions.', color: 'text-indigo-400' },
  { title: 'EDR Tools', icon: Shield, description: 'Placeholder for EDR tool descriptions.', color: 'text-green-400' },
  { title: 'IDS / IPS Tools', icon: AlertTriangle, description: 'Placeholder for IDS/IPS tool descriptions.', color: 'text-red-400' },
  { title: 'Firewalls', icon: Flame, description: 'Placeholder for Firewall tool descriptions.', color: 'text-orange-400' },
  { title: 'Network Models', icon: Globe, description: 'Placeholder for Network Model descriptions.', color: 'text-blue-400' },
  { title: 'Frameworks & Standards', icon: BookOpen, description: 'Placeholder for Frameworks & Standards descriptions.', color: 'text-yellow-400' },
];

const SocCoreToolsMenu: React.FC = () => {
  const [open, setOpen] = React.useState(false);

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="default" className="w-full lg:w-auto flex items-center justify-center bg-primary hover:bg-primary/90 text-primary-foreground transition-all duration-300 shadow-lg hover:shadow-xl">
          <TerminalSquare className="w-4 h-4 mr-2" />
          SOC Core Security Tools
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-[800px] max-h-[90vh] overflow-y-auto p-6 bg-card border-border/50">
        <DialogHeader className="border-b border-border/50 pb-4">
          <DialogTitle className="text-2xl font-bold flex items-center text-foreground">
            <TerminalSquare className="w-5 h-5 mr-3 text-primary" />
            SOC Core Security Tools Dictionary
          </DialogTitle>
          <p className="text-muted-foreground text-sm">
            Explore key tools, platforms, and frameworks used in modern Security Operations Centers.
          </p>
        </DialogHeader>
        
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 py-4">
          {toolCategories.map((category) => (
            <Card 
              key={category.title} 
              className={cn(
                "group cursor-pointer transition-all duration-300 hover:shadow-primary/50 hover:shadow-lg border-border/50",
                "hover:border-primary/80"
              )}
            >
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-lg font-semibold text-foreground">
                  {category.title}
                </CardTitle>
                <category.icon className={cn("h-6 w-6 transition-colors duration-300", category.color, "group-hover:text-primary")} />
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground">
                  {category.description}
                </p>
                <Button variant="link" className="p-0 h-auto mt-2 text-primary">
                    View Details
                </Button>
              </CardContent>
            </Card>
          ))}
        </div>
        
        <div className="flex justify-end pt-4">
          <Button variant="outline" onClick={() => setOpen(false)}>
            <X className="w-4 h-4 mr-2" /> Close
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
};

export default SocCoreToolsMenu;