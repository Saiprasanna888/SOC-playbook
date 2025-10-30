import React from 'react';
import { TerminalSquare, Filter, BookOpen, GraduationCap } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';

interface SidebarNavigationProps {
  activeTab: 'filters' | 'tools' | 'terms';
  setActiveTab: (tab: 'filters' | 'tools' | 'terms') => void;
}

const SidebarNavigation: React.FC<SidebarNavigationProps> = ({ activeTab, setActiveTab }) => {
  
  const baseClasses = "w-full justify-start text-left h-12 px-4 transition-all duration-300 font-semibold text-base";
  const activeClasses = "bg-primary text-primary-foreground shadow-lg shadow-primary/50 border-l-4 border-primary";
  const inactiveClasses = "bg-muted/50 text-muted-foreground hover:bg-accent hover:text-foreground border-l-4 border-transparent";

  return (
    <div className="flex flex-col space-y-3 p-4 bg-card border-r border-border/50 h-full">
      <h3 className="text-sm font-bold uppercase text-muted-foreground mb-2 hidden lg:block">Navigation</h3>
      
      <Button
        variant="ghost"
        className={cn(baseClasses, activeTab === 'filters' ? activeClasses : inactiveClasses)}
        onClick={() => setActiveTab('filters')}
      >
        <Filter className="w-4 h-4 mr-3" />
        Playbook Filters
      </Button>

      <Button
        variant="ghost"
        className={cn(baseClasses, activeTab === 'tools' ? activeClasses : inactiveClasses)}
        onClick={() => setActiveTab('tools')}
      >
        <TerminalSquare className="w-4 h-4 mr-3" />
        SOC Tools Dictionary
      </Button>

      <Button
        variant="ghost"
        className={cn(baseClasses, activeTab === 'terms' ? activeClasses : inactiveClasses)}
        onClick={() => setActiveTab('terms')}
      >
        <GraduationCap className="w-4 h-4 mr-3" />
        Must-Know SOC Terms
      </Button>
    </div>
  );
};

export default SidebarNavigation;