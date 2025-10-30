import React, { useState, useMemo } from 'react';
import { mockAlerts, categories } from '@/data/mockAlerts';
import { AlertPlaybook, AlertCategory } from '@/types/alert';
import AlertList from './AlertList';
import PlaybookFilters from './PlaybookFilters';
import MobileFilter from './MobileFilter';
import { Input } from './ui/input';
import { Search } from 'lucide-react';

interface PlaybookViewProps {
  searchTerm: string;
  onSearchChange: (term: string) => void;
}

type SeverityLevel = 'All' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

// Helper function to determine severity style (copied from AlertList for filtering logic)
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

const severityOptions: { label: SeverityLevel, color: string }[] = [
  { label: 'All', color: 'bg-muted text-muted-foreground' },
  { label: 'CRITICAL', color: 'bg-red-600 hover:bg-red-700' },
  { label: 'HIGH', color: 'bg-orange-500 hover:bg-orange-600' },
  { label: 'MEDIUM', color: 'bg-yellow-500 hover:bg-yellow-600' },
  { label: 'LOW', color: 'bg-green-500 hover:bg-green-600' },
];

const PlaybookView: React.FC<PlaybookViewProps> = ({ searchTerm, onSearchChange }) => {
  const [activeCategory, setActiveCategory] = useState<AlertCategory | 'All'>('All');
  const [activeSeverity, setActiveSeverity] = useState<SeverityLevel>('All');

  const filteredAlerts = useMemo(() => {
    let alerts = mockAlerts;

    // 1. Filter by Category
    if (activeCategory !== 'All') {
      alerts = alerts.filter(alert => alert.category === activeCategory);
    }

    // 2. Filter by Severity
    if (activeSeverity !== 'All') {
      alerts = alerts.filter(alert => getSeverity(alert).label === activeSeverity);
    }

    // 3. Filter by Search Term
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
  }, [searchTerm, activeCategory, activeSeverity]);

  const allCategories = ['All', ...categories] as (AlertCategory | 'All')[];

  return (
    <div className="p-4 transition-opacity duration-500">
      <header className="text-center mb-8">
        <h1 className="text-4xl font-extrabold tracking-tight lg:text-5xl text-foreground">
          SOC Analyst Alert Dictionary
        </h1>
        <p className="text-lg text-muted-foreground mt-2">
          Quickly find playbooks and response steps for common security alerts.
        </p>
      </header>

      {/* Search Bar (Visible on all screens in this view) */}
      <div className="max-w-3xl mx-auto mb-8 relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input
          placeholder="Search alerts, tools, or keywords..."
          className="pl-9 h-10 w-full bg-muted/50 border-border focus-visible:ring-primary transition-all duration-300 hover:bg-muted"
          value={searchTerm}
          onChange={(e) => onSearchChange(e.target.value)}
        />
      </div>

      {/* Mobile Filter (Replaces desktop sidebar on small screens) */}
      <div className="lg:hidden mb-6">
        <MobileFilter 
          categories={allCategories}
          activeCategory={activeCategory}
          setActiveCategory={setActiveCategory}
          severityOptions={severityOptions}
          activeSeverity={activeSeverity}
          setActiveSeverity={setActiveSeverity}
        />
      </div>

      {/* Desktop Layout: Filters + List */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
        
        {/* Filters (Desktop Only) */}
        <div className="hidden lg:block lg:col-span-1">
          <PlaybookFilters
            categories={allCategories}
            activeCategory={activeCategory}
            setActiveCategory={setActiveCategory}
            severityOptions={severityOptions}
            activeSeverity={activeSeverity}
            setActiveSeverity={setActiveSeverity}
          />
        </div>

        {/* Alert List */}
        <AlertList 
          filteredAlerts={filteredAlerts} 
          activeCategory={activeCategory} 
          searchTerm={searchTerm} 
        />
      </div>
    </div>
  );
};

export default PlaybookView;