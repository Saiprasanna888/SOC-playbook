import React, { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { cn } from '@/lib/utils';
import { BookOpen, Zap, Shield, Terminal, ChevronRight, GraduationCap, ArrowLeft } from 'lucide-react';
import { Button } from '@/components/ui/button';
import TermList from './TermList';
import PortList from './PortList';
import AttackList from './AttackList'; // Import the new component
import { coreTerms } from '@/data/socTermsData';

interface TermCategory {
  id: 'terms' | 'ports' | 'attacks' | 'protocols';
  title: string;
  description: string;
  icon: React.ElementType;
  color: string;
  data?: any; // Placeholder for future data
}

const termCategories: TermCategory[] = [
  {
    id: 'terms',
    title: 'Core Terms & Concepts',
    description: 'Definitions for common security terms, acronyms, and concepts (e.g., IOC, TTP, Dwell Time).',
    icon: BookOpen,
    color: 'text-cyan-500',
    data: coreTerms,
  },
  {
    id: 'ports',
    title: 'Network Ports',
    description: 'A quick reference guide for essential TCP/UDP ports and their associated services (e.g., 22, 80, 443).',
    icon: Terminal,
    color: 'text-green-500',
  },
  {
    id: 'attacks',
    title: 'Attack Types',
    description: 'Detailed descriptions of common attack methodologies (e.g., SQL Injection, XSS, DDoS, Phishing).',
    icon: Zap,
    color: 'text-red-500',
  },
  {
    id: 'protocols',
    title: 'Protocols',
    description: 'Understanding key network protocols and their security implications (e.g., DNS, HTTP, SMB, Kerberos).',
    icon: Shield,
    color: 'text-yellow-500',
  },
];

const SocTerms: React.FC = () => {
  const [activeSubCategory, setActiveSubCategory] = useState<TermCategory | null>(null);

  const handleCategoryClick = (category: TermCategory) => {
    setActiveSubCategory(category);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleBack = () => {
    setActiveSubCategory(null);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  if (activeSubCategory) {
    switch (activeSubCategory.id) {
      case 'terms':
        return (
          <TermList 
            title={activeSubCategory.title} 
            data={activeSubCategory.data} 
            onBack={handleBack} 
          />
        );
      case 'ports':
        return (
          <PortList 
            title={activeSubCategory.title} 
            onBack={handleBack} 
          />
        );
      case 'attacks':
        return (
          <AttackList 
            title={activeSubCategory.title} 
            onBack={handleBack} 
          />
        );
      case 'protocols':
        return (
          <div className="p-4 space-y-6">
            <Button variant="ghost" onClick={handleBack} className="p-0 h-auto text-primary hover:text-primary/80">
              <ArrowLeft className="w-4 h-4 mr-2" />
              Back to Categories
            </Button>
            <h2 className="text-3xl font-bold text-foreground flex items-center">
              <activeSubCategory.icon className={cn("w-6 h-6 mr-3", activeSubCategory.color)} />
              {activeSubCategory.title}
            </h2>
            <p className="text-muted-foreground">Content for {activeSubCategory.title} is coming soon!</p>
          </div>
        );
      default:
        return null;
    }
  }

  return (
    <div className="p-4 transition-opacity duration-500">
      <h1 className="text-4xl font-extrabold tracking-tight lg:text-5xl text-foreground mb-6 flex items-center">
        <GraduationCap className="w-8 h-8 mr-3 text-primary" />
        Must-Know SOC Terms
      </h1>
      <p className="text-lg text-muted-foreground mt-2 mb-8">
        Essential knowledge base covering fundamental security concepts, network details, and attack methodologies.
      </p>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6 py-4">
        {termCategories.map((category) => (
          <Card 
            key={category.title} 
            className={cn(
              "group transition-all duration-300 cursor-pointer hover:shadow-primary/50 hover:shadow-lg border-border/50 hover:border-primary/80 hover:scale-[1.02] hover:translate-y-[-2px]",
            )}
            onClick={() => handleCategoryClick(category)}
          >
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-xl font-semibold text-foreground">
                {category.title}
              </CardTitle>
              <category.icon className={cn("h-6 w-6 transition-colors duration-300", category.color, "group-hover:text-primary")} />
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground mb-4">
                {category.description}
              </p>
              <div className="flex justify-end">
                <Button 
                  variant="link" 
                  className="p-0 h-auto text-primary group-hover:translate-x-1 transition-transform duration-200"
                >
                  View Details <ChevronRight className="w-4 h-4 ml-1" />
                </Button>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
};

export default SocTerms;