import React, { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Separator } from '@/components/ui/separator';
import { Activity, ChevronRight, Zap, Cloud, User, Code, MessageSquare, Mail } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { socScenarios, ScenarioDetail } from '@/data/socScenariosData';
import ScenarioDetailView from './ScenarioDetailView';

const SocScenarios: React.FC = () => {
  const [selectedScenario, setSelectedScenario] = useState<ScenarioDetail | null>(null);

  const handleBack = () => {
    setSelectedScenario(null);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  if (selectedScenario) {
    return <ScenarioDetailView scenario={selectedScenario} onBack={handleBack} />;
  }

  return (
    <div className="p-4 transition-opacity duration-500">
      <h1 className="text-4xl font-extrabold tracking-tight lg:text-5xl text-foreground mb-6 flex items-center">
        <Activity className="w-8 h-8 mr-3 text-primary" />
        MSSP SOC Alert Triage & Escalation Workflow (L1–L2)
      </h1>
      <p className="text-lg text-muted-foreground mt-2 mb-8">
        Practical, real-world incident scenarios to practice triage, investigation, and response workflows.
      </p>

      <Separator className="my-6" />

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 py-4">
        {socScenarios.map((scenario, index) => (
          <Card 
            key={index} 
            className={cn(
              "group transition-all duration-300 cursor-pointer hover:shadow-primary/50 hover:shadow-lg border-border/50 hover:border-primary/80 hover:scale-[1.02] hover:translate-y-[-2px]",
            )}
            onClick={() => setSelectedScenario(scenario)}
          >
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-lg font-semibold text-foreground">
                {scenario.title}
              </CardTitle>
              <scenario.icon className={cn("h-6 w-6 transition-colors duration-300", scenario.color, "group-hover:text-primary")} />
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground mb-4">
                Click to view the full incident timeline, IOCs, and response steps.
              </p>
              <div className="flex justify-end">
                <Button 
                  variant="link" 
                  className="p-0 h-auto text-primary group-hover:translate-x-1 transition-transform duration-200"
                >
                  Start Triage <ChevronRight className="w-4 h-4 ml-1" />
                </Button>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
};

export default SocScenarios;