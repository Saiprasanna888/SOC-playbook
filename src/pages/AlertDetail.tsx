import React from 'react';
import { useParams, Link } from 'react-router-dom';
import { mockAlerts } from '@/data/mockAlerts';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { ArrowLeft, Zap, Terminal, Wrench, AlertTriangle, Shield, BookOpen } from 'lucide-react';
import { Separator } from '@/components/ui/separator';
import { useToast } from '@/components/ui/use-toast';
import { cn } from '@/lib/utils';

// Helper function to determine severity style (copied from AlertList for consistency)
const getSeverity = (alert: typeof mockAlerts[0]) => {
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

const AlertDetail: React.FC = () => {
  const { alertId } = useParams<{ alertId: string }>();
  const { toast } = useToast();

  const alert = mockAlerts.find(a => a.id === alertId);

  if (!alert) {
    return (
      <div className="text-center py-12">
        <h2 className="text-2xl font-bold">Alert Not Found</h2>
        <p className="text-muted-foreground mt-2">The requested alert playbook does not exist.</p>
        <Link to="/">
          <Button className="mt-4">Go back to Dictionary</Button>
        </Link>
      </div>
    );
  }

  const severity = getSeverity(alert);

  const handleAISuggestion = () => {
    toast({
      title: "AI Suggestion Requested",
      description: "Dyad AI is generating deeper investigation ideas for this alert...",
      duration: 3000,
    });
  };

  const renderList = (title: string, items: string[], Icon: React.ElementType) => (
    <div className="mb-6">
      <h3 className="text-xl font-semibold mb-3 flex items-center text-foreground">
        <Icon className="w-5 h-5 mr-2 text-primary" />
        {title}
      </h3>
      <ul className="space-y-3 list-none pl-0 text-gray-700 dark:text-gray-300">
        {items.map((item, index) => (
          <li key={index} className="flex items-start">
            <span className="text-primary mr-2 font-bold">{index + 1}.</span>
            <span className="flex-1">{item}</span>
          </li>
        ))}
      </ul>
    </div>
  );

  return (
    <div className="max-w-5xl mx-auto">
      <div className="flex justify-between items-center mb-6">
        <Link to="/">
          <Button variant="outline" className="flex items-center">
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back to Dictionary
          </Button>
        </Link>
        <Button onClick={handleAISuggestion} variant="secondary" className="flex items-center bg-primary hover:bg-primary/90 text-primary-foreground">
          <Zap className="w-4 h-4 mr-2" />
          AI Suggestion (Deep Dive)
        </Button>
      </div>

      <Card className="shadow-xl border-l-4" style={{ borderLeftColor: severity.color.split(' ')[0].replace('bg-', '#') }}>
        <CardHeader className="border-b border-border/50 p-6">
          <div className="flex justify-between items-start">
            <div>
              <CardTitle className="text-4xl font-extrabold text-foreground">{alert.name}</CardTitle>
              <div className="flex space-x-2 mt-3">
                <Badge variant="secondary" className="w-fit text-sm font-medium bg-muted text-muted-foreground">
                  <Shield className="w-3 h-3 mr-1" /> {alert.category}
                </Badge>
                <Badge className={cn("text-sm font-medium uppercase", severity.color)}>
                  Severity: {severity.label}
                </Badge>
              </div>
            </div>
          </div>
          <p className="text-muted-foreground mt-4 italic text-lg">{alert.description}</p>
        </CardHeader>
        <CardContent className="pt-8 px-6">
          
          {renderList("Possible Causes (Why did this happen?)", alert.causes, AlertTriangle)}
          <Separator className="my-8" />

          {renderList("Step-by-Step Response Actions", alert.actions, BookOpen)}
          <Separator className="my-8" />

          <div className="mb-6">
            <h3 className="text-xl font-semibold mb-3 flex items-center text-foreground">
              <Terminal className="w-5 h-5 mr-2 text-primary" />
              Example Queries / Commands
            </h3>
            <div className="space-y-4">
              {alert.queries.map((q, index) => (
                <div key={index} className="bg-muted/50 p-4 rounded-lg border border-border/50 shadow-inner">
                  <p className="font-mono text-sm text-foreground break-all whitespace-pre-wrap">
                    {q.query}
                  </p>
                  <Badge className="mt-2 bg-secondary text-secondary-foreground hover:bg-secondary/80 border border-border/50">{q.tool}</Badge>
                </div>
              ))}
            </div>
          </div>
          <Separator className="my-8" />

          {renderList("Recommended Tools for Investigation", alert.tools, Wrench)}
          <Separator className="my-8" />

          <div className="mb-6 p-4 border border-red-500/50 bg-red-500/10 rounded-lg">
            <h3 className="text-xl font-semibold mb-3 flex items-center text-red-600 dark:text-red-400">
              <AlertTriangle className="w-5 h-5 mr-2" />
              Escalation Criteria & Mitigation
            </h3>
            <p className="text-gray-700 dark:text-gray-300">{alert.escalation}</p>
          </div>

        </CardContent>
      </Card>
    </div>
  );
};

export default AlertDetail;