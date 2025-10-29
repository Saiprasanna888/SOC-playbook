import React from 'react';
import { useParams, Link } from 'react-router-dom';
import { mockAlerts } from '@/data/mockAlerts';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { ArrowLeft, Terminal, Wrench, AlertTriangle, Shield, BookOpen, Copy, Check } from 'lucide-react';
import { Separator } from '@/components/ui/separator';
import { useToast } from '@/components/ui/use-toast';
import { cn } from '@/lib/utils';

// Helper function to determine severity style (copied from AlertList for consistency)
const getSeverity = (alert: typeof mockAlerts[0]) => {
  const name = alert.name.toLowerCase();
  const description = alert.description.toLowerCase();

  if (name.includes('critical') || name.includes('ransomware') || name.includes('golden ticket') || description.includes('critical') || description.includes('immediate suspension') || name.includes('zero-day') || name.includes('mbr')) {
    return { label: 'CRITICAL', variant: 'destructive', color: 'border-red-600 bg-red-900/10', badgeColor: 'bg-red-600 hover:bg-red-700' };
  }
  if (name.includes('compromise') || name.includes('lateral movement') || name.includes('web shell') || description.includes('compromise') || description.includes('high priority') || name.includes('dumping') || name.includes('api key exposed')) {
    return { label: 'HIGH', variant: 'default', color: 'border-orange-500 bg-orange-900/10', badgeColor: 'bg-orange-500 hover:bg-orange-600' };
  }
  if (name.includes('unusual') || name.includes('failed') || description.includes('unusual') || description.includes('medium') || name.includes('scan') || name.includes('vpn')) {
    return { label: 'MEDIUM', variant: 'secondary', color: 'border-yellow-500 bg-yellow-900/10', badgeColor: 'bg-yellow-500 hover:bg-yellow-600' };
  }
  return { label: 'LOW', variant: 'outline', color: 'border-green-500 bg-green-900/10', badgeColor: 'bg-green-500 hover:bg-green-600' };
};

const AlertDetail: React.FC = () => {
  const { alertId } = useParams<{ alertId: string }>();
  const { toast } = useToast();
  const [copiedQueryId, setCopiedQueryId] = React.useState<number | null>(null);

  const alert = mockAlerts.find(a => a.id === alertId);

  if (!alert) {
    return (
      <div className="max-w-5xl mx-auto p-4">
        <div className="text-center py-12 bg-card rounded-lg shadow-md">
          <h2 className="text-2xl font-bold">Alert Not Found</h2>
          <p className="text-muted-foreground mt-2">The requested alert playbook does not exist.</p>
          <Link to="/">
            <Button className="mt-4">Go back to Dictionary</Button>
          </Link>
        </div>
      </div>
    );
  }

  const severity = getSeverity(alert);

  const handleCopy = (query: string, index: number) => {
    navigator.clipboard.writeText(query);
    setCopiedQueryId(index);
    toast({
      title: "Copied!",
      description: "Query copied to clipboard.",
      duration: 1500,
    });
    setTimeout(() => setCopiedQueryId(null), 2000);
  };

  const renderList = (title: string, items: string[], Icon: React.ElementType) => (
    <div className="mb-8 p-4 rounded-lg bg-muted/30 border border-border/50 shadow-inner transition-all duration-500 ease-out opacity-100 translate-y-0 hover:shadow-lg">
      <h3 className="text-xl font-bold mb-4 flex items-center text-foreground">
        <Icon className="w-5 h-5 mr-3 text-primary animate-pulse-slow" />
        {title}
      </h3>
      <ol className="space-y-4 list-none pl-0 text-gray-700 dark:text-gray-300">
        {items.map((item, index) => (
          <li 
            key={index} 
            className="flex items-start border-l-2 border-primary/50 pl-4 transition-all duration-200 hover:bg-background/50 rounded-r-md py-1 hover:border-primary/80 hover:scale-[1.005] hover:shadow-sm" // Added hover:shadow-sm
          >
            <span className="text-primary mr-3 font-extrabold text-lg">{index + 1}.</span>
            <span className="flex-1 text-base">{item}</span>
          </li>
        ))}
      </ol>
    </div>
  );

  return (
    <div className="max-w-5xl mx-auto p-4">
      <div className="flex justify-between items-center mb-6">
        <Link to="/">
          <Button variant="outline" className="flex items-center transition-all duration-200 hover:bg-accent">
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back to Dictionary
          </Button>
        </Link>
      </div>

      <Card className={cn("shadow-2xl border-l-8 transition-all duration-500", severity.color)}>
        <CardHeader className="border-b border-border/50 p-6">
          <div className="flex justify-between items-start">
            <div>
              <CardTitle className="text-4xl font-extrabold text-foreground">{alert.name}</CardTitle>
              <div className="flex space-x-2 mt-3">
                <Badge variant="secondary" className="w-fit text-sm font-medium bg-muted text-muted-foreground flex items-center">
                  <Shield className="w-3 h-3 mr-1" /> {alert.category}
                </Badge>
                <Badge className={cn("text-sm font-medium uppercase", severity.badgeColor)}>
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

          <div className="mb-8">
            <h3 className="text-xl font-bold mb-4 flex items-center text-foreground">
              <Terminal className="w-5 h-5 mr-3 text-primary" />
              Example Queries / Commands
            </h3>
            <div className="space-y-4">
              {alert.queries.map((q, index) => (
                <div key={index} className="bg-muted/50 p-4 rounded-lg border border-border/50 shadow-md flex flex-col md:flex-row justify-between items-start md:items-center transition-all duration-300 hover:bg-muted/70 hover:shadow-lg">
                  <div className="flex-1 overflow-x-auto pr-4">
                    <p className="font-mono text-sm text-foreground whitespace-pre-wrap break-all">
                      {q.query}
                    </p>
                    <Badge className="mt-2 bg-secondary text-secondary-foreground hover:bg-secondary/80 border border-border/50">{q.tool}</Badge>
                  </div>
                  <Button 
                    variant="ghost" 
                    size="icon" 
                    className="mt-3 md:mt-0 flex-shrink-0 transition-colors duration-300"
                    onClick={() => handleCopy(q.query, index)}
                  >
                    {copiedQueryId === index ? (
                      <Check className="w-4 h-4 text-green-500 animate-in fade-in" />
                    ) : (
                      <Copy className="w-4 h-4 text-muted-foreground hover:text-primary" />
                    )}
                  </Button>
                </div>
              ))}
            </div>
          </div>
          <Separator className="my-8" />

          {renderList("Recommended Tools for Investigation", alert.tools, Wrench)}
          <Separator className="my-8" />

          <div className="mb-6 p-6 border border-red-500/50 bg-red-500/10 rounded-lg shadow-inner transition-all duration-500 ease-out hover:shadow-lg">
            <h3 className="text-xl font-bold mb-3 flex items-center text-red-600 dark:text-red-400">
              <AlertTriangle className="w-5 h-5 mr-2 animate-ping-slow" />
              When to Escalate
            </h3>
            <p className="text-gray-700 dark:text-gray-300">
              {alert.escalation}
            </p>
          </div>

        </CardContent>
      </Card>
    </div>
  );
};

export default AlertDetail;