import React from 'react';
import { useParams, Link } from 'react-router-dom';
import { mockAlerts } from '@/data/mockAlerts';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { ArrowLeft, Zap, Terminal, Wrench, AlertTriangle } from 'lucide-react';
import { Separator } from '@/components/ui/separator';
import { useToast } from '@/components/ui/use-toast';

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

  const handleAISuggestion = () => {
    toast({
      title: "AI Suggestion Requested",
      description: "Dyad AI is generating deeper investigation ideas for this alert...",
      duration: 3000,
    });
  };

  const renderList = (title: string, items: string[], Icon: React.ElementType) => (
    <div className="mb-6">
      <h3 className="text-xl font-semibold mb-3 flex items-center text-primary dark:text-primary-foreground">
        <Icon className="w-5 h-5 mr-2" />
        {title}
      </h3>
      <ul className="space-y-2 list-disc list-inside pl-4 text-gray-700 dark:text-gray-300">
        {items.map((item, index) => (
          <li key={index}>{item}</li>
        ))}
      </ul>
    </div>
  );

  return (
    <div className="max-w-4xl mx-auto">
      <div className="flex justify-between items-center mb-6">
        <Link to="/">
          <Button variant="outline" className="flex items-center">
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back to Dictionary
          </Button>
        </Link>
        <Button onClick={handleAISuggestion} variant="secondary" className="flex items-center">
          <Zap className="w-4 h-4 mr-2" />
          AI Suggestion
        </Button>
      </div>

      <Card className="shadow-lg">
        <CardHeader className="border-b dark:border-gray-800">
          <div className="flex justify-between items-start">
            <div>
              <CardTitle className="text-3xl font-extrabold">{alert.name}</CardTitle>
              <Badge variant="secondary" className="w-fit mt-2 text-sm">{alert.category}</Badge>
            </div>
          </div>
          <p className="text-muted-foreground mt-4 italic">{alert.description}</p>
        </CardHeader>
        <CardContent className="pt-6">
          
          {renderList("Possible Causes", alert.causes, AlertTriangle)}
          <Separator className="my-6" />

          {renderList("Step-by-Step Actions", alert.actions, Zap)}
          <Separator className="my-6" />

          <div className="mb-6">
            <h3 className="text-xl font-semibold mb-3 flex items-center text-primary dark:text-primary-foreground">
              <Terminal className="w-5 h-5 mr-2" />
              Example Queries / Commands
            </h3>
            <div className="space-y-4">
              {alert.queries.map((q, index) => (
                <div key={index} className="bg-gray-100 dark:bg-gray-800 p-4 rounded-lg border dark:border-gray-700">
                  <p className="font-mono text-sm text-gray-800 dark:text-gray-200 break-all">
                    {q.query}
                  </p>
                  <Badge className="mt-2 bg-blue-500 hover:bg-blue-600">{q.tool}</Badge>
                </div>
              ))}
            </div>
          </div>
          <Separator className="my-6" />

          {renderList("Recommended Tools", alert.tools, Wrench)}
          <Separator className="my-6" />

          <div className="mb-6">
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