import React from 'react';
import { ArrowLeft, AlertTriangle, Shield, Clock, Terminal, BookOpen, FileText, CheckCircle, Mail } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Separator } from '@/components/ui/separator';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';
import { ScenarioDetail, LogEntry, WorkflowStep } from '@/data/socScenariosData';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';

interface ScenarioDetailViewProps {
  scenario: ScenarioDetail;
  onBack: () => void;
}

const ScenarioDetailView: React.FC<ScenarioDetailViewProps> = ({ scenario, onBack }) => {
  
  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'Critical': return 'bg-red-600 hover:bg-red-700';
      case 'High': return 'bg-orange-500 hover:bg-orange-600';
      case 'Medium': return 'bg-yellow-500 hover:bg-yellow-600';
      default: return 'bg-gray-500 hover:bg-gray-600';
    }
  };

  const renderLogContent = (content: Record<string, string | number | boolean>) => (
    <div className="space-y-1 text-xs font-mono bg-background/50 p-3 rounded-md border border-border/50">
      {Object.entries(content).map(([key, value]) => (
        <div key={key} className="flex">
          <span className="text-muted-foreground w-32 flex-shrink-0">{key}:</span>
          <span className="text-foreground/90 break-all">{String(value)}</span>
        </div>
      ))}
    </div>
  );

  const renderWorkflowTable = (table: { headers: string[]; rows: string[][] }) => (
    <div className="overflow-x-auto mt-4 border rounded-lg">
      <Table>
        <TableHeader>
          <TableRow className="bg-muted/50">
            {table.headers.map((header, i) => (
              <TableHead key={i} className="font-bold text-primary">{header}</TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {table.rows.map((row, rowIndex) => (
            <TableRow key={rowIndex} className="hover:bg-muted/30">
              {row.map((cell, cellIndex) => (
                <TableCell key={cellIndex} className="text-sm text-foreground/90">{cell}</TableCell>
              ))}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );

  return (
    <div className="space-y-8">
      <Button variant="ghost" onClick={onBack} className="p-0 h-auto text-primary hover:text-primary/80">
        <ArrowLeft className="w-4 h-4 mr-2" />
        Back to Scenarios List
      </Button>

      <Card className={cn("shadow-2xl border-l-8 transition-all duration-500", scenario.color.replace('text-', 'border-'))}>
        <CardHeader className="border-b border-border/50 p-6 bg-muted/20">
          <div className="flex justify-between items-start">
            <div>
              <CardTitle className="text-3xl font-extrabold text-foreground flex items-center">
                <scenario.icon className={cn("w-6 h-6 mr-3", scenario.color)} />
                {scenario.title}
              </CardTitle>
              <CardDescription className="mt-2 flex items-center space-x-2">
                <Badge className={cn("text-sm font-medium uppercase", getSeverityColor(scenario.alert.severity))}>
                  Severity: {scenario.alert.severity}
                </Badge>
                <Badge variant="secondary" className="text-xs font-medium">
                  Client: {scenario.alert.client}
                </Badge>
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent className="pt-6 px-6 space-y-8">
          
          {/* Alert Details */}
          <div className="border-l-4 border-primary/50 pl-4">
            <h3 className="text-xl font-bold mb-3 flex items-center text-primary">
              <AlertTriangle className="w-5 h-5 mr-2" /> Alert Details
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
              <p><span className="font-semibold text-muted-foreground">Alert Name:</span> <span className="text-foreground">{scenario.alert.name}</span></p>
              <p><span className="font-semibold text-muted-foreground">Detection Source:</span> <span className="text-foreground">{scenario.alert.source}</span></p>
              <p><span className="font-semibold text-muted-foreground">Endpoint:</span> <span className="text-foreground">{scenario.alert.endpoint}</span></p>
              <p><span className="font-semibold text-muted-foreground">User:</span> <span className="text-foreground">{scenario.alert.user}</span></p>
              <p><span className="font-semibold text-muted-foreground">Trigger Time:</span> <span className="text-foreground">{scenario.alert.triggerTime}</span></p>
            </div>
          </div>

          <Separator />

          {/* Background */}
          <div>
            <h3 className="text-xl font-bold mb-3 flex items-center text-foreground">
              <BookOpen className="w-5 h-5 mr-2 text-primary" /> Background
            </h3>
            <p className="text-sm text-muted-foreground">{scenario.background}</p>
          </div>

          <Separator />

          {/* Correlated Logs */}
          <div>
            <h3 className="text-xl font-bold mb-4 flex items-center text-foreground">
              <Terminal className="w-5 h-5 mr-2 text-primary" /> Correlated Logs
            </h3>
            <div className="space-y-4">
              {scenario.correlatedLogs.map((log, index) => (
                <Card key={index} className="bg-muted/30 border-border/50">
                  <CardHeader className="p-3 border-b border-border/50">
                    <CardTitle className="text-base font-semibold text-foreground">{log.title}</CardTitle>
                  </CardHeader>
                  <CardContent className="p-3">
                    {renderLogContent(log.content)}
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>

          <Separator />

          {/* Workflow */}
          <div>
            <h3 className="text-xl font-bold mb-4 flex items-center text-foreground">
              <CheckCircle className="w-5 h-5 mr-2 text-primary" /> Step-by-Step SOC Workflow
            </h3>
            <div className="space-y-6">
              {scenario.workflow.map((step, index) => (
                <div key={index} className="border-l-4 border-accent/50 pl-4">
                  <h4 className="text-lg font-semibold text-foreground mb-2">Step {index + 1}: {step.title}</h4>
                  <p className="text-sm text-muted-foreground">{step.content}</p>
                  {step.table && renderWorkflowTable(step.table)}
                </div>
              ))}
            </div>
          </div>

          <Separator />

          {/* Escalation */}
          <div className="p-6 border border-primary/50 bg-primary/10 rounded-lg">
            <h3 className="text-xl font-bold mb-3 flex items-center text-primary">
              <Mail className="w-5 h-5 mr-2" /> Client Escalation Notification
            </h3>
            <Card className="bg-background/50 border-dashed border-border/50">
              <CardHeader className="p-3 border-b border-border/50">
                <CardTitle className="text-sm font-semibold text-foreground">Subject: {scenario.escalationSubject}</CardTitle>
              </CardHeader>
              <CardContent className="p-3 whitespace-pre-wrap text-sm text-foreground/90">
                {scenario.escalationBody}
              </CardContent>
            </Card>
          </div>

          <Separator />

          {/* Internal Documentation */}
          <div>
            <h3 className="text-xl font-bold mb-3 flex items-center text-foreground">
              <FileText className="w-5 h-5 mr-2 text-primary" /> Internal MSSP Documentation
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 bg-muted/30 p-4 rounded-lg border border-border/50">
              {Object.entries(scenario.finalDocumentation).map(([key, value]) => (
                <div key={key}>
                  <p className="text-xs font-semibold text-muted-foreground">{key}</p>
                  <p className="text-sm text-foreground">{value}</p>
                </div>
              ))}
            </div>
          </div>

        </CardContent>
      </Card>
    </div>
  );
};

export default ScenarioDetailView;