import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Separator } from '@/components/ui/separator';
import { ArrowLeft, BookOpen } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { TermDefinition } from '@/data/socTermsData';

interface TermListProps {
  title: string;
  data: TermDefinition[];
  onBack: () => void;
}

const TermList: React.FC<TermListProps> = ({ title, data, onBack }) => {
  return (
    <div className="space-y-6">
      <Button variant="ghost" onClick={onBack} className="p-0 h-auto text-primary hover:text-primary/80">
        <ArrowLeft className="w-4 h-4 mr-2" />
        Back to Categories
      </Button>

      <h2 className="text-3xl font-bold text-foreground flex items-center">
        <BookOpen className="w-6 h-6 mr-3 text-cyan-500" />
        {title}
      </h2>
      <p className="text-muted-foreground">A comprehensive dictionary of essential SOC terminology.</p>
      
      <Separator />

      <div className="space-y-4">
        {data.map((item, index) => (
          <Card key={index} className="transition-all duration-300 hover:shadow-lg hover:border-primary/50">
            <CardHeader className="p-4 border-b border-border/50 bg-muted/20">
              <CardTitle className="text-xl font-semibold text-primary">{item.term}</CardTitle>
            </CardHeader>
            <CardContent className="p-4 text-sm text-foreground/90">
              {item.description}
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
};

export default TermList;