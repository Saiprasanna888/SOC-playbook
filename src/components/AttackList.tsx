import React, { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Separator } from '@/components/ui/separator';
import { ArrowLeft, Zap, Search, Lightbulb } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { TermDefinition } from '@/data/socTermsData';
import { attackTypes } from '@/data/socAttackTypes';
import { Input } from '@/components/ui/input';
import { cn } from '@/lib/utils';

interface AttackListProps {
  title: string;
  onBack: () => void;
}

const AttackList: React.FC<AttackListProps> = ({ title, onBack }) => {
  const [searchTerm, setSearchTerm] = useState('');

  const filteredAttacks = attackTypes.filter(attack => 
    attack.term.toLowerCase().includes(searchTerm.toLowerCase()) ||
    attack.description.toLowerCase().includes(searchTerm.toLowerCase())
  );

  // Helper to split description into main text and example
  const parseDescription = (description: string) => {
    const parts = description.split('**Real-life example:**');
    return {
      main: parts[0].trim(),
      example: parts.length > 1 ? parts[1].trim() : null,
    };
  };

  return (
    <div className="space-y-6">
      <Button variant="ghost" onClick={onBack} className="p-0 h-auto text-primary hover:text-primary/80">
        <ArrowLeft className="w-4 h-4 mr-2" />
        Back to Categories
      </Button>

      <h2 className="text-3xl font-bold text-foreground flex items-center">
        <Zap className="w-6 h-6 mr-3 text-red-500" />
        {title}
      </h2>
      <p className="text-muted-foreground">A dictionary of common cyber attack types, explained with simple language and real-life scenarios.</p>
      
      <Separator />

      {/* Search Bar */}
      <div className="relative max-w-lg">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input
          placeholder="Search attack name or description..."
          className="pl-9 h-10 w-full bg-muted/50 border-border focus-visible:ring-primary transition-all duration-300 hover:bg-muted"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
        />
      </div>

      <div className="space-y-4">
        {filteredAttacks.length > 0 ? (
          filteredAttacks.map((item, index) => {
            const { main, example } = parseDescription(item.description);
            return (
              <Card key={index} className="transition-all duration-300 hover:shadow-lg hover:border-red-500/50 border-l-4 border-red-500/30 hover:border-l-8">
                <CardHeader className="p-4 border-b border-border/50 bg-muted/20">
                  <CardTitle className="text-xl font-semibold text-red-500 dark:text-red-400">{item.term}</CardTitle>
                </CardHeader>
                <CardContent className="p-4 text-sm text-foreground/90 space-y-3">
                  <p>{main}</p>
                  {example && (
                    <div className="p-3 border border-dashed border-accent rounded-lg bg-background/50">
                      <h4 className="text-xs font-bold text-muted-foreground mb-1 flex items-center text-primary">
                        <Lightbulb className="w-3 h-3 mr-1" /> Real-life Example
                      </h4>
                      <p className="text-xs italic text-foreground/80">{example}</p>
                    </div>
                  )}
                </CardContent>
              </Card>
            );
          })
        ) : (
          <div className="text-center py-16 border border-dashed rounded-lg mt-8 bg-muted/20">
            <p className="text-muted-foreground text-lg">
              No attack types found matching "{searchTerm}".
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

export default AttackList;