import React, { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Separator } from '@/components/ui/separator';
import { ArrowLeft, Shield, Search, Lightbulb } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { TermDefinition } from '@/data/socTermsData';
import { socProtocols } from '@/data/socProtocolsData';
import { Input } from '@/components/ui/input';
import { cn } from '@/lib/utils';

interface ProtocolListProps {
  title: string;
  onBack: () => void;
}

const ProtocolList: React.FC<ProtocolListProps> = ({ title, onBack }) => {
  const [searchTerm, setSearchTerm] = useState('');

  const filteredProtocols = socProtocols.filter(protocol => 
    protocol.term.toLowerCase().includes(searchTerm.toLowerCase()) ||
    protocol.description.toLowerCase().includes(searchTerm.toLowerCase())
  );

  // Helper to split description into main text and SOC Relevance
  const parseDescription = (description: string) => {
    const parts = description.split('**SOC Relevance:**');
    return {
      main: parts[0].trim(),
      relevance: parts.length > 1 ? parts[1].trim() : null,
    };
  };

  return (
    <div className="space-y-6">
      <Button variant="ghost" onClick={onBack} className="p-0 h-auto text-primary hover:text-primary/80">
        <ArrowLeft className="w-4 h-4 mr-2" />
        Back to Categories
      </Button>

      <h2 className="text-3xl font-bold text-foreground flex items-center">
        <Shield className="w-6 h-6 mr-3 text-yellow-500" />
        {title}
      </h2>
      <p className="text-muted-foreground">Essential network protocols and their critical security implications for the SOC.</p>
      
      <Separator />

      {/* Search Bar */}
      <div className="relative max-w-lg">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input
          placeholder="Search protocol name or description..."
          className="pl-9 h-10 w-full bg-muted/50 border-border focus-visible:ring-primary transition-all duration-300 hover:bg-muted"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
        />
      </div>

      <div className="space-y-4">
        {filteredProtocols.length > 0 ? (
          filteredProtocols.map((item, index) => {
            const { main, relevance } = parseDescription(item.description);
            return (
              <Card key={index} className="transition-all duration-300 hover:shadow-lg hover:border-yellow-500/50 border-l-4 border-yellow-500/30 dark:hover:border-l-8">
                <CardHeader className="p-4 border-b border-border/50 bg-muted/20">
                  <CardTitle className="text-xl font-semibold text-yellow-500 dark:text-yellow-400">{item.term}</CardTitle>
                </CardHeader>
                <CardContent className="p-4 text-sm text-foreground/90 space-y-3">
                  <p className="font-medium">{main}</p>
                  {relevance && (
                    <div className="p-3 border border-dashed border-accent rounded-lg bg-background/50">
                      <h4 className="text-xs font-bold text-muted-foreground mb-1 flex items-center text-primary">
                        <Lightbulb className="w-3 h-3 mr-1" /> SOC Relevance
                      </h4>
                      <p className="text-xs italic text-foreground/80">{relevance}</p>
                    </div>
                  )}
                </CardContent>
              </Card>
            );
          })
        ) : (
          <div className="text-center py-16 border border-dashed rounded-lg mt-8 bg-muted/20">
            <p className="text-muted-foreground text-lg">
              No protocols found matching "{searchTerm}".
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

export default ProtocolList;