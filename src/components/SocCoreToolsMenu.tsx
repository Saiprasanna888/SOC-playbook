import React from 'react';
import { TerminalSquare, Zap, Shield, AlertTriangle, Flame, Globe, BookOpen, X, Settings, Brain, ArrowLeft, CheckCircle, Lightbulb, Users, List, ChevronRight, Home } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { cn } from '@/lib/utils';
import { socToolCategories, ToolCategory, ToolDetail } from '@/data/socTools';
import { Separator } from '@/components/ui/separator';
import { Badge } from '@/components/ui/badge';

// --- Sub-Component for Tool Details ---
interface ToolDetailsViewProps {
  category: ToolCategory;
  onBack: () => void;
}

const ToolDetailsView: React.FC<ToolDetailsViewProps> = ({ category, onBack }) => {
  return (
    <div className="space-y-6">
      <Button variant="ghost" onClick={onBack} className="p-0 h-auto text-primary hover:text-primary/80">
        <ArrowLeft className="w-4 h-4 mr-2" />
        Back to Categories
      </Button>
      
      <h2 className="text-3xl font-bold text-foreground flex items-center">
        <category.icon className={cn("w-6 h-6 mr-3", category.color)} />
        {category.title}
      </h2>
      <p className="text-muted-foreground">{category.description}</p>
      
      <Separator />

      <div className="space-y-8">
        {category.details.map((tool, index) => (
          <Card key={index} className="border-l-4 border-primary/50 shadow-lg hover:shadow-xl transition-shadow duration-300">
            <CardHeader className="bg-muted/20 border-b border-border/50 p-4">
              <CardTitle className="text-xl font-bold flex items-center">
                <tool.icon className={cn("w-5 h-5 mr-3", tool.iconColor)} />
                {tool.name}
              </CardTitle>
            </CardHeader>
            <CardContent className="p-6 space-y-6">
              
              {/* Purpose */}
              <div>
                <h4 className="text-sm font-semibold text-muted-foreground mb-1 flex items-center">
                  <List className="w-3 h-3 mr-1" /> Purpose
                </h4>
                <p className="text-sm text-foreground/90">{tool.purpose}</p>
              </div>

              {/* Daily Life Example (NEW SECTION) */}
              <div className="p-4 border border-dashed border-accent rounded-lg bg-background/50">
                <h4 className="text-sm font-semibold text-muted-foreground mb-2 flex items-center text-primary">
                  <Home className="w-3 h-3 mr-1" /> Daily Life Example
                </h4>
                <p className="text-sm text-foreground/90 italic">{tool.dailyLifeExample}</p>
              </div>

              {/* Key Features */}
              <div>
                <h4 className="text-sm font-semibold text-muted-foreground mb-2 flex items-center">
                  <CheckCircle className="w-3 h-3 mr-1" /> Key Features
                </h4>
                <ul className="list-disc list-inside space-y-1 text-sm text-foreground/80 pl-4">
                  {tool.keyFeatures.map((feature, i) => (
                    <li key={i} className="flex items-start before:content-['•'] before:text-primary before:mr-2">
                      {feature}
                    </li>
                  ))}
                </ul>
              </div>
              
              {/* Usage in SOC */}
              <div>
                <h4 className="text-sm font-semibold text-muted-foreground mb-1 flex items-center">
                  <Users className="w-3 h-3 mr-1" /> Usage in SOC
                </h4>
                <p className="text-sm text-foreground/90 italic">{tool.usage}</p>
              </div>

              {/* Architecture */}
              <div>
                <h4 className="text-sm font-semibold text-muted-foreground mb-2 flex items-center">
                  <TerminalSquare className="w-3 h-3 mr-1" /> Architecture
                </h4>
                <ul className="list-none space-y-1 text-sm text-foreground/80 pl-0">
                  {tool.architecture.map((arch, i) => (
                    <li key={i} className="flex items-start border-l-2 border-accent/50 pl-3 transition-all duration-200 hover:bg-background/50 rounded-r-md py-1">
                      <span className="text-primary mr-2 font-extrabold text-xs mt-0.5">•</span>
                      <span className="flex-1">{arch}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Conceptual Workflow */}
              <div>
                <h4 className="text-sm font-semibold text-muted-foreground mb-2 flex items-center">
                  <BookOpen className="w-3 h-3 mr-1" /> Conceptual SOC Workflow
                </h4>
                <ol className="list-none space-y-2 text-sm text-foreground/90 pl-0">
                  {tool.workflow.map((step, i) => (
                    <li key={i} className="flex items-start border-l-2 border-accent/50 pl-3 transition-all duration-200 hover:bg-background/50 rounded-r-md py-1">
                      <span className="text-primary mr-2 font-extrabold text-xs mt-0.5">{i + 1}.</span>
                      <span className="flex-1">{step}</span>
                    </li>
                  ))}
                </ol>
              </div>

              {/* Advantages */}
              <div>
                <h4 className="text-sm font-semibold text-muted-foreground mb-2 flex items-center">
                  <Lightbulb className="w-3 h-3 mr-1" /> Advantages
                </h4>
                <div className="flex flex-wrap gap-2">
                  {tool.advantages.map((advantage, i) => (
                    <Badge key={i} variant="secondary" className="text-xs bg-accent/50 border border-primary/30">
                      {advantage}
                    </Badge>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
};

// --- Main Component ---
const SocCoreToolsMenu: React.FC = () => {
  const [open, setOpen] = React.useState(false);
  const [selectedCategory, setSelectedCategory] = React.useState<ToolCategory | null>(null);

  const handleCategoryClick = (category: ToolCategory) => {
    if (category.details.length > 0) {
      setSelectedCategory(category);
    }
  };

  const handleBack = () => {
    setSelectedCategory(null);
  };

  return (
    <Dialog open={open} onOpenChange={(o) => {
      setOpen(o);
      if (!o) setSelectedCategory(null); // Reset view when closing
    }}>
      <DialogTrigger asChild>
        <Button variant="default" className="w-full lg:w-auto flex items-center justify-center bg-primary hover:bg-primary/90 text-primary-foreground transition-all duration-300 shadow-lg hover:shadow-xl">
          <TerminalSquare className="w-4 h-4 mr-2" />
          SOC Core Security Tools
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-[900px] max-h-[90vh] overflow-y-auto p-6 bg-card border-border/50">
        <DialogHeader className="border-b border-border/50 pb-4">
          <DialogTitle className="text-2xl font-bold flex items-center text-foreground">
            <TerminalSquare className="w-5 h-5 mr-3 text-primary" />
            {selectedCategory ? selectedCategory.title : 'SOC Core Security Tools Dictionary'}
          </DialogTitle>
          <p className="text-muted-foreground text-sm">
            {selectedCategory ? `Detailed overview of ${selectedCategory.title}` : 'Explore key tools, platforms, and frameworks used in modern Security Operations Centers.'}
          </p>
        </DialogHeader>
        
        {selectedCategory ? (
          <ToolDetailsView category={selectedCategory} onBack={handleBack} />
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 py-4">
            {socToolCategories.map((category) => (
              <Card 
                key={category.title} 
                className={cn(
                  "group transition-all duration-300 hover:shadow-primary/50 hover:shadow-lg border-border/50",
                  category.details.length > 0 ? "cursor-pointer hover:border-primary/80" : "opacity-60 cursor-default"
                )}
                onClick={() => handleCategoryClick(category)}
              >
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-lg font-semibold text-foreground">
                    {category.title}
                  </CardTitle>
                  <category.icon className={cn("h-6 w-6 transition-colors duration-300", category.color, "group-hover:text-primary")} />
                </CardHeader>
                <CardContent>
                  <p className="text-sm text-muted-foreground">
                    {category.description}
                  </p>
                  <Button 
                    variant="link" 
                    className={cn("p-0 h-auto mt-2", category.details.length > 0 ? "text-primary" : "text-muted-foreground cursor-default")}
                    disabled={category.details.length === 0}
                  >
                    {category.details.length > 0 ? (
                      <>
                        View {category.details.length} Tools <ChevronRight className="w-4 h-4 ml-1" />
                      </>
                    ) : (
                      'Coming Soon'
                    )}
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
        
        <div className="flex justify-end pt-4">
          <Button variant="outline" onClick={() => setOpen(false)}>
            <X className="w-4 h-4 mr-2" /> Close
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
};

export default SocCoreToolsMenu;