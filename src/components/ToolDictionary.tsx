import React from 'react';
import { TerminalSquare, Zap, Shield, AlertTriangle, Flame, Globe, BookOpen, X, Settings, Brain, ArrowLeft, CheckCircle, Lightbulb, Users, List, ChevronRight, Home } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { cn, slugify } from '@/lib/utils';
import { socToolCategories, ToolCategory, ToolDetail } from '@/data/socTools';
import { Separator } from '@/components/ui/separator';
import { Badge } from '@/components/ui/badge';

// --- Sub-Component for Tool Details ---
interface ToolDetailsViewProps {
  category: ToolCategory;
  onBack: () => void;
}

const ToolDetailsView: React.FC<ToolDetailsViewProps> = ({ category, onBack }) => {
  
  // Helper to map Tailwind color classes to custom glow classes
  const getGlowClass = (colorClass: string) => {
    const color = colorClass.replace('text-', '');
    return `hover:shadow-lg hover:shadow-${color}/50 hover:border-${color}`;
  };

  // Note: We need a way to scroll the main content area, not a dialog.
  // Since this component will be rendered inside the main content, we rely on the browser's scroll.
  const scrollToId = (id: string) => {
    const element = document.getElementById(id) as HTMLElement | null;
    if (element) {
      window.scrollTo({
        top: element.offsetTop - 80, // Offset for fixed header/sticky bar
        behavior: 'smooth',
      });
    }
  };

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

      {/* Horizontal Index Bar (Sticky) */}
      <div className="sticky top-16 z-10 bg-card/90 backdrop-blur-sm border-b border-border/50 py-3 -mx-6 px-6">
        <div className="flex gap-4 overflow-x-auto pb-1 scrollbar-hide">
          {category.details.map((tool) => {
            const id = slugify(tool.name);
            return (
              <a
                key={id}
                href={`#${id}`}
                onClick={(e) => {
                  e.preventDefault();
                  scrollToId(id);
                }}
                className={cn(
                  "flex-shrink-0 text-sm font-medium py-1 px-3 rounded-full transition-colors duration-200",
                  "bg-muted/50 text-muted-foreground hover:bg-primary/10 hover:text-primary"
                )}
              >
                {tool.name}
              </a>
            );
          })}
        </div>
      </div>
      
      {/* Tool Details List */}
      <div className="space-y-8 pt-4">
        {category.details.map((tool, index) => {
          const glowClass = getGlowClass(tool.iconColor);
          return (
            <Card 
              key={index} 
              id={slugify(tool.name)} // Add ID for anchoring
              className={cn(
                "border-l-4 shadow-lg transition-all duration-300 hover:scale-[1.01] hover:border-l-8",
                tool.iconColor.replace('text-', 'border-'), // Base border color
                glowClass // Custom glow effect
              )}
            >
              <CardHeader className="bg-muted/20 border-b border-border/50 p-4">
                <CardTitle className="text-xl font-bold flex items-center">
                  <tool.icon className={cn("w-5 h-5 mr-3", tool.iconColor)} />
                  {tool.name}
                </CardTitle>
              </CardHeader>
              <CardContent className="p-6 space-y-6">
                
                {/* Purpose */}
                <div>
                  <h4 className="text-sm font-bold text-muted-foreground mb-1 flex items-center">
                    <List className="w-3 h-3 mr-1" /> Purpose
                  </h4>
                  <p className="text-sm text-foreground/90">{tool.purpose}</p>
                </div>

                {/* Daily Life Example */}
                <div className="p-4 border border-dashed border-accent rounded-lg bg-background/50">
                  <h4 className="text-sm font-bold text-muted-foreground mb-2 flex items-center text-primary">
                    <Home className="w-3 h-3 mr-1" /> Daily Life Example
                  </h4>
                  <p className="text-sm text-foreground/90 italic">{tool.dailyLifeExample}</p>
                </div>

                {/* Key Features */}
                <div>
                  <h4 className="text-sm font-bold text-muted-foreground mb-2 flex items-center">
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
                  <h4 className="text-sm font-bold text-muted-foreground mb-1 flex items-center">
                    <Users className="w-3 h-3 mr-1" /> Usage in SOC
                  </h4>
                  <p className="text-sm text-foreground/90 italic">{tool.usage}</p>
                </div>

                {/* Architecture */}
                <div>
                  <h4 className="text-sm font-bold text-muted-foreground mb-2 flex items-center">
                    <TerminalSquare className="w-3 h-3 mr-1" /> Architecture
                  </h4>
                  <ul className="list-none space-y-1 text-sm text-foreground/80 pl-0">
                    {tool.architecture.map((arch, i) => {
                      const [title, ...rest] = arch.split(':');
                      return (
                        <li key={i} className="flex items-start border-l-2 border-accent/50 pl-3 transition-all duration-200 hover:bg-background/50 rounded-r-md py-1">
                          <span className="text-primary mr-2 font-extrabold text-xs mt-0.5 font-bold">{i + 1}.</span>
                          <span className="flex-1">
                            <span className="font-bold">{title}:</span>
                            {rest.join(':')}
                          </span>
                        </li>
                      );
                    })}
                  </ul>
                </div>

                {/* Conceptual Workflow */}
                <div>
                  <h4 className="text-sm font-bold text-muted-foreground mb-2 flex items-center">
                    <BookOpen className="w-3 h-3 mr-1" /> Conceptual SOC Workflow
                  </h4>
                  <ol className="list-none space-y-2 text-sm text-foreground/90 pl-0">
                    {tool.workflow.map((step, i) => {
                      // 1. Remove "Step X – " prefix if present
                      const content = step.replace(/^Step \d+ – /, '').trim(); 
                      
                      // 2. Split by the first colon to separate the main step title from details
                      const [stepTitle, ...stepDetails] = content.split(':');

                      return (
                        <li key={i} className="flex items-start border-l-2 border-accent/50 pl-3 transition-all duration-200 hover:bg-background/50 rounded-r-md py-1">
                          <span className="text-primary mr-2 font-extrabold text-xs mt-0.5 font-bold">{i + 1}.</span>
                          <span className="flex-1">
                            <span className="font-bold">{stepTitle}:</span>
                            {stepDetails.join(':')}
                          </span>
                        </li>
                      );
                    })}
                  </ol>
                </div>

                {/* Advantages */}
                <div>
                  <h4 className="text-sm font-bold text-muted-foreground mb-2 flex items-center">
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
          );
        })}
      </div>
    </div>
  );
};

// --- Main Component ---
const ToolDictionary: React.FC = () => {
  const [selectedCategory, setSelectedCategory] = React.useState<ToolCategory | null>(null);

  const handleCategoryClick = (category: ToolCategory) => {
    setSelectedCategory(category);
    // Scroll to top when category changes
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleBack = () => {
    setSelectedCategory(null);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <div className="p-4 transition-opacity duration-500">
      <h1 className="text-4xl font-extrabold tracking-tight lg:text-5xl text-foreground mb-6">
        {selectedCategory ? selectedCategory.title : 'SOC Core Security Tools Dictionary'}
      </h1>
      <p className="text-lg text-muted-foreground mt-2 mb-8">
        {selectedCategory ? selectedCategory.description : 'Explore key tools, platforms, and frameworks used in modern Security Operations Centers.'}
      </p>

      {selectedCategory ? (
        <ToolDetailsView category={selectedCategory} onBack={handleBack} />
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 py-4">
          {socToolCategories.map((category) => (
            <Card 
              key={category.title} 
              className={cn(
                "group transition-all duration-300 hover:shadow-primary/50 hover:shadow-lg border-border/50",
                category.details.length > 0 ? "cursor-pointer hover:border-primary/80 hover:scale-[1.02] hover:translate-y-[-2px]" : "opacity-60 cursor-default"
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
    </div>
  );
};

export default ToolDictionary;