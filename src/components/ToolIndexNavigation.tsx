import React, { useState, useEffect, useRef } from 'react';
import { cn, slugify } from '@/lib/utils';
import { ToolDetail } from '@/data/socTools';
import { List } from 'lucide-react';

interface ToolIndexNavigationProps {
  tools: ToolDetail[];
}

const ToolIndexNavigation: React.FC<ToolIndexNavigationProps> = ({ tools }) => {
  const [activeId, setActiveId] = useState<string>('');
  const toolIds = tools.map(tool => slugify(tool.name));
  const scrollContainerRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    // Find the scrollable parent (the DialogContent)
    const dialogContent = document.querySelector('.soc-tools-dialog-content');
    scrollContainerRef.current = dialogContent as HTMLElement;

    if (tools.length > 0) {
      setActiveId(toolIds[0]);
    }

    // Use Intersection Observer to track which section is currently visible
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            // Set active ID when an element enters the viewport from the top
            setActiveId(entry.target.id);
          }
        });
      },
      {
        root: scrollContainerRef.current,
        rootMargin: '0px 0px -80% 0px', // Trigger when 20% of the element is visible from the top
        threshold: 0,
      }
    );

    toolIds.forEach(id => {
      const element = document.getElementById(id);
      if (element) {
        observer.observe(element);
      }
    });

    return () => {
      observer.disconnect();
    };
  }, [tools]);

  const scrollToId = (id: string) => {
    const element = document.getElementById(id);
    const container = scrollContainerRef.current;

    if (element && container) {
      // Calculate the position relative to the container's current scroll position
      const targetScrollTop = element.offsetTop - container.offsetTop;
      
      container.scrollTo({
        top: targetScrollTop - 20, // Small offset for padding
        behavior: 'smooth',
      });
      
      setActiveId(id);
    }
  };

  return (
    <div className="sticky top-0 pt-4 pr-4">
      <h3 className="text-sm font-semibold text-muted-foreground mb-3 flex items-center uppercase tracking-wider">
        <List className="w-3 h-3 mr-2" /> Tool Index
      </h3>
      <nav className="space-y-1">
        {tools.map((tool) => {
          const id = slugify(tool.name);
          const isActive = activeId === id;
          return (
            <a
              key={id}
              href={`#${id}`}
              onClick={(e) => {
                e.preventDefault();
                scrollToId(id);
              }}
              className={cn(
                "block text-sm py-1 px-3 rounded-md transition-colors duration-200 truncate",
                "hover:bg-accent hover:text-foreground",
                isActive
                  ? "bg-primary text-primary-foreground font-medium shadow-md"
                  : "text-muted-foreground"
              )}
            >
              {tool.name}
            </a>
          );
        })}
      </nav>
    </div>
  );
};

export default ToolIndexNavigation;