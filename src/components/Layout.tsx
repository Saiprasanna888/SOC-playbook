import React from 'react';
import { Link } from 'react-router-dom';
import { Shield, BookOpen, Search, Github, Linkedin } from 'lucide-react';
import { ThemeToggle } from './ThemeToggle';
import { Input } from './ui/input';
import { MadeWithDyad } from './made-with-dyad';
import { Button } from './ui/button';

interface LayoutProps {
  children: React.ReactNode;
  onSearchChange: (term: string) => void;
  searchTerm: string;
}

const Layout: React.FC<LayoutProps> = ({ children, onSearchChange, searchTerm }) => {
  return (
    <div className="min-h-screen bg-background flex flex-col">
      <header className="sticky top-0 z-40 w-full border-b border-border shadow-lg bg-background/90 backdrop-blur-md transition-all duration-300">
        <div className="container flex h-16 items-center justify-between space-x-4 sm:space-x-0">
          {/* Logo and Title */}
          <Link to="/" className="flex items-center space-x-2 group">
            <Shield className="h-6 w-6 text-primary transition-transform duration-300 group-hover:rotate-6" />
            <span className="font-extrabold text-xl tracking-tight text-foreground hidden sm:inline">
              <span className="text-primary">SOCpedia</span> by Saiprasanna
            </span>
          </Link>

          {/* Search Bar (Centralized - Hidden on mobile) */}
          <div className="flex-1 max-w-lg mx-4 relative hidden md:block">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search alerts, tools, or keywords..."
              className="pl-9 h-9 w-full bg-muted/50 border-border focus-visible:ring-primary transition-all duration-300 hover:bg-muted"
              value={searchTerm}
              onChange={(e) => onSearchChange(e.target.value)}
            />
          </div>
          
          {/* Mobile Search Button (Visible on mobile, uses the main search state) */}
          <div className="md:hidden flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search..."
              className="pl-9 h-9 w-full bg-muted/50 border-border focus-visible:ring-primary"
              value={searchTerm}
              onChange={(e) => onSearchChange(e.target.value)}
            />
          </div>


          {/* Actions */}
          <nav className="flex items-center space-x-1">
            {/* Playbooks Link (Home) */}
            <Link to="/" className="h-8 w-8 flex items-center justify-center rounded-md hover:bg-accent text-muted-foreground hover:text-primary transition-colors" aria-label="Playbooks Home">
                <BookOpen className="h-4 w-4" />
            </Link>
            
            {/* GitHub Link */}
            <a
              href="https://github.com/Saiprasanna888"
              target="_blank"
              rel="noopener noreferrer"
              className="h-8 w-8 flex items-center justify-center rounded-md hover:bg-accent text-muted-foreground hover:text-primary transition-colors"
              aria-label="GitHub Profile"
            >
              <Github className="w-4 h-4" />
            </a>

            {/* LinkedIn Link */}
            <a
              href="https://www.linkedin.com/in/muppallasaiprasanna/"
              target="_blank"
              rel="noopener noreferrer"
              className="h-8 w-8 flex items-center justify-center rounded-md hover:bg-accent text-muted-foreground hover:text-primary transition-colors"
              aria-label="LinkedIn Profile"
            >
              <Linkedin className="w-4 h-4" />
            </a>

            <ThemeToggle />
          </nav>
        </div>
      </header>
      <main className="flex-grow container py-8">
        {children}
      </main>
      <footer className="border-t border-border mt-8">
        <MadeWithDyad />
      </footer>
    </div>
  );
};

export default Layout;