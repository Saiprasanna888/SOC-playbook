import React from 'react';
import { Link } from 'react-router-dom';
import { Shield, BookOpen, Search, User, HelpCircle } from 'lucide-react';
import { ThemeToggle } from './ThemeToggle';
import { Input } from './ui/input';
import { MadeWithDyad } from './made-with-dyad';
import { Button } from './ui/button'; // <-- Added import

interface LayoutProps {
  children: React.ReactNode;
  onSearchChange: (term: string) => void;
  searchTerm: string;
}

const Layout: React.FC<LayoutProps> = ({ children, onSearchChange, searchTerm }) => {
  return (
    <div className="min-h-screen bg-background flex flex-col">
      <header className="sticky top-0 z-40 w-full border-b bg-background/90 backdrop-blur-sm border-border shadow-sm">
        <div className="container flex h-16 items-center justify-between space-x-4 sm:space-x-0">
          {/* Logo and Title */}
          <Link to="/" className="flex items-center space-x-2">
            <Shield className="h-6 w-6 text-primary" />
            <span className="font-bold text-xl tracking-tight text-foreground hidden sm:inline">
              SOC Playbook Dictionary
            </span>
          </Link>

          {/* Search Bar (Centralized) */}
          <div className="flex-1 max-w-lg mx-4 relative hidden md:block">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search alerts, tools, or keywords..."
              className="pl-9 h-9 w-full bg-muted/50 border-border focus-visible:ring-primary"
              value={searchTerm}
              onChange={(e) => onSearchChange(e.target.value)}
            />
          </div>

          {/* Actions */}
          <nav className="flex items-center space-x-1">
            <Link to="/" className="text-sm font-medium text-muted-foreground hover:text-primary transition-colors flex items-center space-x-1 p-2 rounded-md hover:bg-accent">
                <BookOpen className="h-4 w-4" />
                <span className="hidden sm:inline">Playbooks</span>
            </Link>
            <Button variant="ghost" size="icon" className="h-8 w-8">
                <HelpCircle className="h-4 w-4" />
            </Button>
            <Button variant="ghost" size="icon" className="h-8 w-8">
                <User className="h-4 w-4" />
            </Button>
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