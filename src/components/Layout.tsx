import React from 'react';
import { Link } from 'react-router-dom';
import { Shield, BookOpen } from 'lucide-react';

interface LayoutProps {
  children: React.ReactNode;
}

const Layout: React.FC<LayoutProps> = ({ children }) => {
  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex flex-col">
      <header className="sticky top-0 z-40 w-full border-b bg-white/90 backdrop-blur-sm dark:bg-gray-950/90 dark:border-gray-800">
        <div className="container flex h-16 items-center space-x-4 sm:justify-between sm:space-x-0">
          <Link to="/" className="flex items-center space-x-2">
            <Shield className="h-6 w-6 text-primary" />
            <span className="font-bold text-xl tracking-tight text-gray-900 dark:text-gray-50">
              SOC Alert Dictionary
            </span>
          </Link>
          <nav className="flex items-center space-x-1">
            <Link to="/" className="text-sm font-medium text-muted-foreground hover:text-primary transition-colors flex items-center space-x-1">
                <BookOpen className="h-4 w-4" />
                <span>Playbooks</span>
            </Link>
          </nav>
        </div>
      </header>
      <main className="flex-grow container py-8">
        {children}
      </main>
      {/* Footer is handled by MadeWithDyad in Index.tsx */}
    </div>
  );
};

export default Layout;