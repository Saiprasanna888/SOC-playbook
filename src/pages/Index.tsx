import React, { useState } from 'react';
import Layout from "@/components/Layout";
import PlaybookView from "@/components/PlaybookView";
import ToolDictionary from "@/components/ToolDictionary";
import SidebarNavigation from "@/components/SidebarNavigation";
import { cn } from '@/lib/utils';

const Index = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [activeTab, setActiveTab] = useState<'filters' | 'tools'>('filters');

  const renderContent = () => {
    switch (activeTab) {
      case 'filters':
        return (
          <PlaybookView 
            searchTerm={searchTerm} 
            onSearchChange={setSearchTerm} 
          />
        );
      case 'tools':
        return (
          <ToolDictionary />
        );
      default:
        return null;
    }
  };

  return (
    <Layout>
      <div className="flex flex-col lg:flex-row min-h-[80vh]">
        
        {/* Left Sidebar Navigation (Fixed width on desktop) */}
        <div className="w-full lg:w-64 flex-shrink-0 border-b lg:border-r border-border/50">
          <SidebarNavigation 
            activeTab={activeTab} 
            setActiveTab={setActiveTab} 
          />
        </div>

        {/* Main Content Area (Scrollable) */}
        <div className={cn(
          "flex-grow overflow-y-auto transition-opacity duration-500",
          activeTab === 'filters' ? 'lg:px-4' : 'lg:px-8' // Adjust padding based on content type
        )}>
          {renderContent()}
        </div>
      </div>
    </Layout>
  );
};

export default Index;