import React, { useState } from 'react';
import Layout from "@/components/Layout";
import AlertList from "@/components/AlertList";

const Index = () => {
  const [searchTerm, setSearchTerm] = useState('');

  return (
    <Layout searchTerm={searchTerm} onSearchChange={setSearchTerm}>
      <div className="space-y-8">
        <header className="text-center">
          <h1 className="text-4xl font-extrabold tracking-tight lg:text-5xl text-foreground">
            SOC Analyst Alert Dictionary
          </h1>
          <p className="text-lg text-muted-foreground mt-2">
            Quickly find playbooks and response steps for common security alerts.
          </p>
        </header>
        
        <AlertList searchTerm={searchTerm} />
      </div>
    </Layout>
  );
};

export default Index;