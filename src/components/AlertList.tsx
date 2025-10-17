import React, { useState, useMemo } from 'react';
import { mockAlerts, categories } from '@/data/mockAlerts';
import { AlertPlaybook, AlertCategory } from '@/types/alert';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Search, Filter, ChevronRight } from 'lucide-react';
import { Link } from 'react-router-dom';
import { cn } from '@/lib/utils';

const AlertList: React.FC = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [activeCategory, setActiveCategory] = useState<AlertCategory | 'All'>('All');

  const filteredAlerts = useMemo(() => {
    let alerts = mockAlerts;

    // 1. Filter by Category
    if (activeCategory !== 'All') {
      alerts = alerts.filter(alert => alert.category === activeCategory);
    }

    // 2. Filter by Search Term
    if (searchTerm.trim()) {
      const lowerCaseSearch = searchTerm.toLowerCase();
      alerts = alerts.filter(alert => 
        alert.name.toLowerCase().includes(lowerCaseSearch) ||
        alert.description.toLowerCase().includes(lowerCaseSearch)
      );
    }

    return alerts;
  }, [searchTerm, activeCategory]);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
      {/* Sidebar for Filters */}
      <div className="lg:col-span-1">
        <Card className="sticky top-20">
          <CardHeader>
            <CardTitle className="text-lg flex items-center">
              <Filter className="w-4 h-4 mr-2" />
              Filter Playbooks
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="relative mb-6">
              <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search alerts..."
                className="pl-9"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
            </div>

            <h4 className="font-semibold mb-2">Categories</h4>
            <div className="space-y-1">
              {['All', ...categories].map((category) => (
                <Button
                  key={category}
                  variant="ghost"
                  className={cn(
                    "w-full justify-start",
                    activeCategory === category && "bg-muted hover:bg-muted dark:bg-gray-800 dark:hover:bg-gray-800"
                  )}
                  onClick={() => setActiveCategory(category as AlertCategory | 'All')}
                >
                  {category}
                </Button>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Alert Results */}
      <div className="lg:col-span-3">
        <h2 className="text-2xl font-bold mb-4">
          {activeCategory === 'All' ? 'All Playbooks' : `${activeCategory} Alerts`} ({filteredAlerts.length})
        </h2>
        
        {filteredAlerts.length === 0 ? (
          <div className="text-center py-12 border border-dashed rounded-lg mt-8">
            <p className="text-muted-foreground">No alerts found matching your criteria.</p>
          </div>
        ) : (
          <div className="space-y-4">
            {filteredAlerts.map((alert) => (
              <Link key={alert.id} to={`/alert/${alert.id}`}>
                <Card className="hover:shadow-md transition-shadow cursor-pointer">
                  <CardHeader>
                    <div className="flex justify-between items-start">
                      <CardTitle className="text-xl">{alert.name}</CardTitle>
                      <ChevronRight className="w-5 h-5 text-muted-foreground" />
                    </div>
                    <Badge variant="outline" className="w-fit mt-1">{alert.category}</Badge>
                  </CardHeader>
                  <CardContent>
                    <CardDescription className="line-clamp-2">
                      {alert.description}
                    </CardDescription>
                  </CardContent>
                </Card>
              </Link>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default AlertList;