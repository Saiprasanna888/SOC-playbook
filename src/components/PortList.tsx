import React, { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Separator } from '@/components/ui/separator';
import { ArrowLeft, Terminal, Search } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { networkPorts, PortDefinition } from '@/data/socPortsData';
import { Input } from '@/components/ui/input';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { cn } from '@/lib/utils';

interface PortListProps {
  title: string;
  onBack: () => void;
}

const PortList: React.FC<PortListProps> = ({ title, onBack }) => {
  const [searchTerm, setSearchTerm] = useState('');

  const filteredPorts = networkPorts.filter(port => 
    port.port.toLowerCase().includes(searchTerm.toLowerCase()) ||
    port.service.toLowerCase().includes(searchTerm.toLowerCase()) ||
    port.description.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="space-y-6">
      <Button variant="ghost" onClick={onBack} className="p-0 h-auto text-primary hover:text-primary/80">
        <ArrowLeft className="w-4 h-4 mr-2" />
        Back to Categories
      </Button>

      <h2 className="text-3xl font-bold text-foreground flex items-center">
        <Terminal className="w-6 h-6 mr-3 text-green-500" />
        {title}
      </h2>
      <p className="text-muted-foreground">A quick reference guide for essential TCP/UDP ports and their security implications.</p>
      
      <Separator />

      {/* Search Bar */}
      <div className="relative max-w-lg">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input
          placeholder="Search port number, service, or description..."
          className="pl-9 h-10 w-full bg-muted/50 border-border focus-visible:ring-primary transition-all duration-300 hover:bg-muted"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
        />
      </div>

      <Card className="shadow-lg">
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader className="sticky top-0 bg-card/90 backdrop-blur-sm z-10">
                <TableRow>
                  <TableHead className="w-[100px] font-bold text-primary">Port</TableHead>
                  <TableHead className="w-[200px] font-bold text-primary">Service</TableHead>
                  <TableHead className="font-bold text-primary">Security Description</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredPorts.length > 0 ? (
                  filteredPorts.map((item, index) => (
                    <TableRow key={index} className="hover:bg-muted/50 transition-colors">
                      <TableCell className="font-mono text-sm font-semibold text-foreground">{item.port}</TableCell>
                      <TableCell className="font-medium text-foreground">{item.service}</TableCell>
                      <TableCell className="text-sm text-muted-foreground">{item.description}</TableCell>
                    </TableRow>
                  ))
                ) : (
                  <TableRow>
                    <TableCell colSpan={3} className="h-24 text-center text-muted-foreground">
                      No ports found matching "{searchTerm}".
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default PortList;