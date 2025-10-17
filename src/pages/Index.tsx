import { MadeWithDyad } from "@/components/made-with-dyad";
import Layout from "@/components/Layout";
import AlertList from "@/components/AlertList";

const Index = () => {
  return (
    <Layout>
      <div className="space-y-8">
        <header className="text-center">
          <h1 className="text-4xl font-extrabold tracking-tight lg:text-5xl">
            SOC Analyst Alert Dictionary
          </h1>
          <p className="text-lg text-muted-foreground mt-2">
            Quickly find playbooks and response steps for common security alerts.
          </p>
        </header>
        
        <AlertList />
      </div>
      <MadeWithDyad />
    </Layout>
  );
};

export default Index;