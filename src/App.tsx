import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import Packages from "./pages/Packages";
import NotFound from "./pages/NotFound";
import { useSbomData } from "@/hooks/useSbomData";
import { useOsvScanner } from "@/hooks/useOsvScanner";

const queryClient = new QueryClient();

const App = () => {
  const sbomData = useSbomData();
  const osvScanner = useOsvScanner({
    packages: sbomData.packages,
    setPackages: sbomData.setPackages,
  });

  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <Toaster />
        <Sonner />
        <BrowserRouter>
          <Routes>
            <Route path="/" element={<Dashboard sbomData={sbomData} />} />
            <Route
              path="/packages"
              element={<Packages sbomData={sbomData} osvScanner={osvScanner} />}
            />
            <Route path="*" element={<NotFound />} />
          </Routes>
        </BrowserRouter>
      </TooltipProvider>
    </QueryClientProvider>
  );
};

export default App;
