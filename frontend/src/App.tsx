import { BrowserRouter, Routes, Route } from "react-router-dom";

import Analytics from "./pages/Analytics";
import Dashboard from "./pages/Dashboard";
import Threats from "./pages/Threats";
import Activity from "./pages/Activity";
import Settings from "./pages/Settings";

import Layout from "./components/layout/Layout";

function App() {
  return (
    <BrowserRouter>
      <Layout>
        <Routes>

          <Route path="/" element={<Dashboard />} />

          <Route path="/threats" element={<Threats />} />

          <Route path="/analytics" element={<Analytics />} />

          <Route path="/activity" element={<Activity />} />

          <Route path="/settings" element={<Settings />} />

        </Routes>
      </Layout>
    </BrowserRouter>
  );
}

export default App;