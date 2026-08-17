import type { ReactNode } from "react";
import Sidebar from "./Sidebar";
import Header from "./Header";

interface LayoutProps {
  children: ReactNode;
}

function Layout({ children }: LayoutProps) {
  return (
    <div className="app">
      <Sidebar />

      <div className="main">
        <Header />

        <main className="content">
          {children}
        </main>
      </div>
    </div>
  );
}

export default Layout;