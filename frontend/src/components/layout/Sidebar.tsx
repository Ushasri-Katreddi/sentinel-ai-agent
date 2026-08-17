import { NavLink } from "react-router-dom";
import {
  LayoutDashboard,
  ShieldAlert,
  BarChart3,
  Activity,
  Settings,
  Shield,
} from "lucide-react";

function Sidebar() {
  return (
    <aside className="sidebar">

      <div className="sidebar-brand">
        <Shield size={32} />
        <span>Sentinel AI</span>
      </div>

      <nav className="sidebar-nav">

        <NavLink to="/" className="nav-item">
          <LayoutDashboard size={20} />
          <span>Dashboard</span>
        </NavLink>

        <NavLink to="/threats" className="nav-item">
          <ShieldAlert size={20} />
          <span>Threats</span>
        </NavLink>

        <NavLink to="/analytics" className="nav-item">
          <BarChart3 size={20} />
          <span>Analytics</span>
        </NavLink>

        <NavLink to="/activity" className="nav-item">
          <Activity size={20} />
          <span>Activity</span>
        </NavLink>

        <NavLink to="/settings" className="nav-item">
          <Settings size={20} />
          <span>Settings</span>
        </NavLink>

      </nav>

    </aside>
  );
}

export default Sidebar;