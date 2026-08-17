import { Bell, Circle } from "lucide-react";

function Header() {
  return (
    <header className="header">
      <div>
        <h2>Security Operations Center</h2>
        <p>Autonomous threat monitoring</p>
      </div>

      <div className="header-right">
        <div className="system-status">
          <Circle size={10} fill="currentColor" />
          System Online
        </div>

        <Bell size={22} />
      </div>
    </header>
  );
}

export default Header;