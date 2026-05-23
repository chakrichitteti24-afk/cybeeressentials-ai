import React from 'react';
import './Navbar.css';

const Navbar = () => {
  return (
    <nav className="cs-navbar">
      <div className="nav-left">
        <span className="shield">🛡️</span>
        <span className="title">CYBERSENTINEL AI</span>
      </div>
      <div className="nav-right">
        <span className="live-dot">● LIVE</span>
      </div>
    </nav>
  );
};

export default Navbar;
