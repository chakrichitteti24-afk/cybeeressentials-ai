import React, { useEffect, useState } from 'react';
import './StatsPanel.css';

const StatCard = ({ label, value, glowClass }) => {
  const [flicker, setFlicker] = useState(false);
  useEffect(() => {
    if (value !== undefined) {
      setFlicker(true);
      const t = setTimeout(() => setFlicker(false), 900);
      return () => clearTimeout(t);
    }
  }, [value]);

  return (
    <div className={`stat-card ${glowClass} ${flicker ? 'flicker' : ''}`}>
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
};

const StatsPanel = ({ critical = 0, high = 0, medium = 0, low = 0 }) => {
  return (
    <div className="stats-panel">
      <StatCard label="CRITICAL" value={critical} glowClass="glow-critical" />
      <StatCard label="HIGH" value={high} glowClass="glow-high" />
      <StatCard label="MEDIUM" value={medium} glowClass="glow-medium" />
      <StatCard label="LOW" value={low} glowClass="glow-low" />
    </div>
  );
};

export default StatsPanel;
