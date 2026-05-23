import React from 'react';
import './SeverityBadge.css';

const SeverityBadge = ({ severity }) => {
  const mapping = {
    critical: { label: 'CRITICAL', color: '#ff0040', bg: 'rgba(255,0,64,0.07)' },
    high: { label: 'HIGH', color: '#ff8c00', bg: 'rgba(255,140,0,0.06)' },
    medium: { label: 'MEDIUM', color: '#ffff00', bg: 'rgba(255,255,0,0.06)' },
    low: { label: 'LOW', color: '#00d4ff', bg: 'rgba(0,212,255,0.06)' }
  };
  const info = mapping[severity] || mapping.low;
  return <span className="severity-badge" style={{ color: info.color, background: info.bg, border: `1px solid ${info.color}33` }}>{info.label}</span>;
};

export default SeverityBadge;
