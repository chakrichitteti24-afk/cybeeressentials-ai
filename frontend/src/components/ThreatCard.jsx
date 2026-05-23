import React, { useState } from 'react';
import './ThreatCard.css';
import SeverityBadge from './SeverityBadge';
import { analyzeThreat } from '../api/client';

const ThreatCard = ({ threat }) => {
  const [expanded, setExpanded] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [analysis, setAnalysis] = useState({ ai_explanation: threat.ai_explanation || '', recommended_fix: threat.recommended_fix || '' });

  const handleToggle = async () => {
    if (!expanded && !analysis.ai_explanation) {
      setAnalyzing(true);
      try {
        const res = await analyzeThreat(threat.id || threat);
        setAnalysis({ ai_explanation: res.ai_explanation || res.ai_explanation || 'No explanation', recommended_fix: res.recommended_fix || 'No fix' });
      } catch (err) {
        console.error(err);
      }
      setAnalyzing(false);
    }
    setExpanded(!expanded);
  };

  const borderColor = threat.severity === 'critical' ? '#ff0040' : threat.severity === 'high' ? '#ff8c00' : threat.severity === 'medium' ? '#ffff00' : '#00d4ff';

  return (
    <div className="threat-card" style={{ borderLeft: `6px solid ${borderColor}` }}>
      <div className="threat-row" onClick={handleToggle}>
        <div className="left">
          <SeverityBadge severity={threat.severity} />
          <div className="meta">
            <div className="type">{threat.type}</div>
            <div className="source">{threat.source_ip} • {new Date(threat.timestamp).toLocaleString()}</div>
          </div>
        </div>
        <div className={`expand-arrow ${expanded ? 'open' : ''}`}>{analyzing ? '...' : '▸'}</div>
      </div>

      <div className="description">{threat.description}</div>

      {expanded && (
        <div className="analysis">
          <div className="explain"><strong>AI Explanation:</strong> {analysis.ai_explanation}</div>
          <div className="fix"><strong>Recommended Fix:</strong> {analysis.recommended_fix}</div>
        </div>
      )}
    </div>
  );
};

export default ThreatCard;
