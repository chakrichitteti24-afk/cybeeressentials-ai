import React from 'react';
import './ThreatFeed.css';
import ThreatCard from './ThreatCard';

const ThreatFeed = ({ threats = [] }) => {
  return (
    <div className="threat-feed">
      <h2>[ THREAT FEED ]</h2>
      {threats.length === 0 ? (
        <div className="empty"><pre>// NO THREATS DETECTED</pre></div>
      ) : (
        <div className="threat-list">
          {threats.map((t) => (
            <ThreatCard key={t.id} threat={t} />
          ))}
        </div>
      )}
    </div>
  );
};

export default ThreatFeed;
