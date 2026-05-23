import React from 'react';
import './LogUploader.css';
import { getMockLogs } from '../api/client';

const LogUploader = ({ logsText, setLogsText, onScan }) => {
  const loadMock = async () => {
    try {
      const data = await getMockLogs();
      if (Array.isArray(data)) {
        const joined = data.map(l => `[${l.timestamp}] ${l.source_ip} ${l.event_type} ${l.message}`).join('\n');
        setLogsText(joined);
      } else if (typeof data === 'string') {
        setLogsText(data);
      } else {
        setLogsText(JSON.stringify(data, null, 2));
      }
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="log-uploader">
      <textarea className="terminal-textarea" value={logsText} onChange={(e) => setLogsText(e.target.value)} placeholder="Paste raw logs here..."></textarea>
      <div className="uploader-actions">
        <button className="btn load" onClick={loadMock}>LOAD MOCK LOGS</button>
        <button className="btn scan" onClick={() => onScan(logsText)}>INITIATE SCAN ▶️</button>
      </div>
    </div>
  );
};

export default LogUploader;
