import React, { useEffect, useState } from 'react';
import './App.css';
import Navbar from './components/Navbar';
import StatsPanel from './components/StatsPanel';
import ThreatFeed from './components/ThreatFeed';
import LogUploader from './components/LogUploader';
import { scanLogs, getThreats, getStats } from './api/client';

function App() {
  const [threats, setThreats] = useState([]);
  const [stats, setStats] = useState({ critical: 0, high: 0, medium: 0, low: 0, total: 0 });
  const [loading, setLoading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [logsText, setLogsText] = useState('');
  const [showScanline, setShowScanline] = useState(true);

  useEffect(() => {
    fetchInitial();
    const t = setTimeout(() => setShowScanline(false), 2400);
    return () => clearTimeout(t);
  }, []);

  async function fetchInitial() {
    setLoading(true);
    try {
      const statsRes = await getStats();
      const threatsRes = await getThreats();
      setStats(statsRes.data || statsRes);
      setThreats(threatsRes.data || threatsRes);
    } catch (err) {
      console.error(err);
    }
    setLoading(false);
  }

  async function handleScan(overrideLogs) {
    setScanning(true);
    try {
      const payload = overrideLogs !== undefined ? overrideLogs : logsText;
      const res = await scanLogs(payload);
      const result = res.data || res;
      setThreats(result.threats || []);
      setStats({
        critical: result.critical || 0,
        high: result.high || 0,
        medium: result.medium || 0,
        low: result.low || 0,
        total: result.threats ? result.threats.length : (result.threats_found || 0)
      });
    } catch (err) {
      console.error(err);
    }
    setScanning(false);
  }

  return (
    <div className="app-root">
      {showScanline && <div className="scanline" />}
      <Navbar />
      <header className="app-header">
        <h1>🛡️ CYBERSENTINEL AI</h1>
        <div className="system-status"><span className="dot green" /> SYSTEM ACTIVE</div>
      </header>

      <main className="main-content">
        <div className="controls-row">
          <StatsPanel critical={stats.critical} high={stats.high} medium={stats.medium} low={stats.low} />
          <div className="actions">
            <button className="scan-button" onClick={() => handleScan()} disabled={scanning}>
              {scanning ? 'SCANNING...' : 'SCAN LOGS'}
            </button>
          </div>
        </div>

        <LogUploader logsText={logsText} setLogsText={setLogsText} onScan={handleScan} />

        <section className="threat-feed-section">
          <ThreatFeed threats={threats} />
        </section>
      </main>

      <footer className="app-footer">
        <div>© CyberSentinel AI</div>
      </footer>
    </div>
  );
}

export default App;
