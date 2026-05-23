import React, { useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  BarChart3,
  FileText,
  LayoutDashboard,
  Loader2,
  Lock,
  LogOut,
  RefreshCw,
  Shield,
  Siren,
  Upload,
} from 'lucide-react';
import {
  ArcElement,
  BarElement,
  CategoryScale,
  Chart as ChartJS,
  Legend,
  LinearScale,
  Tooltip,
} from 'chart.js';
import { Bar, Doughnut } from 'react-chartjs-2';
import './App.css';
import { analyzeThreat, getMockLogs, getStats, getThreats, login, scanLogs, uploadCsv } from './api/client';

ChartJS.register(ArcElement, BarElement, CategoryScale, LinearScale, Tooltip, Legend);

const navItems = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'feed', label: 'Threat Feed', icon: Siren },
  { id: 'analytics', label: 'Analytics', icon: BarChart3 },
  { id: 'reports', label: 'Reports', icon: FileText },
];

const emptyStats = { total: 0, critical: 0, medium: 0, low: 0, high: 0 };

function normalizeThreat(rawThreat, index = 0) {
  return {
    id: rawThreat.id || rawThreat.alert_id || `threat-${index}`,
    type: rawThreat.type || rawThreat.threat_type || 'Threat alert',
    severity: rawThreat.severity || 'low',
    risk_score: rawThreat.risk_score ?? rawThreat.score ?? 0,
    source_ip: rawThreat.source_ip || rawThreat.ip || 'unknown',
    description: rawThreat.description || rawThreat.message || 'Suspicious activity detected.',
    timestamp: rawThreat.timestamp || rawThreat.created_at || new Date().toISOString(),
    ai_explanation: rawThreat.ai_explanation || rawThreat.explanation || '',
    recommended_fix: rawThreat.recommended_fix || rawThreat.recommended_action || rawThreat.recommendation || '',
  };
}

function normalizeThreats(response) {
  const threatList = Array.isArray(response) ? response : response?.threats;
  if (!Array.isArray(threatList)) return [];
  return threatList.map(normalizeThreat);
}

function normalizeStats(response, fallbackThreats = []) {
  return {
    ...emptyStats,
    critical: response?.critical ?? fallbackThreats.filter((threat) => threat.severity === 'critical').length,
    high: response?.high ?? fallbackThreats.filter((threat) => threat.severity === 'high').length,
    medium: response?.medium ?? fallbackThreats.filter((threat) => threat.severity === 'medium').length,
    low: response?.low ?? fallbackThreats.filter((threat) => threat.severity === 'low').length,
    total: response?.threats_found ?? response?.total ?? fallbackThreats.length,
  };
}

function severityColor(severity) {
  if (severity === 'critical') return 'border-rose-400 bg-rose-500/10 text-rose-200';
  if (severity === 'medium') return 'border-amber-300 bg-amber-400/10 text-amber-100';
  return 'border-sky-300 bg-sky-400/10 text-sky-100';
}

function LoginPage({ onLogin }) {
  const [email, setEmail] = useState('analyst@example.com');
  const [password, setPassword] = useState('strongpassword123');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function handleSubmit(event) {
    event.preventDefault();
    setLoading(true);
    setError('');
    try {
      const result = await login({ email, password });
      localStorage.setItem('cybersentinel_token', result.access_token);
      onLogin();
    } catch (err) {
      setError(err.response?.data?.detail || 'Login failed. Register this user in the API first.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto flex min-h-screen w-full max-w-6xl items-center px-6 py-10">
        <div className="grid w-full gap-8 lg:grid-cols-[1.1fr_0.9fr]">
          <section className="flex flex-col justify-center">
            <div className="mb-8 flex h-14 w-14 items-center justify-center rounded-lg border border-sky-400/40 bg-sky-400/10">
              <Shield className="h-7 w-7 text-sky-300" />
            </div>
            <h1 className="max-w-2xl text-4xl font-semibold tracking-normal text-white md:text-5xl">
              CyberSentinel AI
            </h1>
            <p className="mt-5 max-w-xl text-base leading-7 text-slate-300">
              Prioritize suspicious activity, triage alerts, and review AI-generated explanations from one security operations dashboard.
            </p>
            <div className="mt-8 grid max-w-xl grid-cols-3 gap-3 text-sm text-slate-300">
              <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-4">Log ingestion</div>
              <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-4">Risk scoring</div>
              <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-4">AI analysis</div>
            </div>
          </section>

          <form onSubmit={handleSubmit} className="rounded-lg border border-slate-800 bg-slate-900 p-6 shadow-2xl shadow-black/30">
            <div className="mb-6 flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-slate-800">
                <Lock className="h-5 w-5 text-sky-300" />
              </div>
              <div>
                <h2 className="text-xl font-semibold text-white">Analyst Login</h2>
                <p className="text-sm text-slate-400">Use your FastAPI JWT account</p>
              </div>
            </div>

            <label className="mb-2 block text-sm text-slate-300" htmlFor="email">Email</label>
            <input
              id="email"
              className="mb-4 w-full rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 text-white outline-none focus:border-sky-400"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              type="email"
            />

            <label className="mb-2 block text-sm text-slate-300" htmlFor="password">Password</label>
            <input
              id="password"
              className="mb-5 w-full rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 text-white outline-none focus:border-sky-400"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              type="password"
            />

            {error && <div className="mb-4 rounded-lg border border-rose-400/30 bg-rose-500/10 p-3 text-sm text-rose-100">{error}</div>}

            <button
              className="flex w-full items-center justify-center gap-2 rounded-lg bg-sky-400 px-4 py-3 font-semibold text-slate-950 transition hover:bg-sky-300 disabled:cursor-not-allowed disabled:opacity-70"
              disabled={loading}
            >
              {loading && <Loader2 className="h-4 w-4 animate-spin" />}
              Sign in
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}

function StatCard({ title, value, tone, icon: Icon }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900 p-5">
      <div className="flex items-center justify-between gap-3">
        <span className="text-sm text-slate-400">{title}</span>
        <Icon className={`h-5 w-5 ${tone}`} />
      </div>
      <div className="mt-4 text-3xl font-semibold text-white">{value}</div>
    </div>
  );
}

function ThreatCard({ threat }) {
  const [open, setOpen] = useState(false);
  const [analysis, setAnalysis] = useState({
    ai_explanation: threat.ai_explanation || '',
    recommended_fix: threat.recommended_fix || threat.recommended_action || '',
  });
  const [loading, setLoading] = useState(false);

  async function toggle() {
    const shouldFetch = !open && !analysis.ai_explanation && threat.id;
    setOpen(!open);
    if (!shouldFetch) return;
    setLoading(true);
    try {
      const result = await analyzeThreat(threat.id);
      setAnalysis({
        ai_explanation: result.ai_explanation || '',
        recommended_fix: result.recommended_fix || result.recommended_action || '',
      });
    } finally {
      setLoading(false);
    }
  }

  return (
    <article className={`rounded-lg border p-5 ${severityColor(threat.severity)}`}>
      <button className="flex w-full items-start justify-between gap-4 text-left" onClick={toggle}>
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="rounded border border-current px-2 py-1 text-xs font-semibold uppercase">{threat.severity || 'low'}</span>
            <span className="text-sm text-slate-300">Risk {threat.risk_score ?? 0}</span>
          </div>
          <h3 className="mt-3 text-lg font-semibold text-white">{threat.type || threat.threat_type || 'Threat alert'}</h3>
          <p className="mt-2 text-sm leading-6 text-slate-300">{threat.description}</p>
        </div>
        <span className="shrink-0 text-sm text-slate-400">{open ? 'Hide' : 'Explain'}</span>
      </button>

      <div className="mt-4 flex flex-wrap gap-3 text-xs text-slate-400">
        <span>Source IP: {threat.source_ip || 'unknown'}</span>
        <span>{threat.timestamp ? new Date(threat.timestamp).toLocaleString() : 'No timestamp'}</span>
      </div>

      {open && (
        <div className="mt-5 rounded-lg border border-slate-700 bg-slate-950/60 p-4">
          {loading ? (
            <div className="flex items-center gap-2 text-sm text-slate-300">
              <Loader2 className="h-4 w-4 animate-spin" />
              Loading AI explanation
            </div>
          ) : (
            <div className="space-y-3 text-sm leading-6 text-slate-300">
              <p><span className="font-semibold text-white">AI Explanation:</span> {analysis.ai_explanation || 'No explanation available.'}</p>
              <p><span className="font-semibold text-white">Recommended Fix:</span> {analysis.recommended_fix || 'No recommendation available.'}</p>
            </div>
          )}
        </div>
      )}
    </article>
  );
}

function DashboardPage({
  stats,
  threats,
  loading,
  scanning,
  csvUploading,
  csvUploadMessage,
  selectedCsvFile,
  runScan,
  onCsvFileChange,
  onCsvUpload,
}) {
  const recent = threats.slice(0, 4);
  return (
    <div className="space-y-6">
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <StatCard title="Total Threats" value={stats.total ?? threats.length} tone="text-sky-300" icon={Shield} />
        <StatCard title="Critical Threats" value={stats.critical ?? 0} tone="text-rose-300" icon={AlertTriangle} />
        <StatCard title="Medium Threats" value={stats.medium ?? 0} tone="text-amber-300" icon={Siren} />
        <StatCard title="Low Threats" value={stats.low ?? 0} tone="text-emerald-300" icon={BarChart3} />
      </div>
      <section className="rounded-lg border border-slate-800 bg-slate-900 p-5">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h2 className="text-lg font-semibold text-white">Upload Web Server CSV</h2>
            <p className="text-sm text-slate-400">Headers: IP, Time, URL, Staus</p>
          </div>
          <label className={`flex min-w-0 cursor-pointer items-center gap-2 rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-200 transition hover:bg-slate-800 ${csvUploading ? 'cursor-not-allowed opacity-60' : ''}`}>
            <FileText className="h-4 w-4 shrink-0" />
            <span className="max-w-56 truncate">{selectedCsvFile?.name || 'Choose CSV'}</span>
            <input
              className="sr-only"
              type="file"
              accept=".csv,text/csv"
              disabled={csvUploading}
              onChange={onCsvFileChange}
            />
          </label>
          <button
            className="flex items-center gap-2 rounded-lg bg-sky-400 px-4 py-2 text-sm font-semibold text-slate-950 transition hover:bg-sky-300 disabled:cursor-not-allowed disabled:opacity-60"
            disabled={csvUploading || !selectedCsvFile}
            onClick={onCsvUpload}
          >
            {csvUploading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Upload className="h-4 w-4" />}
            {csvUploading ? 'Uploading' : 'Upload CSV'}
          </button>
        </div>
        {csvUploadMessage && (
          <div className="mt-4 rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-slate-300">
            {csvUploadMessage}
          </div>
        )}
      </section>
      <section className="rounded-lg border border-slate-800 bg-slate-900 p-5">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold text-white">Recent Threats</h2>
            <p className="text-sm text-slate-400">Populated from FastAPI threat and scan responses</p>
          </div>
          <div className="flex items-center gap-3">
            {(loading || scanning) && <Loader2 className="h-5 w-5 animate-spin text-sky-300" />}
            <button
              className="rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-200 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-60"
              onClick={runScan}
              disabled={scanning}
            >
              {scanning ? 'Scanning' : 'Run Sample Scan'}
            </button>
          </div>
        </div>
        <div className="grid gap-4 xl:grid-cols-2">
          {recent.length ? recent.map((threat) => <ThreatCard key={threat.id} threat={threat} />) : <EmptyState />}
        </div>
      </section>
    </div>
  );
}

function ThreatFeedPage({ threats, loading }) {
  return (
    <section className="rounded-lg border border-slate-800 bg-slate-900 p-5">
      <div className="mb-5 flex items-center justify-between">
        <h2 className="text-lg font-semibold text-white">Threat Feed</h2>
        {loading && <Loader2 className="h-5 w-5 animate-spin text-sky-300" />}
      </div>
      <div className="grid gap-4">
        {threats.length ? threats.map((threat) => <ThreatCard key={threat.id} threat={threat} />) : <EmptyState />}
      </div>
    </section>
  );
}

function AnalyticsPage({ stats, threats }) {
  const doughnutData = {
    labels: ['Critical', 'Medium', 'Low'],
    datasets: [
      {
        data: [stats.critical || 0, stats.medium || 0, stats.low || 0],
        backgroundColor: ['#fb7185', '#facc15', '#38bdf8'],
        borderColor: '#0f172a',
      },
    ],
  };
  const typeCounts = threats.reduce((acc, threat) => {
    const key = threat.type || threat.threat_type || 'Unknown';
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});
  const barData = {
    labels: Object.keys(typeCounts).slice(0, 8),
    datasets: [{ label: 'Alerts', data: Object.values(typeCounts).slice(0, 8), backgroundColor: '#38bdf8' }],
  };
  const options = {
    plugins: { legend: { labels: { color: '#cbd5e1' } } },
    scales: {
      x: { ticks: { color: '#94a3b8' }, grid: { color: '#1e293b' } },
      y: { ticks: { color: '#94a3b8' }, grid: { color: '#1e293b' } },
    },
    maintainAspectRatio: false,
  };

  return (
    <div className="grid gap-5 xl:grid-cols-2">
      <section className="rounded-lg border border-slate-800 bg-slate-900 p-5">
        <h2 className="mb-5 text-lg font-semibold text-white">Severity Distribution</h2>
        <div className="h-80"><Doughnut data={doughnutData} options={{ plugins: options.plugins, maintainAspectRatio: false }} /></div>
      </section>
      <section className="rounded-lg border border-slate-800 bg-slate-900 p-5">
        <h2 className="mb-5 text-lg font-semibold text-white">Threat Types</h2>
        <div className="h-80"><Bar data={barData} options={options} /></div>
      </section>
    </div>
  );
}

function ReportsPage({ stats, threats }) {
  const critical = threats.filter((threat) => threat.severity === 'critical');
  return (
    <section className="rounded-lg border border-slate-800 bg-slate-900 p-5">
      <h2 className="text-lg font-semibold text-white">Reports</h2>
      <div className="mt-5 grid gap-4 md:grid-cols-3">
        <ReportBlock label="Open Alerts" value={stats.total ?? threats.length} />
        <ReportBlock label="Critical Items" value={critical.length} />
        <ReportBlock label="AI Explanations" value={threats.filter((t) => t.ai_explanation).length} />
      </div>
      <div className="mt-6 rounded-lg border border-slate-800 bg-slate-950 p-4 text-sm leading-6 text-slate-300">
        Current report summary: {critical.length} critical alerts require immediate analyst review. Medium and low alerts should be prioritized by source IP repetition, account sensitivity, and AI recommendation confidence.
      </div>
    </section>
  );
}

function ReportBlock({ label, value }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950 p-4">
      <div className="text-sm text-slate-400">{label}</div>
      <div className="mt-2 text-2xl font-semibold text-white">{value}</div>
    </div>
  );
}

function EmptyState() {
  return (
    <div className="rounded-lg border border-dashed border-slate-700 bg-slate-950 p-8 text-center text-slate-400">
      No threats returned from the backend.
    </div>
  );
}

function AppShell({
  activePage,
  setActivePage,
  stats,
  threats,
  loading,
  scanning,
  csvUploading,
  csvUploadMessage,
  selectedCsvFile,
  refresh,
  runScan,
  onCsvFileChange,
  onCsvUpload,
  onLogout,
}) {
  const title = navItems.find((item) => item.id === activePage)?.label || 'Dashboard';
  const page = useMemo(() => {
    if (activePage === 'feed') return <ThreatFeedPage threats={threats} loading={loading} />;
    if (activePage === 'analytics') return <AnalyticsPage stats={stats} threats={threats} />;
    if (activePage === 'reports') return <ReportsPage stats={stats} threats={threats} />;
    return (
      <DashboardPage
        stats={stats}
        threats={threats}
        loading={loading}
        scanning={scanning}
        csvUploading={csvUploading}
        csvUploadMessage={csvUploadMessage}
        selectedCsvFile={selectedCsvFile}
        runScan={runScan}
        onCsvFileChange={onCsvFileChange}
        onCsvUpload={onCsvUpload}
      />
    );
  }, [activePage, csvUploadMessage, csvUploading, loading, onCsvFileChange, onCsvUpload, scanning, selectedCsvFile, stats, threats]);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <aside className="fixed inset-y-0 left-0 hidden w-64 border-r border-slate-800 bg-slate-900 lg:block">
        <div className="flex h-16 items-center gap-3 border-b border-slate-800 px-5">
          <Shield className="h-7 w-7 text-sky-300" />
          <span className="font-semibold text-white">CyberSentinel AI</span>
        </div>
        <nav className="space-y-1 p-3">
          {navItems.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              className={`flex w-full items-center gap-3 rounded-lg px-3 py-3 text-left text-sm transition ${activePage === id ? 'bg-sky-400 text-slate-950' : 'text-slate-300 hover:bg-slate-800'}`}
              onClick={() => setActivePage(id)}
            >
              <Icon className="h-5 w-5" />
              {label}
            </button>
          ))}
        </nav>
      </aside>

      <main className="lg:pl-64">
        <header className="sticky top-0 z-10 border-b border-slate-800 bg-slate-950/90 px-5 py-4 backdrop-blur">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h1 className="text-2xl font-semibold text-white">{title}</h1>
              <p className="text-sm text-slate-400">FastAPI-connected threat detection workspace</p>
            </div>
            <div className="flex items-center gap-2">
              <button className="flex items-center gap-2 rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-200 hover:bg-slate-800" onClick={refresh}>
                <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
                Refresh
              </button>
              <button className="flex items-center gap-2 rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-200 hover:bg-slate-800" onClick={onLogout}>
                <LogOut className="h-4 w-4" />
                Logout
              </button>
            </div>
          </div>
          <div className="mt-4 flex gap-2 overflow-x-auto lg:hidden">
            {navItems.map(({ id, label }) => (
              <button key={id} className={`shrink-0 rounded-lg px-3 py-2 text-sm ${activePage === id ? 'bg-sky-400 text-slate-950' : 'bg-slate-900 text-slate-300'}`} onClick={() => setActivePage(id)}>
                {label}
              </button>
            ))}
          </div>
        </header>
        <div className="p-5">{page}</div>
      </main>
    </div>
  );
}

export default function App() {
  const [authenticated, setAuthenticated] = useState(() => Boolean(localStorage.getItem('cybersentinel_token')));
  const [activePage, setActivePage] = useState('dashboard');
  const [threats, setThreats] = useState([]);
  const [stats, setStats] = useState(emptyStats);
  const [loading, setLoading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [csvUploading, setCsvUploading] = useState(false);
  const [csvUploadMessage, setCsvUploadMessage] = useState('');
  const [selectedCsvFile, setSelectedCsvFile] = useState(null);

  async function fetchData() {
    setLoading(true);
    try {
      const [threatData, statData] = await Promise.all([getThreats(), getStats()]);
      const normalizedThreats = normalizeThreats(threatData);
      setThreats(normalizedThreats);
      setStats(normalizeStats(statData, normalizedThreats));
    } finally {
      setLoading(false);
    }
  }

  async function runSampleScan() {
    setScanning(true);
    try {
      const mockLogs = await getMockLogs();
      const scanResult = await scanLogs(mockLogs);
      const normalizedThreats = normalizeThreats(scanResult);
      setThreats(normalizedThreats);
      setStats(normalizeStats(scanResult, normalizedThreats));
    } finally {
      setScanning(false);
    }
  }

  function handleCsvFileChange(event) {
    const file = event.target.files?.[0];
    event.target.value = '';
    setSelectedCsvFile(file || null);
    setCsvUploadMessage(file ? `Selected ${file.name}.` : '');
  }

  async function handleCsvUpload() {
    if (!selectedCsvFile) {
      setCsvUploadMessage('Choose a CSV file first.');
      return;
    }

    setCsvUploading(true);
    setCsvUploadMessage('');
    try {
      const scanResult = await uploadCsv(selectedCsvFile);
      const normalizedThreats = normalizeThreats(scanResult);
      setThreats(normalizedThreats);
      setStats(normalizeStats(scanResult, normalizedThreats));
      setCsvUploadMessage(`Uploaded ${selectedCsvFile.name}. Scanned ${scanResult.total_logs || 0} logs and found ${scanResult.threats_found || 0} threats.`);
      setSelectedCsvFile(null);
      setActivePage('dashboard');
    } catch (err) {
      setCsvUploadMessage(err.response?.data?.detail || 'CSV upload failed. Check the file headers and backend connection.');
    } finally {
      setCsvUploading(false);
    }
  }

  useEffect(() => {
    if (authenticated) fetchData();
  }, [authenticated]);

  if (!authenticated) {
    return <LoginPage onLogin={() => setAuthenticated(true)} />;
  }

  return (
    <AppShell
      activePage={activePage}
      setActivePage={setActivePage}
      stats={stats}
      threats={threats}
      loading={loading}
      scanning={scanning}
      csvUploading={csvUploading}
      csvUploadMessage={csvUploadMessage}
      selectedCsvFile={selectedCsvFile}
      refresh={fetchData}
      runScan={runSampleScan}
      onCsvFileChange={handleCsvFileChange}
      onCsvUpload={handleCsvUpload}
      onLogout={() => {
        localStorage.removeItem('cybersentinel_token');
        setAuthenticated(false);
      }}
    />
  );
}
