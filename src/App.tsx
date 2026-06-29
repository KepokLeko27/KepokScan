import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  Cpu, 
  Globe, 
  Clock, 
  ArrowRight, 
  Copy, 
  Check, 
  Sparkles, 
  RefreshCw, 
  FileCode, 
  Terminal, 
  Info,
  Server,
  Lock,
  ExternalLink,
  Zap,
  FileText,
  Search,
  Settings,
  HelpCircle,
  HardDrive,
  Filter,
  Trash2,
  ChevronRight,
  Eye,
  Download
} from 'lucide-react';
import { SecurityReport, HeaderAnalysis, ExposureItem } from './types';

const PRESETS = [
  'https://github.com',
  'https://google.com',
  'https://wikipedia.org',
  'https://news.ycombinator.com'
];

export default function App() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<SecurityReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  
  // Enterprise Navigation & Layout states
  const [activeView, setActiveView] = useState<'dashboard' | 'headers' | 'exposures' | 'ai' | 'raw' | 'json' | 'settings'>('dashboard');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedHeaderKey, setSelectedHeaderKey] = useState<string | null>('strict-transport-security');
  
  // Clipboard states
  const [copiedHeader, setCopiedHeader] = useState<string | null>(null);
  const [copiedJson, setCopiedJson] = useState(false);
  const [copiedCode, setCopiedCode] = useState<string | null>(null);
  
  // AI Audit States
  const [aiAuditText, setAiAuditText] = useState<string>('');
  const [loadingAiAudit, setLoadingAiAudit] = useState(false);

  // PDF Generator States
  const [downloadingPdf, setDownloadingPdf] = useState(false);

  // Persistent History
  const [historyList, setHistoryList] = useState<string[]>(() => {
    const saved = localStorage.getItem('kepokscan_scan_history');
    return saved ? JSON.parse(saved) : PRESETS;
  });
  const [historyCleared, setHistoryCleared] = useState(false);
  const [hasGemini, setHasGemini] = useState<boolean>(true);

  // Engine Settings
  const [scannerTimeout, setScannerTimeout] = useState<number>(2500);
  const [customUserAgent, setCustomUserAgent] = useState<string>('KepokScan-Auditor/1.4');
  const [benchmarkProfile, setBenchmarkProfile] = useState<'owasp' | 'dod' | 'cis'>('owasp');

  // Load an initial benchmark scan of GitHub on startup and fetch system config
  useEffect(() => {
    handleScan('https://github.com');
    
    // Fetch server configuration
    fetch('/api/config')
      .then(res => res.json())
      .then(data => {
        if (data && typeof data.hasGemini === 'boolean') {
          setHasGemini(data.hasGemini);
        }
      })
      .catch(err => {
        console.error('Failed to load server config:', err);
      });
  }, []);

  const handleScan = async (targetUrl: string) => {
    const trimmed = targetUrl.trim();
    if (!trimmed) return;

    setLoading(true);
    setError(null);
    setAiAuditText(''); // Clear old AI audit
    setUrl(trimmed);

    try {
      const response = await fetch('/scan/headers', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: trimmed }),
      });

      const data = await response.json();

      if (!response.ok || data.error) {
        throw new Error(data.error || 'Failed to complete vulnerability scan.');
      }

      setReport(data);

      // Add to local scan history list
      setHistoryList(prev => {
        const filtered = prev.filter(u => u.toLowerCase() !== trimmed.toLowerCase());
        const updated = [trimmed, ...filtered].slice(0, 12);
        localStorage.setItem('kepokscan_scan_history', JSON.stringify(updated));
        return updated;
      });

      // Default the selected header inspector key to the first key in the headers list
      const firstHeaderKey = Object.keys(data.headers)[0];
      if (firstHeaderKey) {
        setSelectedHeaderKey(firstHeaderKey);
      }
    } catch (err: any) {
      console.error(err);
      setError(err.message || 'The scanner encountered an unexpected transport error.');
    } finally {
      setLoading(false);
    }
  };

  const handleAiAudit = async () => {
    if (!report) return;

    setLoadingAiAudit(true);
    setAiAuditText('');
    
    try {
      const response = await fetch('/api/ai-audit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ report }),
      });

      const data = await response.json();
      if (!response.ok || data.error) {
        throw new Error(data.error || 'Failed to generate AI Audit.');
      }

      setAiAuditText(data.text);
    } catch (err: any) {
      console.error(err);
      setAiAuditText(`### Error Generating Audit\n\n${err.message || 'Failed to contact Gemini API. Please make sure your API key is correctly configured.'}`);
    } finally {
      setLoadingAiAudit(false);
    }
  };

  const handleDownloadPdf = async () => {
    if (!report) return;
    setDownloadingPdf(true);
    setError(null);

    try {
      const response = await fetch('/api/download-pdf', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ report, aiAuditText }),
      });

      if (!response.ok) {
        const errData = await response.json();
        throw new Error(errData.error || 'Failed to generate PDF report.');
      }

      const blob = await response.blob();
      const blobUrl = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = blobUrl;
      link.download = `kepokscan-security-report-${new URL(report.url).hostname}.pdf`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(blobUrl);
    } catch (err: any) {
      console.error(err);
      setError(`PDF Export Failed: ${err.message || 'Internal reporting service error.'}`);
    } finally {
      setDownloadingPdf(false);
    }
  };

  const copyToClipboard = (text: string, id: string, type: 'header' | 'json' | 'code' = 'header') => {
    navigator.clipboard.writeText(text);
    if (type === 'json') {
      setCopiedJson(true);
      setTimeout(() => setCopiedJson(false), 2000);
    } else if (type === 'code') {
      setCopiedCode(id);
      setTimeout(() => setCopiedCode(null), 2000);
    } else {
      setCopiedHeader(id);
      setTimeout(() => setCopiedHeader(null), 2000);
    }
  };

  const clearHistory = () => {
    localStorage.removeItem('kepokscan_scan_history');
    setHistoryList(PRESETS);
    setHistoryCleared(true);
    setTimeout(() => setHistoryCleared(false), 3000);
  };

  // Convert score into high-density terminal ASCII bar
  const renderAsciiBar = (score: number) => {
    const totalBlocks = 15;
    const filled = Math.round((score / 100) * totalBlocks);
    const empty = totalBlocks - filled;
    return '█'.repeat(filled) + '░'.repeat(empty);
  };

  // Get semantic colors for SOC tables
  const getSeverityBadge = (status: HeaderAnalysis['status']) => {
    switch (status) {
      case 'danger':
        return (
          <span className="px-2 py-0.5 text-[11px] font-mono font-bold bg-red-950/40 text-red-500 border border-red-900/60 rounded">
            CRITICAL
          </span>
        );
      case 'warning':
        return (
          <span className="px-2 py-0.5 text-[11px] font-mono font-bold bg-yellow-950/40 text-yellow-500 border border-yellow-900/50 rounded">
            WARNING
          </span>
        );
      case 'secure':
      case 'info':
        return (
          <span className="px-2 py-0.5 text-[11px] font-mono font-bold bg-emerald-950/40 text-emerald-500 border border-emerald-900/50 rounded">
            PASSED
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 text-[11px] font-mono font-bold bg-zinc-800 text-zinc-400 border border-zinc-700 rounded">
            INFO
          </span>
        );
    }
  };

  // Extract Cookies from raw headers for tabular audit
  const getCookiesFromHeaders = () => {
    if (!report) return [];
    const cookieHeaders = Object.entries(report.rawHeaders).filter(([key]) => 
      key.toLowerCase() === 'set-cookie'
    );
    if (cookieHeaders.length === 0) return [];

    return cookieHeaders.map(([_, val], index) => {
      const parts = (val as string).split(';').map(p => p.trim());
      const nameValue = parts[0] || '';
      const name = nameValue.split('=')[0] || `cookie_idx_${index}`;
      const isSecure = parts.some(p => p.toLowerCase() === 'secure');
      const isHttpOnly = parts.some(p => p.toLowerCase() === 'httponly');
      const sameSitePart = parts.find(p => p.toLowerCase().startsWith('samesite='));
      const sameSite = sameSitePart ? sameSitePart.split('=')[1] : 'Not Set';

      return {
        name,
        isSecure,
        isHttpOnly,
        sameSite,
        raw: val as string
      };
    });
  };

  // Filter headers list based on search bar
  const getFilteredHeaders = (): [string, HeaderAnalysis][] => {
    if (!report) return [];
    return (Object.entries(report.headers) as [string, HeaderAnalysis][]).filter(([key, h]) => {
      const q = searchQuery.toLowerCase();
      return key.toLowerCase().includes(q) || h.name.toLowerCase().includes(q) || h.description.toLowerCase().includes(q);
    });
  };

  // Retrieve code deployment snippet for the selected header
  const getDeploymentSnippet = (headerKey: string, value: string | null) => {
    const val = value || 'example-policy-directive-value';
    return {
      nginx: `add_header ${headerKey === 'strict-transport-security' ? 'Strict-Transport-Security' : headerKey} "${val}" always;`,
      apache: `Header always set ${headerKey === 'strict-transport-security' ? 'Strict-Transport-Security' : headerKey} "${val}"`,
      express: `app.use((req, res, next) => {\n  res.setHeader('${headerKey}', '${val}');\n  next();\n});`
    };
  };

  const detectedCookies = getCookiesFromHeaders();
  const filteredHeaders = getFilteredHeaders();

  // Selected Header object in inspector panel
  const selectedHeader: HeaderAnalysis | undefined = report?.headers[selectedHeaderKey as keyof typeof report.headers];

  return (
    <div className="min-h-screen bg-[#121212] text-[#e0e0e0] flex flex-col font-sans antialiased selection:bg-blue-600/30 selection:text-white">
      
      {/* 1. TOP NAVIGATION PANEL */}
      <nav className="h-12 bg-[#1a1a1a] border-b border-zinc-800 px-4 flex items-center justify-between shrink-0 select-none">
        
        {/* Left Brand Block */}
        <div className="flex items-baseline gap-2">
          <span className="font-mono text-sm font-bold tracking-wider text-white">KEPOKSCAN</span>
          <span className="text-[11px] font-mono text-zinc-500 uppercase tracking-widest border-l border-zinc-800 pl-2">
            Web Security Assessment Toolkit
          </span>
        </div>

        {/* Global Filter & Status Controls */}
        <div className="flex items-center gap-4">
          
          {/* Quick Case-Insensitive Filtering */}
          {report && (
            <div className="relative hidden md:block">
              <span className="absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-500">
                <Search className="w-3.5 h-3.5" />
              </span>
              <input
                type="text"
                placeholder="Filter findings matrix..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-60 bg-[#141414] border border-zinc-800 text-xs rounded px-2.5 py-1 pl-8 outline-none focus:border-blue-600 text-zinc-300 font-mono"
              />
              {searchQuery && (
                <button 
                  onClick={() => setSearchQuery('')}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-[10px] text-zinc-500 hover:text-white"
                >
                  ✕
                </button>
              )}
            </div>
          )}

          {/* Engine Status Indicators */}
          <div className="flex items-center gap-3 text-xs font-mono text-zinc-500">
            <span className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
              <span className="text-zinc-400">SOC_NODE: ONLINE</span>
            </span>
            <span className="hidden lg:inline border-l border-zinc-800 h-3 pl-3">
              LICENSE: ACTIVE
            </span>
          </div>

        </div>

      </nav>

      {/* 2. MAIN SPLIT LAYOUT */}
      <div className="flex flex-1 overflow-hidden">
        
        {/* LEFT SIDEBAR PANEL */}
        <aside className="w-52 bg-[#161616] border-r border-zinc-800 p-2 flex flex-col justify-between shrink-0 select-none">
          
          <div className="flex flex-col gap-1">
            <span className="text-[10px] font-mono font-bold text-zinc-500 px-2.5 py-1 tracking-widest uppercase block">
              VULNERABILITY SCOPES
            </span>

            <button
              onClick={() => { setActiveView('dashboard'); }}
              className={`w-full flex items-center justify-between px-2.5 py-1.5 rounded text-xs font-mono transition cursor-pointer ${
                activeView === 'dashboard' 
                  ? 'bg-blue-600/10 text-blue-400 border border-blue-600/30 font-bold' 
                  : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/30 border border-transparent'
              }`}
            >
              <div className="flex items-center gap-2">
                <Globe className="w-3.5 h-3.5" />
                <span>01. Dashboard</span>
              </div>
            </button>

            <button
              onClick={() => { setActiveView('headers'); }}
              className={`w-full flex items-center justify-between px-2.5 py-1.5 rounded text-xs font-mono transition cursor-pointer ${
                activeView === 'headers' 
                  ? 'bg-blue-600/10 text-blue-400 border border-blue-600/30 font-bold' 
                  : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/30 border border-transparent'
              }`}
            >
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-3.5 h-3.5" />
                <span>02. Header Matrix</span>
              </div>
              {report && (
                <span className="text-[9px] bg-zinc-800 text-zinc-300 font-bold px-1 rounded border border-zinc-700">
                  {Object.keys(report.headers).length}
                </span>
              )}
            </button>

            <button
              onClick={() => { setActiveView('exposures'); }}
              className={`w-full flex items-center justify-between px-2.5 py-1.5 rounded text-xs font-mono transition cursor-pointer ${
                activeView === 'exposures' 
                  ? 'bg-blue-600/10 text-blue-400 border border-blue-600/30 font-bold' 
                  : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/30 border border-transparent'
              }`}
            >
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-3.5 h-3.5" />
                <span>03. Exposures</span>
              </div>
              {report?.exposures && (
                <span className={`text-[9px] font-bold px-1 rounded border ${
                  report.exposures.some(e => e.status === 'danger')
                    ? 'bg-red-950 text-red-400 border-red-900/60'
                    : 'bg-zinc-800 text-zinc-300 border-zinc-700'
                }`}>
                  {report.exposures.length}
                </span>
              )}
            </button>

            <button
              onClick={() => { setActiveView('ai'); if(!aiAuditText && hasGemini) handleAiAudit(); }}
              className={`w-full flex items-center justify-between px-2.5 py-1.5 rounded text-xs font-mono transition cursor-pointer ${
                activeView === 'ai' 
                  ? 'bg-blue-600/10 text-blue-400 border border-blue-600/30 font-bold' 
                  : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/30 border border-transparent'
              }`}
            >
              <div className="flex items-center gap-2">
                <Sparkles className="w-3.5 h-3.5 text-yellow-500/90" />
                <span>04. AI Security Audit</span>
              </div>
              {!hasGemini && (
                <span className="text-[9px] text-zinc-500 font-mono border border-zinc-800 px-1 rounded uppercase bg-zinc-950">
                  Optional
                </span>
              )}
            </button>

            <button
              onClick={() => { setActiveView('raw'); }}
              className={`w-full flex items-center justify-between px-2.5 py-1.5 rounded text-xs font-mono transition cursor-pointer ${
                activeView === 'raw' 
                  ? 'bg-blue-600/10 text-blue-400 border border-blue-600/30 font-bold' 
                  : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/30 border border-transparent'
              }`}
            >
              <div className="flex items-center gap-2">
                <Terminal className="w-3.5 h-3.5" />
                <span>05. Raw Headers</span>
              </div>
            </button>

            <button
              onClick={() => { setActiveView('json'); }}
              className={`w-full flex items-center justify-between px-2.5 py-1.5 rounded text-xs font-mono transition cursor-pointer ${
                activeView === 'json' 
                  ? 'bg-blue-600/10 text-blue-400 border border-blue-600/30 font-bold' 
                  : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/30 border border-transparent'
              }`}
            >
              <div className="flex items-center gap-2">
                <FileCode className="w-3.5 h-3.5" />
                <span>06. API Output JSON</span>
              </div>
            </button>

            <span className="text-[10px] font-mono font-bold text-zinc-500 px-2.5 py-1 tracking-widest uppercase block mt-4">
              CONFIGURATION
            </span>

            <button
              onClick={() => { setActiveView('settings'); }}
              className={`w-full flex items-center gap-2 px-2.5 py-1.5 rounded text-xs font-mono transition cursor-pointer ${
                activeView === 'settings' 
                  ? 'bg-blue-600/10 text-blue-400 border border-blue-600/30 font-bold' 
                  : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/30 border border-transparent'
              }`}
            >
              <Settings className="w-3.5 h-3.5" />
              <span>Scanner Settings</span>
            </button>
          </div>

          {/* Sidebar Footer System Block */}
          <div className="bg-[#121212] border border-zinc-800 rounded p-2 flex flex-col gap-1 text-[10px] font-mono text-zinc-500">
            <span className="text-zinc-400 font-bold uppercase border-b border-zinc-800 pb-1 mb-1">AUDITOR_STATUS</span>
            <div className="flex justify-between">
              <span>MEMCACHE:</span>
              <span className="text-zinc-300">ENGAGED</span>
            </div>
            <div className="flex justify-between">
              <span>BENCHMARK:</span>
              <span className="text-blue-500 uppercase">{benchmarkProfile}</span>
            </div>
            <div className="flex justify-between">
              <span>REPORT_SYS:</span>
              <span className="text-emerald-500">READY</span>
            </div>
          </div>

        </aside>

        {/* MAIN DISPLAY WORKSPACE */}
        <main className="flex-1 bg-[#121212] overflow-y-auto p-4 flex flex-col gap-4">

          {/* QUICK TARGET CONTROLLER (Always accessible at top of content pane) */}
          <section className="bg-[#1a1a1a] border border-zinc-800 rounded p-4 flex flex-col gap-3">
            <div className="flex items-center justify-between border-b border-zinc-800/50 pb-2">
              <div className="flex items-center gap-2">
                <Globe className="w-4 h-4 text-blue-500" />
                <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-white">
                  Target Audit Controller
                </h2>
              </div>
              <span className="text-[10px] font-mono text-zinc-500">
                Supports IPv4, standard hostname endpoints and SSL queries
              </span>
            </div>

            <form 
              onSubmit={(e) => { e.preventDefault(); handleScan(url); }}
              className="flex gap-2"
            >
              <div className="flex-1 relative">
                <input
                  id="target-url-input"
                  aria-label="Target URL to inspect"
                  type="text"
                  placeholder="Enter target URL (e.g. github.com, https://google.com)"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  disabled={loading}
                  className="w-full bg-[#121212] border border-zinc-800 text-xs font-mono rounded px-3 py-2 outline-none focus:border-blue-600 text-white placeholder-zinc-600"
                />
                {loading && (
                  <div className="absolute right-3 top-1/2 -translate-y-1/2">
                    <RefreshCw className="w-3.5 h-3.5 text-zinc-400 animate-spin" />
                  </div>
                )}
              </div>
              <button
                type="submit"
                disabled={loading || !url.trim()}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-zinc-800 disabled:text-zinc-600 text-white text-xs font-mono rounded font-semibold transition flex items-center gap-1.5 cursor-pointer"
              >
                <span>{loading ? 'RUNNING_COMPLIANCE_SCAN...' : 'EXECUTE_AUDIT'}</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </form>

            {/* Quick History / Presets Row */}
            <div className="flex flex-wrap items-center gap-1.5 text-[11px] font-mono text-zinc-500">
              <span className="text-zinc-400 uppercase font-bold tracking-wider mr-1">QUICK_PRESETS:</span>
              {historyList.map((histUrl) => (
                <button
                  key={histUrl}
                  onClick={() => handleScan(histUrl)}
                  disabled={loading}
                  className="px-2 py-0.5 bg-[#121212] hover:bg-zinc-800 border border-zinc-800 text-zinc-400 hover:text-white transition rounded text-[11px] cursor-pointer"
                >
                  {histUrl.replace('https://', '').replace('http://', '')}
                </button>
              ))}
              {historyList.length > PRESETS.length && (
                <button 
                  onClick={clearHistory}
                  title="Reset Presets"
                  className="ml-auto text-zinc-600 hover:text-red-500 transition cursor-pointer"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </section>

          {/* ERROR STATUS BOUNDARY */}
          {error && (
            <div className="bg-red-950/20 border border-red-900/50 text-red-400 p-3.5 rounded text-xs font-mono flex gap-2.5 items-start">
              <ShieldAlert className="w-4 h-4 text-red-500 shrink-0 mt-0.5" />
              <div className="flex-1">
                <span className="font-bold text-red-300">Scanner Engine Error Code: SC_TRANS_FAULT</span>
                <p className="mt-1 text-zinc-400 leading-relaxed">{error}</p>
              </div>
            </div>
          )}

          {/* CORE REPORT WORKSPACE */}
          {!report ? (
            /* Blank/Pending screen */
            <div className="flex-1 bg-[#1a1a1a] border border-zinc-800 rounded p-12 flex flex-col items-center justify-center text-center gap-3">
              <Cpu className="w-8 h-8 text-zinc-600 animate-pulse" />
              <span className="text-sm font-mono font-bold text-white uppercase tracking-wider">KepokScan Engine Idle</span>
              <p className="text-xs text-zinc-500 max-w-sm font-mono leading-relaxed">
                Provide a live URL or click a preset above to load audited response headers, security cookies, technology footprints, and compliance logs.
              </p>
            </div>
          ) : (
            /* Active Scanner Report View */
            <div className="flex flex-col gap-4 animate-fade-in">
              
              {/* VIEW 1: UNIFIED COMPREHENSIVE DASHBOARD */}
              {activeView === 'dashboard' && (
                <div className="flex flex-col gap-4">
                  
                  {/* METRIC OVERVIEW BAR (Replaces circular scores with flat horizontal progress bar & letter grade) */}
                  <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
                    
                    {/* Horizontal score display card */}
                    <div className="lg:col-span-6 bg-[#1a1a1a] border border-zinc-800 rounded p-4 flex flex-col justify-between gap-4">
                      
                      <div className="flex items-center justify-between border-b border-zinc-800/60 pb-2">
                        <span className="text-xs font-mono font-bold uppercase text-white tracking-wider">Security Benchmark Rating</span>
                        <span className="text-[10px] font-mono text-zinc-500">Benchmark Profile: {benchmarkProfile.toUpperCase()}</span>
                      </div>

                      <div className="flex items-center justify-between gap-4">
                        <div className="flex flex-col gap-1">
                          <span className="text-[11px] font-mono text-zinc-500 uppercase tracking-wider">Security Score</span>
                          <span className="text-2xl font-mono font-bold text-white">
                            {report.score} / 100
                          </span>
                        </div>
                        <div className="flex flex-col items-end gap-1">
                          <span className="text-[11px] font-mono text-zinc-500 uppercase tracking-wider">Compliance Status</span>
                          <span className={`text-xl font-mono font-bold tracking-tight ${
                            report.grade.startsWith('A') || report.grade.startsWith('B') ? 'text-emerald-500' : 'text-red-500'
                          }`}>
                            GRADE {report.grade}
                          </span>
                        </div>
                      </div>

                      {/* Horizontal progress bar */}
                      <div className="flex flex-col gap-1.5 font-mono">
                        <div className="flex justify-between text-[10px] text-zinc-500">
                          <span>0% [MIN_DEFENSE]</span>
                          <span>100% [OPTIMAL]</span>
                        </div>
                        <div className="h-6 bg-[#121212] border border-zinc-800 rounded overflow-hidden flex items-center px-2">
                          <span className="text-xs font-mono text-blue-500 tracking-tight select-none">
                            {renderAsciiBar(report.score)}
                          </span>
                          <div className="ml-auto text-xs text-zinc-400 font-bold">
                            {report.score}%
                          </div>
                        </div>
                      </div>

                      {/* Grid metrics breakdown */}
                      <div className="grid grid-cols-4 gap-2 bg-[#121212] border border-zinc-800 rounded p-2 text-center font-mono">
                        <div>
                          <div className="text-[10px] text-zinc-500 uppercase">Passed</div>
                          <div className="text-xs font-bold text-emerald-500 mt-0.5">{report.summary.secure}</div>
                        </div>
                        <div>
                          <div className="text-[10px] text-zinc-500 uppercase">Warning</div>
                          <div className="text-xs font-bold text-yellow-500 mt-0.5">{report.summary.warning}</div>
                        </div>
                        <div>
                          <div className="text-[10px] text-zinc-500 uppercase">Critical</div>
                          <div className="text-xs font-bold text-red-500 mt-0.5">{report.summary.danger}</div>
                        </div>
                        <div>
                          <div className="text-[10px] text-zinc-500 uppercase">Info</div>
                          <div className="text-xs font-bold text-blue-400 mt-0.5">{report.summary.info}</div>
                        </div>
                      </div>

                    </div>

                    {/* Target Information Card */}
                    <div className="lg:col-span-6 bg-[#1a1a1a] border border-zinc-800 rounded p-4 flex flex-col justify-between gap-3">
                      
                      <div className="flex items-center justify-between border-b border-zinc-800/60 pb-2">
                        <span className="text-xs font-mono font-bold uppercase text-white tracking-wider">Host Reconnaissance Info</span>
                        
                        <div className="flex items-center gap-2">
                          <button
                            onClick={handleDownloadPdf}
                            disabled={downloadingPdf}
                            className="text-[10px] font-mono bg-blue-600 hover:bg-blue-500 disabled:bg-zinc-800 text-white px-2 py-0.5 rounded transition flex items-center gap-1.5 cursor-pointer"
                          >
                            {downloadingPdf ? (
                              <RefreshCw className="w-3 h-3 animate-spin" />
                            ) : (
                              <Download className="w-3 h-3" />
                            )}
                            <span>{downloadingPdf ? 'EXPORTING_PDF...' : 'GENERATE_PDF_REPORT'}</span>
                          </button>
                        </div>
                      </div>

                      <div className="grid grid-cols-2 gap-3 text-xs font-mono">
                        <div className="bg-[#121212] p-2 border border-zinc-800 rounded">
                          <div className="text-[10px] text-zinc-500">TARGET_HOSTNAME</div>
                          <div className="font-bold text-zinc-200 truncate mt-0.5">{new URL(report.url).hostname}</div>
                        </div>
                        <div className="bg-[#121212] p-2 border border-zinc-800 rounded">
                          <div className="text-[10px] text-zinc-500">RESOLVED_IP</div>
                          <div className="font-bold text-zinc-200 mt-0.5">{report.serverInfo.ipAddress || 'Not resolved'}</div>
                        </div>
                        <div className="bg-[#121212] p-2 border border-zinc-800 rounded">
                          <div className="text-[10px] text-zinc-500">SERVER_BANNER</div>
                          <div className="font-bold text-zinc-200 truncate mt-0.5">{report.serverInfo.server || 'None Disclosed'}</div>
                        </div>
                        <div className="bg-[#121212] p-2 border border-zinc-800 rounded">
                          <div className="text-[10px] text-zinc-500">POWERED_BY_FRAMEWORK</div>
                          <div className="font-bold text-zinc-200 truncate mt-0.5">{report.serverInfo.poweredBy || 'None Disclosed'}</div>
                        </div>
                      </div>

                      <div className="flex items-center justify-between text-[11px] font-mono text-zinc-500 border-t border-zinc-800/60 pt-2">
                        <span className="flex items-center gap-1">
                          <Clock className="w-3 h-3" />
                          <span>UTC Scan: {report.scannedAt.replace('T', ' ').split('.')[0]}</span>
                        </span>
                        <span className="text-zinc-400">
                          HTTP Response Code: <b className="text-blue-500">{report.statusCode}</b>
                        </span>
                      </div>

                    </div>

                  </div>

                  {/* MASTER COMPLIANCE FINDINGS COMPACT TABLE */}
                  <div className="bg-[#1a1a1a] border border-zinc-800 rounded p-4 flex flex-col gap-3">
                    <div className="flex items-center justify-between border-b border-zinc-800/60 pb-2">
                      <div className="flex items-center gap-1.5">
                        <Filter className="w-4 h-4 text-zinc-400" />
                        <span className="text-xs font-mono font-bold uppercase text-white tracking-wider">
                          HTTP Security Header Compliance Matrix
                        </span>
                      </div>
                      <span className="text-[10px] font-mono text-zinc-500">
                        Click on any row to load standard remediation rules & configurations
                      </span>
                    </div>

                    <div className="overflow-x-auto">
                      <table className="w-full text-left border-collapse text-xs font-mono">
                        <thead>
                          <tr className="bg-[#121212] border-b border-zinc-800 text-zinc-400 font-bold">
                            <th className="py-2 px-3 w-32 border-r border-zinc-800">SEVERITY</th>
                            <th className="py-2 px-3 w-48 border-r border-zinc-800">FINDING / HEADER</th>
                            <th className="py-2 px-3 border-r border-zinc-800">SECURITY RISK / ASSESSMENT</th>
                            <th className="py-2 px-3 w-64">REMEDIATION ADVICE</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-zinc-800/60">
                          {(Object.entries(report.headers) as [string, HeaderAnalysis][]).map(([key, h]) => {
                            const isSelected = selectedHeaderKey === key;
                            return (
                              <tr 
                                key={key}
                                onClick={() => { setSelectedHeaderKey(key); setActiveView('headers'); }}
                                className={`hover:bg-zinc-800/45 transition cursor-pointer ${
                                  isSelected ? 'bg-blue-600/5 border-l-2 border-l-blue-600' : ''
                                }`}
                              >
                                <td className="py-2.5 px-3 border-r border-zinc-800">
                                  {getSeverityBadge(h.status)}
                                </td>
                                <td className="py-2.5 px-3 border-r border-zinc-800 font-bold text-zinc-100">
                                  <div className="flex flex-col">
                                    <span>{h.name}</span>
                                    <span className="text-[10px] text-zinc-500 lowercase font-normal">{key}</span>
                                  </div>
                                </td>
                                <td className="py-2.5 px-3 border-r border-zinc-800 text-zinc-300 leading-relaxed">
                                  {h.description}
                                </td>
                                <td className="py-2.5 px-3 text-zinc-400 truncate max-w-xs" title={h.recommendation}>
                                  {h.recommendation}
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  </div>

                  {/* MIDDLE SECTION: COOKIES AND TECHNOLOGIES */}
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                    
                    {/* Cookies Audit Panel */}
                    <div className="bg-[#1a1a1a] border border-zinc-800 rounded p-4 flex flex-col gap-3">
                      <div className="flex items-center justify-between border-b border-zinc-800/60 pb-2">
                        <span className="text-xs font-mono font-bold uppercase text-white tracking-wider">
                          Cookies Configuration Audit
                        </span>
                        <span className="text-[10px] font-mono text-zinc-500">
                          Total Cookies Discovered: {detectedCookies.length}
                        </span>
                      </div>

                      {detectedCookies.length === 0 ? (
                        <div className="py-8 text-center text-zinc-500 text-xs font-mono">
                          <Lock className="w-5 h-5 mx-auto text-emerald-500/70 mb-2" />
                          <span>No response cookies were established by this remote target.</span>
                        </div>
                      ) : (
                        <div className="overflow-x-auto">
                          <table className="w-full text-left text-xs font-mono">
                            <thead>
                              <tr className="bg-[#121212] text-zinc-400 font-bold border-b border-zinc-800">
                                <th className="py-1.5 px-2">COOKIE NAME</th>
                                <th className="py-1.5 px-2 text-center">HTTPONLY</th>
                                <th className="py-1.5 px-2 text-center">SECURE</th>
                                <th className="py-1.5 px-2 text-center">SAMESITE</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-zinc-800/65">
                              {detectedCookies.map((cookie, index) => (
                                <tr key={index} className="hover:bg-[#121212]/50">
                                  <td className="py-2 px-2 text-zinc-200 font-bold truncate max-w-[150px]">{cookie.name}</td>
                                  <td className="py-2 px-2 text-center">
                                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                                      cookie.isHttpOnly ? 'bg-emerald-950/40 text-emerald-500 border border-emerald-900/40' : 'bg-red-950/40 text-red-500 border border-red-900/40'
                                    }`}>
                                      {cookie.isHttpOnly ? 'TRUE' : 'FALSE (RISK)'}
                                    </span>
                                  </td>
                                  <td className="py-2 px-2 text-center">
                                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                                      cookie.isSecure ? 'bg-emerald-950/40 text-emerald-500 border border-emerald-900/40' : 'bg-red-950/40 text-red-500 border border-red-900/40'
                                    }`}>
                                      {cookie.isSecure ? 'TRUE' : 'FALSE (RISK)'}
                                    </span>
                                  </td>
                                  <td className="py-2 px-2 text-center text-zinc-300">
                                    {cookie.sameSite}
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      )}
                    </div>

                    {/* Technologies Footprint Table */}
                    <div className="bg-[#1a1a1a] border border-zinc-800 rounded p-4 flex flex-col gap-3">
                      <div className="flex items-center justify-between border-b border-zinc-800/60 pb-2">
                        <span className="text-xs font-mono font-bold uppercase text-white tracking-wider">
                          Server Technology Disclosure
                        </span>
                        <span className="text-[10px] font-mono text-zinc-500">
                          Identified via Server Headers
                        </span>
                      </div>

                      <div className="overflow-x-auto">
                        <table className="w-full text-left text-xs font-mono">
                          <thead>
                            <tr className="bg-[#121212] text-zinc-400 font-bold border-b border-zinc-800">
                              <th className="py-1.5 px-2">COMPONENT</th>
                              <th className="py-1.5 px-2">DISCOVERED VALUE</th>
                              <th className="py-1.5 px-2">EXPOSURE RATING</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-zinc-800/65">
                            <tr className="hover:bg-[#121212]/50">
                              <td className="py-2 px-2 text-zinc-400">Server Software</td>
                              <td className="py-2 px-2 text-zinc-200 font-bold truncate max-w-[160px]">
                                {report.serverInfo.server || 'None Advertised'}
                              </td>
                              <td className="py-2 px-2">
                                <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                                  report.serverInfo.server ? 'bg-yellow-950/40 text-yellow-500 border border-yellow-900/40' : 'bg-emerald-950/40 text-emerald-500 border border-emerald-900/40'
                                }`}>
                                  {report.serverInfo.server ? 'INFO DISCLOSURE' : 'SECURE'}
                                </span>
                              </td>
                            </tr>
                            <tr className="hover:bg-[#121212]/50">
                              <td className="py-2 px-2 text-zinc-400">X-Powered-By Banner</td>
                              <td className="py-2 px-2 text-zinc-200 font-bold truncate max-w-[160px]">
                                {report.serverInfo.poweredBy || 'None Disclosed'}
                              </td>
                              <td className="py-2 px-2">
                                <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                                  report.serverInfo.poweredBy ? 'bg-red-950/40 text-red-500 border border-red-900/40' : 'bg-emerald-950/40 text-emerald-500 border border-emerald-900/40'
                                }`}>
                                  {report.serverInfo.poweredBy ? 'VULNERABLE' : 'SECURE'}
                                </span>
                              </td>
                            </tr>
                            <tr className="hover:bg-[#121212]/50">
                              <td className="py-2 px-2 text-zinc-400">SSL/TLS Redirection</td>
                              <td className="py-2 px-2 text-zinc-200 font-bold truncate max-w-[160px]">
                                {report.url.startsWith('https://') ? 'HTTPS Enforced' : 'HTTP Plaintext'}
                              </td>
                              <td className="py-2 px-2">
                                <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                                  report.url.startsWith('https://') ? 'bg-emerald-950/40 text-emerald-500 border border-emerald-900/40' : 'bg-red-950/40 text-red-500 border border-red-900/40'
                                }`}>
                                  {report.url.startsWith('https://') ? 'SECURE' : 'HIGH RISK'}
                                </span>
                              </td>
                            </tr>
                          </tbody>
                        </table>
                      </div>
                    </div>

                  </div>

                  {/* SUMMARY RECOMMENDATIONS LIST */}
                  <div className="bg-[#1a1a1a] border border-zinc-800 rounded p-4 flex flex-col gap-3">
                    <div className="flex items-center justify-between border-b border-zinc-800/60 pb-2">
                      <span className="text-xs font-mono font-bold uppercase text-white tracking-wider">
                        Actionable Hardening Guidelines
                      </span>
                      <span className="text-[10px] font-mono text-zinc-500">
                        Top 3 high-impact recommendations to improve rating
                      </span>
                    </div>

                    <div className="flex flex-col gap-2 font-mono text-xs">
                      {(Object.entries(report.headers) as [string, HeaderAnalysis][])
                        .filter(([_, h]) => h.status === 'danger')
                        .slice(0, 3)
                        .map(([key, h], index) => (
                          <div 
                            key={key}
                            onClick={() => { setSelectedHeaderKey(key); setActiveView('headers'); }}
                            className="bg-[#121212] border border-zinc-800 hover:border-blue-600 transition p-3 rounded flex items-start gap-3 cursor-pointer"
                          >
                            <span className="w-5 h-5 bg-red-950/60 border border-red-900 text-red-400 flex items-center justify-center rounded text-xs font-bold shrink-0">
                              {index + 1}
                            </span>
                            <div className="flex-1">
                              <span className="font-bold text-white block">Remediate missing {h.name}</span>
                              <p className="text-zinc-400 mt-1 leading-relaxed text-[11px]">{h.recommendation}</p>
                            </div>
                            <ChevronRight className="w-4 h-4 text-zinc-600 self-center" />
                          </div>
                        ))}
                      
                      {(Object.entries(report.headers) as [string, HeaderAnalysis][]).filter(([_, h]) => h.status === 'danger').length === 0 && (
                        <div className="bg-[#121212] border border-zinc-800 p-4 rounded text-center text-zinc-500">
                          <ShieldCheck className="w-5 h-5 mx-auto text-emerald-500 mb-1" />
                          <span>All critical headers exist! No urgent recommendations found.</span>
                        </div>
                      )}
                    </div>
                  </div>

                </div>
              )}

              {/* VIEW 2: SECURITY HEADERS (MASTER-DETAIL INSPECTOR) */}
              {activeView === 'headers' && (
                <div className="grid grid-cols-1 xl:grid-cols-12 gap-4">
                  
                  {/* Left Column: Headers Compliance Table */}
                  <div className="xl:col-span-7 bg-[#1a1a1a] border border-zinc-800 rounded p-4 flex flex-col gap-3">
                    
                    <div className="flex items-center justify-between border-b border-zinc-800 pb-2">
                      <div className="flex items-center gap-1.5">
                        <Filter className="w-4 h-4 text-zinc-400" />
                        <span className="text-xs font-mono font-bold uppercase text-white tracking-wider">
                          Compliance Matrix Selection
                        </span>
                      </div>
                      <span className="text-[10px] font-mono text-zinc-500">
                        Select a header to inspect
                      </span>
                    </div>

                    <div className="overflow-x-auto">
                      <table className="w-full text-left text-xs font-mono">
                        <thead>
                          <tr className="bg-[#121212] text-zinc-400 font-bold border-b border-zinc-800">
                            <th className="py-2 px-2">SEVERITY</th>
                            <th className="py-2 px-2">HEADER KEY</th>
                            <th className="py-2 px-2">RATING</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-zinc-800/60">
                          {filteredHeaders.map(([key, h]) => (
                            <tr
                              key={key}
                              onClick={() => setSelectedHeaderKey(key)}
                              className={`hover:bg-zinc-800/40 transition cursor-pointer ${
                                selectedHeaderKey === key ? 'bg-blue-600/10 font-bold' : ''
                              }`}
                            >
                              <td className="py-2 px-2">
                                {getSeverityBadge(h.status)}
                              </td>
                              <td className="py-2 px-2 text-zinc-200">
                                <div className="flex flex-col">
                                  <span>{h.name}</span>
                                  <span className="text-[10px] text-zinc-500 font-normal lowercase">{key}</span>
                                </div>
                              </td>
                              <td className="py-2 px-2 text-zinc-400">
                                {h.rating}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>

                  </div>

                  {/* Right Column: Detailed Vulnerability Detail Inspector */}
                  <div className="xl:col-span-5 bg-[#1a1a1a] border border-zinc-800 rounded p-4 flex flex-col gap-4">
                    
                    <div className="border-b border-zinc-800 pb-2 flex items-center justify-between">
                      <span className="text-xs font-mono font-bold uppercase text-white tracking-wider">
                        Vulnerability & Mitigation Inspector
                      </span>
                      <span className="text-[10px] font-mono text-zinc-500">
                        Rule ID: {selectedHeaderKey}
                      </span>
                    </div>

                    {selectedHeader ? (
                      <div className="flex flex-col gap-4 font-mono text-xs">
                        
                        {/* Header metadata summary */}
                        <div className="bg-[#121212] border border-zinc-800 p-3 rounded">
                          <span className="text-[10px] text-zinc-500 uppercase block font-bold">Rule Name</span>
                          <span className="text-sm font-bold text-white block mt-0.5">{selectedHeader.name}</span>
                          
                          <div className="flex items-center justify-between mt-2 pt-2 border-t border-zinc-800/50">
                            <span className="text-[10px] text-zinc-500 uppercase">Assessment Status:</span>
                            {getSeverityBadge(selectedHeader.status)}
                          </div>
                        </div>

                        {/* Current Value disclosure */}
                        <div className="flex flex-col gap-1.5">
                          <span className="text-[10px] text-zinc-500 uppercase font-bold">Audited Header Value:</span>
                          {selectedHeader.present && selectedHeader.value ? (
                            <div className="relative">
                              <pre className="p-2.5 bg-[#121212] border border-zinc-800 text-[11px] text-blue-400 rounded break-all whitespace-pre-wrap select-text pr-10">
                                {selectedHeader.value}
                              </pre>
                              <button
                                onClick={() => copyToClipboard(selectedHeader.value || '', selectedHeaderKey || '', 'header')}
                                className="absolute right-2 top-2 p-1 bg-zinc-800 hover:bg-zinc-700 text-zinc-400 hover:text-white transition rounded"
                                title="Copy Value"
                              >
                                {copiedHeader === selectedHeaderKey ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
                              </button>
                            </div>
                          ) : (
                            <div className="bg-red-950/20 border border-red-900/30 text-red-400/90 p-2.5 rounded text-[11px]">
                              ⚠️ MISSING: This security header is completely absent from the target's response. This leaves the server in a non-compliant state.
                            </div>
                          )}
                        </div>

                        {/* Functional Risk Description */}
                        <div className="flex flex-col gap-1">
                          <span className="text-[10px] text-zinc-500 uppercase font-bold">Threat & Risk Summary:</span>
                          <p className="bg-[#121212] border border-zinc-800 p-2.5 text-zinc-300 leading-relaxed text-[11px]">
                            {selectedHeader.description}
                          </p>
                        </div>

                        {/* Remediation deployment recipes */}
                        <div className="flex flex-col gap-2">
                          <span className="text-[10px] text-zinc-500 uppercase font-bold">rem_recipe (deployment rules):</span>
                          <p className="text-[11px] text-zinc-400 italic mb-1">
                            {selectedHeader.recommendation}
                          </p>

                          {/* Remediation code block */}
                          <div className="flex flex-col gap-2 border border-zinc-800 rounded bg-[#121212] overflow-hidden">
                            <div className="bg-[#161616] px-3 py-1.5 border-b border-zinc-800 flex items-center justify-between text-[10px]">
                              <span className="text-zinc-500 font-bold uppercase">Deployment Instructions</span>
                              <span className="text-zinc-600">CONF_RULES</span>
                            </div>
                            
                            <div className="p-2 flex flex-col gap-3">
                              {/* Nginx recipe */}
                              <div className="flex flex-col gap-1">
                                <div className="flex justify-between text-[10px] text-zinc-500 font-mono">
                                  <span>NGINX (Server Block):</span>
                                  <button 
                                    onClick={() => copyToClipboard(getDeploymentSnippet(selectedHeaderKey || '', selectedHeader.value).nginx, 'nginx', 'code')}
                                    className="hover:text-white transition"
                                  >
                                    {copiedCode === 'nginx' ? 'Copied!' : 'Copy'}
                                  </button>
                                </div>
                                <pre className="p-1.5 bg-[#161616] text-[10px] font-mono text-zinc-300 rounded overflow-x-auto whitespace-nowrap">
                                  {getDeploymentSnippet(selectedHeaderKey || '', selectedHeader.value).nginx}
                                </pre>
                              </div>

                              {/* Express recipe */}
                              <div className="flex flex-col gap-1">
                                <div className="flex justify-between text-[10px] text-zinc-500 font-mono">
                                  <span>EXPRESS (Middleware):</span>
                                  <button 
                                    onClick={() => copyToClipboard(getDeploymentSnippet(selectedHeaderKey || '', selectedHeader.value).express, 'express', 'code')}
                                    className="hover:text-white transition"
                                  >
                                    {copiedCode === 'express' ? 'Copied!' : 'Copy'}
                                  </button>
                                </div>
                                <pre className="p-1.5 bg-[#161616] text-[10px] font-mono text-zinc-300 rounded overflow-x-auto whitespace-pre">
                                  {getDeploymentSnippet(selectedHeaderKey || '', selectedHeader.value).express}
                                </pre>
                              </div>

                            </div>
                          </div>

                        </div>

                      </div>
                    ) : (
                      <div className="text-zinc-500 text-xs font-mono py-12 text-center">
                        Select a header on the left matrix to load security guidelines.
                      </div>
                    )}

                  </div>

                </div>
              )}

              {/* VIEW 3: EXPOSURES & CRAWLERS */}
              {activeView === 'exposures' && (
                <div className="bg-[#1a1a1a] border border-zinc-800 rounded p-4 flex flex-col gap-4 animate-fade-in">
                  
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-zinc-800 pb-3">
                    <div>
                      <h3 className="text-xs font-mono font-bold uppercase text-white flex items-center gap-1.5">
                        <ShieldAlert className="w-4 h-4 text-red-500 animate-pulse" />
                        Discovered Configuration Exposures & Crawlers Scan
                      </h3>
                      <p className="text-[11px] text-zinc-500 mt-0.5 font-mono">
                        Verification of public indices, source directories, robotic filters, and administrative endpoints.
                      </p>
                    </div>
                  </div>

                  {!report.exposures || report.exposures.length === 0 ? (
                    <div className="py-12 text-center text-zinc-500 font-mono text-xs flex flex-col items-center gap-2">
                      <ShieldAlert className="w-6 h-6 text-zinc-600" />
                      <p>No exposure records loaded in compliance report cache.</p>
                      <button
                        onClick={() => handleScan(report.url)}
                        className="px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 text-white rounded font-mono text-xs cursor-pointer"
                      >
                        RE-INITIALIZE DIRECTORY SCAN
                      </button>
                    </div>
                  ) : (
                    <div className="overflow-x-auto">
                      <table className="w-full text-left text-xs font-mono">
                        <thead>
                          <tr className="bg-[#121212] text-zinc-400 font-bold border-b border-zinc-800">
                            <th className="py-2 px-3 w-32 border-r border-zinc-800">SEVERITY</th>
                            <th className="py-2 px-3 w-52 border-r border-zinc-800">INSPECTED PARAMETER</th>
                            <th className="py-2 px-3 border-r border-zinc-800">DISCOVERED TARGET ENDPOINT</th>
                            <th className="py-2 px-3">VULNERABILITY ASSESSMENT FINDINGS</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-zinc-800/60">
                          {report.exposures.map((exp, index) => {
                            let statusBadge = (
                              <span className="px-1.5 py-0.5 text-[10px] font-bold bg-emerald-950/40 text-emerald-500 border border-emerald-900/50 rounded">
                                SECURE
                              </span>
                            );
                            if (exp.status === 'danger') {
                              statusBadge = (
                                <span className="px-1.5 py-0.5 text-[10px] font-bold bg-red-950/40 text-red-400 border border-red-900/60 rounded">
                                  CRITICAL
                                </span>
                              );
                            } else if (exp.status === 'warning') {
                              statusBadge = (
                                <span className="px-1.5 py-0.5 text-[10px] font-bold bg-yellow-950/40 text-yellow-500 border border-yellow-900/50 rounded">
                                  WARNING
                                </span>
                              );
                            }

                            return (
                              <tr key={index} className="hover:bg-[#121212]/50">
                                <td className="py-3 px-3 border-r border-zinc-800">
                                  {statusBadge}
                                </td>
                                <td className="py-3 px-3 border-r border-zinc-800 font-bold text-zinc-200">
                                  {exp.name}
                                </td>
                                <td className="py-3 px-3 border-r border-zinc-800 truncate max-w-xs text-blue-400 select-all font-mono text-[11px]" title={exp.url}>
                                  <a href={exp.url} target="_blank" referrerPolicy="no-referrer" className="hover:underline">
                                    {exp.url}
                                  </a>
                                </td>
                                <td className="py-3 px-3 text-zinc-300 text-[11px] leading-relaxed">
                                  <p className="font-bold text-zinc-200">{exp.details}</p>
                                  <p className="text-zinc-500 mt-1">Remediation: {exp.recommendation}</p>
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  )}

                </div>
              )}

              {/* VIEW 4: AI SECURITY AUDIT */}
              {activeView === 'ai' && (
                <div className="bg-[#1a1a1a] border border-zinc-800 rounded p-4 flex flex-col gap-4 animate-fade-in">
                  
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-zinc-800 pb-3">
                    <div>
                      <h3 className="text-xs font-mono font-bold uppercase text-white flex items-center gap-1.5">
                        <Sparkles className="w-3.5 h-3.5 text-yellow-500/90" />
                        Gemini Pro Security Posture Evaluation Audit
                      </h3>
                      <p className="text-[11px] text-zinc-500 mt-0.5 font-mono">
                        Generates server configuration setups and threat models based on active findings.
                      </p>
                    </div>

                    {hasGemini && (
                      <button
                        onClick={handleAiAudit}
                        disabled={loadingAiAudit}
                        className="text-[11px] font-mono bg-zinc-800 hover:bg-zinc-700 text-zinc-200 px-3 py-1 border border-zinc-700 rounded transition flex items-center gap-1.5 cursor-pointer"
                      >
                        <RefreshCw className={`w-3.5 h-3.5 ${loadingAiAudit ? 'animate-spin' : ''}`} />
                        <span>{loadingAiAudit ? 'GENERATING_AUDIT...' : 'REGENERATE_AUDIT'}</span>
                      </button>
                    )}
                  </div>

                  {!hasGemini ? (
                    <div className="py-12 px-6 text-center text-zinc-400 font-mono text-xs flex flex-col items-center gap-4 bg-[#121212] border border-zinc-800/80 rounded-lg max-w-xl mx-auto my-4">
                      <Sparkles className="w-8 h-8 text-zinc-600 animate-pulse" />
                      <div className="space-y-2">
                        <p className="font-bold text-white text-sm">AI Security Audit Is Optional</p>
                        <p className="text-zinc-500 leading-relaxed text-[11px]">
                          AI Analysis is optional. Add your Gemini API key in a local .env file to enable AI explanations.
                        </p>
                      </div>
                      <div className="p-3 bg-[#1a1a1a] border border-zinc-800 rounded text-left w-full space-y-1.5 text-[10px] text-zinc-500">
                        <p className="font-bold text-zinc-400">To enable AI-powered deep auditing:</p>
                        <ol className="list-decimal pl-4 space-y-1">
                          <li>Create a <code className="text-blue-400 bg-blue-950/20 px-1 py-0.5 rounded border border-blue-900/40">.env</code> file in the project root.</li>
                          <li>Add <code className="text-emerald-400 bg-emerald-950/20 px-1 py-0.5 rounded border border-emerald-900/40">GEMINI_API_KEY=your_key_here</code>.</li>
                          <li>Restart the application server.</li>
                        </ol>
                      </div>
                    </div>
                  ) : loadingAiAudit ? (
                    <div className="py-16 flex flex-col items-center justify-center gap-4">
                      <div className="w-8 h-8 border-2 border-zinc-600 border-t-blue-500 rounded-full animate-spin" />
                      <div className="text-center flex flex-col gap-1 font-mono text-xs">
                        <span className="text-blue-500 font-bold uppercase tracking-wider">Compiling AI Audit report...</span>
                        <p className="text-zinc-500 max-w-xs text-[11px]">Gemini is assembling threat directives and security policy patches.</p>
                      </div>
                    </div>
                  ) : aiAuditText ? (
                    <div className="flex flex-col gap-2">
                      <div className="flex justify-between items-center bg-[#121212] border border-zinc-800 px-3 py-1.5 rounded-t text-[11px] font-mono text-zinc-500">
                        <span>AUDIT_OUTPUT_TEXT</span>
                        <button 
                          onClick={() => copyToClipboard(aiAuditText, 'ai_audit', 'code')}
                          className="hover:text-white transition"
                        >
                          [ COPY_RAW_MARKDOWN ]
                        </button>
                      </div>
                      <div className="bg-[#121212] border border-zinc-800 border-t-0 p-4 rounded-b text-xs text-zinc-300 font-mono leading-relaxed max-h-[500px] overflow-y-auto whitespace-pre-wrap select-text">
                        {aiAuditText}
                      </div>
                    </div>
                  ) : (
                    <div className="py-16 text-center text-zinc-500 font-mono text-xs flex flex-col items-center gap-3">
                      <Sparkles className="w-6 h-6 text-yellow-500/50" />
                      <p>No security audit compiled yet.</p>
                      <button
                        onClick={handleAiAudit}
                        className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white font-bold rounded cursor-pointer"
                      >
                        RUN GEMINI THREAT MODELING
                      </button>
                    </div>
                  )}

                </div>
              )}

              {/* VIEW 5: RAW HEADERS */}
              {activeView === 'raw' && (
                <div className="bg-[#1a1a1a] border border-zinc-800 rounded p-4 flex flex-col gap-3 animate-fade-in">
                  
                  <div className="flex items-center justify-between border-b border-zinc-800 pb-2">
                    <span className="text-xs font-mono font-bold uppercase text-white tracking-wider">
                      HTTP Response Header Stream Dump
                    </span>
                    <span className="text-[10px] font-mono text-zinc-500">
                      Standard GET Response Stream (Raw)
                    </span>
                  </div>

                  <div className="bg-[#121212] border border-zinc-800 rounded p-4 max-h-[450px] overflow-y-auto">
                    <pre className="font-mono text-xs text-blue-400/90 leading-relaxed select-text">
                      <div className="text-zinc-500 pb-2 mb-2 border-b border-zinc-800">
                        HTTP/1.1 {report.statusCode || 200} OK<br />
                        Date: {report.scannedAt}
                      </div>
                      {Object.entries(report.rawHeaders).map(([key, val]) => (
                        <div key={key} className="flex py-1 hover:bg-zinc-800/20 rounded">
                          <span className="text-zinc-400 font-bold shrink-0 min-w-[180px] select-all">{key}:</span>
                          <span className="text-zinc-300 break-all select-all pl-2">{val}</span>
                        </div>
                      ))}
                    </pre>
                  </div>

                </div>
              )}

              {/* VIEW 6: JSON OUTPUT */}
              {activeView === 'json' && (
                <div className="bg-[#1a1a1a] border border-zinc-800 rounded p-4 flex flex-col gap-3 animate-fade-in">
                  
                  <div className="flex items-center justify-between border-b border-zinc-800 pb-2">
                    <div className="flex flex-col">
                      <span className="text-xs font-mono font-bold uppercase text-white tracking-wider">
                        GET /scan/headers Response JSON Stream
                      </span>
                      <p className="text-[10px] text-zinc-500 mt-0.5 font-mono">
                        Use this raw dataset to feed deployment pipelines and CI check steps.
                      </p>
                    </div>

                    <button
                      onClick={() => copyToClipboard(JSON.stringify(report, null, 2), 'json', 'json')}
                      className="text-[11px] font-mono bg-zinc-800 hover:bg-zinc-700 text-zinc-200 px-3 py-1 border border-zinc-700 rounded transition cursor-pointer"
                    >
                      {copiedJson ? 'COPIED!' : 'COPY_JSON_STREAM'}
                    </button>
                  </div>

                  <div className="bg-[#121212] border border-zinc-800 rounded p-4 max-h-[450px] overflow-y-auto">
                    <pre className="font-mono text-xs text-emerald-500/90 leading-relaxed select-text whitespace-pre">
                      {JSON.stringify(report, null, 2)}
                    </pre>
                  </div>

                </div>
              )}

            </div>
          )}

          {/* VIEW 7: SCANNER CONFIGURATION SETTINGS */}
          {activeView === 'settings' && (
            <section className="bg-[#1a1a1a] border border-zinc-800 rounded p-5 flex flex-col gap-4 animate-fade-in">
              <div className="border-b border-zinc-800 pb-2">
                <h3 className="text-xs font-mono font-bold uppercase text-white tracking-wider">
                  Auditor Engine Settings & Profiles
                </h3>
                <p className="text-[11px] text-zinc-500 font-mono mt-0.5">
                  Adjust standard scan profile constraints and custom HTTP metadata.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
                
                {/* Timeout setting */}
                <div className="flex flex-col gap-2">
                  <label className="text-zinc-400 font-bold">SCAN_TIMEOUT_LIMIT</label>
                  <p className="text-[11px] text-zinc-500 leading-normal">
                    The maximum time limits permitted for DNS lookup and header acquisition before aborting.
                  </p>
                  <select 
                    value={scannerTimeout} 
                    onChange={(e) => setScannerTimeout(Number(e.target.value))}
                    className="bg-[#121212] border border-zinc-800 text-zinc-200 rounded px-3 py-2 outline-none focus:border-blue-600"
                  >
                    <option value={2500}>2500 ms (Standard)</option>
                    <option value={5000}>5000 ms (Slow Connection)</option>
                    <option value={10000}>10000 ms (Strict Maximum)</option>
                  </select>
                </div>

                {/* User Agent setting */}
                <div className="flex flex-col gap-2">
                  <label className="text-zinc-400 font-bold">SCAN_USER_AGENT</label>
                  <p className="text-[11px] text-zinc-500 leading-normal">
                    Custom HTTP user agent passed inside standard request headers during reconnaissance.
                  </p>
                  <input
                    type="text"
                    value={customUserAgent}
                    onChange={(e) => setCustomUserAgent(e.target.value)}
                    className="bg-[#121212] border border-zinc-800 text-zinc-200 rounded px-3 py-2 outline-none focus:border-blue-600"
                  />
                </div>

                {/* Benchmark Profiles selection */}
                <div className="flex flex-col gap-2">
                  <label className="text-zinc-400 font-bold">COMPLIANCE_BENCHMARK_PROFILE</label>
                  <p className="text-[11px] text-zinc-500 leading-normal">
                    The policy profiles and score weightings used to calculate letter grades and threat severity.
                  </p>
                  <div className="flex gap-2">
                    {(['owasp', 'cis', 'dod'] as const).map((profile) => (
                      <button
                        key={profile}
                        onClick={() => setBenchmarkProfile(profile)}
                        className={`flex-1 py-2 border rounded font-bold uppercase text-[11px] transition cursor-pointer ${
                          benchmarkProfile === profile 
                            ? 'bg-blue-600/10 text-blue-400 border-blue-600/50' 
                            : 'bg-[#121212] text-zinc-500 border-zinc-800 hover:text-zinc-300'
                        }`}
                      >
                        {profile === 'owasp' ? 'OWASP Top 10' : profile === 'cis' ? 'CIS Bench' : 'DoD Secure'}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Simulation rules */}
                <div className="flex flex-col gap-2 bg-[#121212] p-3 border border-zinc-800 rounded">
                  <span className="text-zinc-400 font-bold">LOCAL_DATABASE_CLEANUP</span>
                  <p className="text-[11px] text-zinc-500 leading-normal mt-1">
                    Remove all persistent localStorage cached domains and restore original benchmark presets.
                  </p>
                  <button
                    onClick={clearHistory}
                    className={`mt-2 py-1.5 px-3 border transition rounded font-bold text-[10px] uppercase cursor-pointer ${
                      historyCleared 
                        ? 'bg-emerald-950/40 text-emerald-400 border-emerald-900/40 hover:border-emerald-500/40' 
                        : 'bg-red-950/20 hover:bg-red-950/40 text-red-400 border-red-900/40 hover:border-red-500/40'
                    }`}
                  >
                    {historyCleared ? '✓ History Purged!' : 'Purge History & Reset Defaults'}
                  </button>
                </div>

              </div>
            </section>
          )}

        </main>
      </div>

      {/* 3. FOOTER */}
      <footer className="h-8 bg-[#161616] border-t border-zinc-800 px-4 flex items-center justify-between text-[10px] font-mono text-zinc-500 select-none shrink-0">
        <span>KEPOKSCAN SECURITY SYSTEMS • COMPLIANCE AUDITING FRAMEWORK</span>
        <div className="flex gap-3">
          <span className="text-zinc-500 hover:text-zinc-400 cursor-help" title="Strict-Transport-Security">HSTS</span>
          <span>•</span>
          <span className="text-zinc-500 hover:text-zinc-400 cursor-help" title="Content-Security-Policy">CSP</span>
          <span>•</span>
          <span className="text-zinc-500 hover:text-zinc-400 cursor-help" title="X-Frame-Options">XFO</span>
          <span>•</span>
          <span className="text-zinc-500 hover:text-zinc-400 cursor-help" title="X-Content-Type-Options">XCTO</span>
        </div>
      </footer>

    </div>
  );
}
