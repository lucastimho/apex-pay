import { useState, useEffect, useCallback, useMemo, useRef } from "react";
import {
  Shield, ShieldAlert, ShieldCheck, ShieldX, Activity, DollarSign,
  Users, AlertTriangle, Eye, EyeOff, Search, ChevronRight, X,
  Zap, Globe, Clock, TrendingUp, BarChart3, Settings, Power,
  RefreshCw, Filter, Bell, Terminal, Cpu, Radio, CircleDot,
  ChevronDown, Check, Pencil, Save, Ban, ExternalLink,
} from "lucide-react";
import { PieChart, Pie, Cell, ResponsiveContainer } from "recharts";

// ═══════════════════════════════════════════════════════════════════════════
// MOCK DATA — Replace with TanStack Query calls to APEX-Pay FastAPI backend
// ═══════════════════════════════════════════════════════════════════════════
const MOCK_AGENTS = [
  { id: "a1", name: "GPT-Buyer", status: "active", balance: 342.18, dailySpend: 157.82, dailyLimit: 200, riskAvg: 22, txCount: 48 },
  { id: "a2", name: "Claude-Ops", status: "active", balance: 891.50, dailySpend: 42.50, dailyLimit: 500, riskAvg: 8, txCount: 15 },
  { id: "a3", name: "Agent-Smith", status: "suspended", balance: 0, dailySpend: 200, dailyLimit: 200, riskAvg: 87, txCount: 112 },
  { id: "a4", name: "Gemini-Pay", status: "active", balance: 1250.00, dailySpend: 89.00, dailyLimit: 300, riskAvg: 31, txCount: 27 },
  { id: "a5", name: "Llama-Trade", status: "active", balance: 455.33, dailySpend: 178.67, dailyLimit: 250, riskAvg: 56, txCount: 63 },
];

const STATUSES = ["APPROVED", "DENIED", "PENDING_REVIEW"];
const DOMAINS = ["api.stripe.com", "api.openai.com", "api.shopify.com", "payments.google.com", "evil.example.com"];
const FUNCTIONS = ["charge_card", "book_flight", "subscribe", "purchase_api_credits", "transfer_funds", "refund", "list_products"];

function generateAuditEntry(i) {
  const status = STATUSES[Math.random() < 0.55 ? 0 : Math.random() < 0.7 ? 1 : 2];
  const agent = MOCK_AGENTS[Math.floor(Math.random() * MOCK_AGENTS.length)];
  const cost = +(Math.random() * 80 + 1).toFixed(2);
  const risk = Math.min(100, Math.max(0, Math.floor(Math.random() * 100)));
  return {
    id: `log-${Date.now()}-${i}`,
    timestamp: new Date(Date.now() - Math.random() * 86400000).toISOString(),
    agentName: agent.name,
    agentId: agent.id,
    status,
    function: FUNCTIONS[Math.floor(Math.random() * FUNCTIONS.length)],
    domain: DOMAINS[Math.floor(Math.random() * DOMAINS.length)],
    cost,
    riskScore: risk,
    reason: status === "DENIED" ? (risk > 60 ? "daily_budget_exceeded" : "domain_not_allowed") : status === "PENDING_REVIEW" ? "elevated_risk_score" : "policy_passed",
    rawIntent: { function: "charge_card", target_url: `https://${DOMAINS[Math.floor(Math.random() * DOMAINS.length)]}/v1/charges`, parameters: { amount: cost, currency: "USD" } },
  };
}

const INITIAL_LOGS = Array.from({ length: 60 }, (_, i) => generateAuditEntry(i))
  .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

// ═══════════════════════════════════════════════════════════════════════════
// THEME TOKENS — Cyber-Noir palette
// ═══════════════════════════════════════════════════════════════════════════
const T = {
  bg: "#0a0e17", surface: "#111827", surfaceAlt: "#1a2236", border: "#1e293b",
  borderHover: "#334155", text: "#e2e8f0", textMuted: "#94a3b8", textDim: "#64748b",
  accent: "#38bdf8", accentDim: "#0ea5e9", emerald: "#34d399", emeraldDim: "#059669",
  rose: "#fb7185", roseDim: "#e11d48", amber: "#fbbf24", amberDim: "#d97706",
  violet: "#a78bfa", cyan: "#22d3ee",
};

// ═══════════════════════════════════════════════════════════════════════════
// UTILITY COMPONENTS
// ═══════════════════════════════════════════════════════════════════════════
function Badge({ children, color = T.accent, style }) {
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: 4,
      padding: "2px 10px", borderRadius: 9999, fontSize: 11, fontWeight: 600,
      letterSpacing: "0.03em", textTransform: "uppercase",
      background: color + "18", color, border: `1px solid ${color}30`,
      ...style,
    }}>
      {children}
    </span>
  );
}

function StatusBadge({ status }) {
  const map = {
    APPROVED: { color: T.emerald, icon: <ShieldCheck size={12} /> },
    DENIED: { color: T.rose, icon: <ShieldX size={12} /> },
    PENDING_REVIEW: { color: T.amber, icon: <ShieldAlert size={12} /> },
  };
  const s = map[status] || map.APPROVED;
  return <Badge color={s.color}>{s.icon} {status.replace("_", " ")}</Badge>;
}

function Card({ children, style, onClick }) {
  return (
    <div onClick={onClick} style={{
      background: T.surface, border: `1px solid ${T.border}`, borderRadius: 12,
      padding: 20, position: "relative", overflow: "hidden",
      cursor: onClick ? "pointer" : "default",
      transition: "border-color 0.2s, box-shadow 0.2s",
      ...style,
    }}
    onMouseEnter={e => { e.currentTarget.style.borderColor = T.borderHover; e.currentTarget.style.boxShadow = `0 0 20px ${T.accent}08`; }}
    onMouseLeave={e => { e.currentTarget.style.borderColor = T.border; e.currentTarget.style.boxShadow = "none"; }}
    >
      {children}
    </div>
  );
}

function SectionHeader({ icon, title, subtitle, action }) {
  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 16 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <div style={{ color: T.accent, display: "flex" }}>{icon}</div>
        <div>
          <h2 style={{ margin: 0, fontSize: 16, fontWeight: 700, color: T.text }}>{title}</h2>
          {subtitle && <p style={{ margin: 0, fontSize: 12, color: T.textDim }}>{subtitle}</p>}
        </div>
      </div>
      {action}
    </div>
  );
}

function Btn({ children, variant = "default", style, ...props }) {
  const base = { display: "inline-flex", alignItems: "center", gap: 6, padding: "7px 14px", borderRadius: 8, fontSize: 13, fontWeight: 600, cursor: "pointer", border: "none", transition: "all 0.15s", fontFamily: "inherit" };
  const variants = {
    default: { background: T.surfaceAlt, color: T.text, border: `1px solid ${T.border}` },
    primary: { background: T.accent, color: "#0a0e17" },
    danger: { background: T.roseDim + "30", color: T.rose, border: `1px solid ${T.roseDim}40` },
    ghost: { background: "transparent", color: T.textMuted },
  };
  return <button style={{ ...base, ...variants[variant], ...style }} {...props}>{children}</button>;
}

// ═══════════════════════════════════════════════════════════════════════════
// RISK METER — Semi-circle SVG gauge
// ═══════════════════════════════════════════════════════════════════════════
function RiskMeter({ score = 0, size = 140 }) {
  const clamp = Math.min(100, Math.max(0, score));
  const r = 55, cx = 70, cy = 70, strokeW = 12;
  const circumference = Math.PI * r;
  const offset = circumference - (clamp / 100) * circumference;
  const color = clamp < 30 ? T.emerald : clamp < 60 ? T.amber : T.rose;
  const label = clamp < 30 ? "LOW" : clamp < 60 ? "MEDIUM" : "HIGH";

  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
      <svg width={size} height={size * 0.6} viewBox="0 0 140 85" style={{ overflow: "visible" }}>
        <defs>
          <linearGradient id={`rg-${score}`} x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor={T.emerald} />
            <stop offset="50%" stopColor={T.amber} />
            <stop offset="100%" stopColor={T.rose} />
          </linearGradient>
        </defs>
        {/* Track */}
        <path d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
          fill="none" stroke={T.border} strokeWidth={strokeW} strokeLinecap="round" />
        {/* Fill */}
        <path d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
          fill="none" stroke={color} strokeWidth={strokeW} strokeLinecap="round"
          strokeDasharray={circumference} strokeDashoffset={offset}
          style={{ transition: "stroke-dashoffset 0.8s ease, stroke 0.4s ease", filter: `drop-shadow(0 0 6px ${color}60)` }} />
        {/* Score */}
        <text x={cx} y={cy - 12} textAnchor="middle" fill={T.text} fontSize="28" fontWeight="800" fontFamily="inherit">{clamp}</text>
        <text x={cx} y={cy + 4} textAnchor="middle" fill={color} fontSize="10" fontWeight="700" fontFamily="inherit" letterSpacing="0.1em">{label} RISK</text>
      </svg>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// HEAT BAR — Budget utilisation (blue → orange → red)
// ═══════════════════════════════════════════════════════════════════════════
function HeatBar({ spent, limit }) {
  const pct = Math.min(100, (spent / limit) * 100);
  const color = pct < 50 ? T.accent : pct < 80 ? T.amber : T.rose;
  return (
    <div style={{ width: "100%", marginTop: 6 }}>
      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: T.textDim, marginBottom: 3 }}>
        <span>${spent.toFixed(0)} / ${limit.toFixed(0)}</span>
        <span style={{ color }}>{pct.toFixed(0)}%</span>
      </div>
      <div style={{ width: "100%", height: 6, background: T.surfaceAlt, borderRadius: 3, overflow: "hidden" }}>
        <div style={{ width: `${pct}%`, height: "100%", background: `linear-gradient(90deg, ${T.accentDim}, ${color})`, borderRadius: 3, transition: "width 0.6s ease, background 0.4s", boxShadow: pct > 80 ? `0 0 8px ${color}60` : "none" }} />
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// STAT CARD — Dashboard top row
// ═══════════════════════════════════════════════════════════════════════════
function useIsMobile(breakpoint = 768) {
  const [mobile, setMobile] = useState(typeof window !== "undefined" ? window.innerWidth < breakpoint : false);
  useEffect(() => {
    const mq = window.matchMedia(`(max-width: ${breakpoint - 1}px)`);
    const handler = (e) => setMobile(e.matches);
    setMobile(mq.matches);
    mq.addEventListener("change", handler);
    return () => mq.removeEventListener("change", handler);
  }, [breakpoint]);
  return mobile;
}

function StatCard({ icon, label, value, sub, color = T.accent }) {
  return (
    <Card style={{ flex: "1 1 260px", minWidth: 0 }}>
      <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 3, background: `linear-gradient(90deg, ${color}, transparent)` }} />
      <div style={{ display: "flex", alignItems: "flex-start", gap: 14 }}>
        <div style={{ padding: 10, borderRadius: 10, background: color + "14", color, flexShrink: 0, display: "flex" }}>{icon}</div>
        <div>
          <p style={{ margin: 0, fontSize: 12, color: T.textDim, fontWeight: 500, textTransform: "uppercase", letterSpacing: "0.05em" }}>{label}</p>
          <p style={{ margin: "4px 0 0", fontSize: 28, fontWeight: 800, color: T.text, lineHeight: 1 }}>{value}</p>
          {sub && <p style={{ margin: "6px 0 0", fontSize: 12, color: T.textMuted }}>{sub}</p>}
        </div>
      </div>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// AUDIT FEED — Live Nerve Center
// ═══════════════════════════════════════════════════════════════════════════
function AuditFeed({ logs, onSelect }) {
  const [filter, setFilter] = useState("ALL");
  const [search, setSearch] = useState("");
  const filtered = useMemo(() => {
    let r = logs;
    if (filter !== "ALL") r = r.filter(l => l.status === filter);
    if (search) r = r.filter(l => l.agentName.toLowerCase().includes(search.toLowerCase()) || l.function.toLowerCase().includes(search.toLowerCase()) || l.domain?.toLowerCase().includes(search.toLowerCase()));
    return r;
  }, [logs, filter, search]);

  return (
    <Card style={{ flex: 1, display: "flex", flexDirection: "column", minHeight: 400 }}>
      <SectionHeader icon={<Radio size={18} />} title="Live Nerve Center" subtitle={`${logs.length} events — streaming`} />
      {/* Toolbar */}
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
        {["ALL", "APPROVED", "DENIED", "PENDING_REVIEW"].map(f => (
          <Btn key={f} variant={filter === f ? "primary" : "default"} onClick={() => setFilter(f)}
            style={{ fontSize: 11, padding: "4px 10px" }}>
            {f === "ALL" ? "All" : f.replace("_", " ")}
          </Btn>
        ))}
        <div style={{ flex: "1 1 160px", minWidth: 120, display: "flex", alignItems: "center", gap: 6, background: T.surfaceAlt, borderRadius: 8, padding: "0 10px", border: `1px solid ${T.border}` }}>
          <Search size={14} color={T.textDim} style={{ flexShrink: 0 }} />
          <input placeholder="Search…" value={search} onChange={e => setSearch(e.target.value)}
            style={{ background: "none", border: "none", color: T.text, fontSize: 12, padding: "6px 0", outline: "none", width: "100%", minWidth: 0, fontFamily: "inherit" }} />
        </div>
      </div>
      {/* Log list */}
      <div style={{ flex: 1, overflowY: "auto", maxHeight: 360 }}>
        {filtered.length === 0 && <p style={{ color: T.textDim, fontSize: 13, textAlign: "center", padding: 30 }}>No matching events.</p>}
        {filtered.map(log => (
          <div key={log.id} onClick={() => onSelect(log)}
            style={{
              display: "flex", alignItems: "center", gap: 12, padding: "10px 12px",
              borderBottom: `1px solid ${T.border}`, cursor: "pointer",
              transition: "background 0.1s",
            }}
            onMouseEnter={e => e.currentTarget.style.background = T.surfaceAlt}
            onMouseLeave={e => e.currentTarget.style.background = "transparent"}
          >
            <div style={{ width: 4, height: 32, borderRadius: 2, background: log.status === "APPROVED" ? T.emerald : log.status === "DENIED" ? T.rose : T.amber, flexShrink: 0 }} />
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                <span style={{ fontSize: 13, fontWeight: 600, color: T.text }}>{log.agentName}</span>
                <span style={{ fontSize: 12, color: T.textDim, fontFamily: "monospace" }}>{log.function}()</span>
                <StatusBadge status={log.status} />
              </div>
              <div style={{ fontSize: 11, color: T.textDim, marginTop: 3, display: "flex", gap: 12 }}>
                <span><Globe size={10} style={{ verticalAlign: "-1px" }} /> {log.domain || "internal"}</span>
                <span><DollarSign size={10} style={{ verticalAlign: "-1px" }} /> ${log.cost.toFixed(2)}</span>
                <span>Risk: {log.riskScore}</span>
              </div>
            </div>
            <span style={{ fontSize: 11, color: T.textDim, whiteSpace: "nowrap" }}>
              {new Date(log.timestamp).toLocaleTimeString()}
            </span>
            <ChevronRight size={14} color={T.textDim} />
          </div>
        ))}
      </div>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// LOG DETAIL SLIDE-OVER
// ═══════════════════════════════════════════════════════════════════════════
function LogDetail({ log, onClose }) {
  if (!log) return null;
  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 1000, display: "flex", justifyContent: "flex-end" }}
      onClick={onClose}>
      <div style={{ position: "absolute", inset: 0, background: "rgba(0,0,0,0.6)", backdropFilter: "blur(4px)" }} />
      <div onClick={e => e.stopPropagation()}
        style={{ position: "relative", width: "min(480px, 100vw)", height: "100%", background: T.surface, borderLeft: `1px solid ${T.border}`, padding: "20px clamp(14px, 4vw, 24px)", overflowY: "auto", animation: "slideIn 0.2s ease", WebkitOverflowScrolling: "touch" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
          <h3 style={{ margin: 0, fontSize: 16, color: T.text }}>Event Detail</h3>
          <Btn variant="ghost" onClick={onClose}><X size={16} /></Btn>
        </div>
        <StatusBadge status={log.status} />
        <div style={{ marginTop: 20 }}>
          <RiskMeter score={log.riskScore} size={160} />
        </div>
        {/* Intent Analyzer — Semantic Highlight */}
        <div style={{ marginTop: 20 }}>
          <p style={{ fontSize: 11, color: T.textDim, textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 8 }}>Intent Analysis</p>
          <div style={{ background: T.surfaceAlt, borderRadius: 8, padding: 14, fontSize: 13, color: T.textMuted, lineHeight: 1.6 }}>
            Agent <b style={{ color: T.cyan }}>{log.agentName}</b> requested{" "}
            <b style={{ color: T.violet }}>{log.function}()</b> targeting{" "}
            <b style={{ color: T.accent }}>{log.domain}</b> for{" "}
            <b style={{ color: T.amber }}>${log.cost.toFixed(2)}</b>.
            {log.status === "DENIED" && <span style={{ color: T.rose }}> Blocked: {log.reason}.</span>}
            {log.status === "APPROVED" && <span style={{ color: T.emerald }}> Transaction cleared.</span>}
          </div>
        </div>
        {/* Metadata rows */}
        <div style={{ marginTop: 20 }}>
          {[
            ["Agent", log.agentName], ["Function", log.function], ["Domain", log.domain],
            ["Cost", `$${log.cost.toFixed(2)}`], ["Risk Score", log.riskScore],
            ["Reason", log.reason], ["Timestamp", new Date(log.timestamp).toLocaleString()],
          ].map(([k, v]) => (
            <div key={k} style={{ display: "flex", justifyContent: "space-between", padding: "8px 0", borderBottom: `1px solid ${T.border}`, fontSize: 13 }}>
              <span style={{ color: T.textDim }}>{k}</span>
              <span style={{ color: T.text, fontWeight: 500, fontFamily: k === "Function" ? "monospace" : "inherit" }}>{v}</span>
            </div>
          ))}
        </div>
        {/* Raw JSON */}
        <div style={{ marginTop: 20 }}>
          <p style={{ fontSize: 11, color: T.textDim, textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 8 }}>Raw Intent Payload</p>
          <pre style={{ background: T.bg, borderRadius: 8, padding: 14, fontSize: 11, color: T.accent, overflow: "auto", maxHeight: 200, border: `1px solid ${T.border}`, margin: 0, fontFamily: "monospace", lineHeight: 1.5 }}>
            {JSON.stringify(log.rawIntent, null, 2)}
          </pre>
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// AGENT REGISTRY — with Kill Switch
// ═══════════════════════════════════════════════════════════════════════════
function AgentRegistry({ agents, onToggle }) {
  return (
    <Card>
      <SectionHeader icon={<Cpu size={18} />} title="Agent Registry" subtitle={`${agents.filter(a => a.status === "active").length} active of ${agents.length}`} />
      <div style={{ display: "grid", gap: 10 }}>
        {agents.map(agent => {
          const active = agent.status === "active";
          return (
            <div key={agent.id} style={{
              display: "flex", alignItems: "center", gap: 14, padding: 14,
              background: T.surfaceAlt, borderRadius: 10,
              border: `1px solid ${active ? T.border : T.roseDim + "40"}`,
              opacity: active ? 1 : 0.65,
            }}>
              {/* Status dot */}
              <div style={{ width: 10, height: 10, borderRadius: "50%", background: active ? T.emerald : T.rose, boxShadow: `0 0 8px ${active ? T.emerald : T.rose}50`, flexShrink: 0 }} />
              {/* Info */}
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ fontSize: 14, fontWeight: 700, color: T.text }}>{agent.name}</span>
                  <Badge color={active ? T.emerald : T.rose}>{active ? "ACTIVE" : "SUSPENDED"}</Badge>
                </div>
                <div style={{ fontSize: 11, color: T.textDim, marginTop: 3, display: "flex", gap: 14, flexWrap: "wrap" }}>
                  <span>Balance: <b style={{ color: T.text }}>${agent.balance.toFixed(2)}</b></span>
                  <span>Txns: {agent.txCount}</span>
                  <span>Avg Risk: {agent.riskAvg}</span>
                </div>
                <HeatBar spent={agent.dailySpend} limit={agent.dailyLimit} />
              </div>
              {/* Kill switch */}
              <button onClick={() => onToggle(agent.id)}
                title={active ? "Suspend Agent" : "Reactivate Agent"}
                style={{
                  width: 44, height: 26, borderRadius: 13, border: "none", cursor: "pointer",
                  background: active ? T.emerald + "30" : T.rose + "30",
                  position: "relative", transition: "background 0.2s", flexShrink: 0,
                }}>
                <div style={{
                  width: 20, height: 20, borderRadius: "50%",
                  background: active ? T.emerald : T.rose,
                  position: "absolute", top: 3,
                  left: active ? 21 : 3,
                  transition: "left 0.2s, background 0.2s",
                  boxShadow: `0 0 6px ${active ? T.emerald : T.rose}60`,
                }} />
              </button>
            </div>
          );
        })}
      </div>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// POLICY STUDIO — Form editor with validation
// ═══════════════════════════════════════════════════════════════════════════
function PolicyStudio() {
  const [daily, setDaily] = useState("200.00");
  const [maxTxn, setMaxTxn] = useState("50.00");
  const [domains, setDomains] = useState("api.stripe.com, api.openai.com");
  const [errors, setErrors] = useState({});
  const [saved, setSaved] = useState(false);

  const validate = () => {
    const e = {};
    const d = parseFloat(daily);
    const m = parseFloat(maxTxn);
    if (isNaN(d) || d <= 0) e.daily = "Must be a positive number";
    if (isNaN(m) || m <= 0) e.maxTxn = "Must be a positive number";
    if (m > d) e.maxTxn = "Cannot exceed daily limit";
    const domList = domains.split(",").map(s => s.trim()).filter(Boolean);
    if (domList.length === 0) e.domains = "At least one domain required";
    const domRegex = /^[a-z0-9.-]+\.[a-z]{2,}$/i;
    const invalid = domList.filter(d => !domRegex.test(d));
    if (invalid.length) e.domains = `Invalid: ${invalid.join(", ")}`;
    setErrors(e);
    return Object.keys(e).length === 0;
  };

  const onSave = () => {
    if (!validate()) return;
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  const inputStyle = (err) => ({
    width: "100%", padding: "10px 12px", borderRadius: 8, border: `1px solid ${err ? T.roseDim : T.border}`,
    background: T.surfaceAlt, color: T.text, fontSize: 14, fontFamily: "inherit", outline: "none",
    transition: "border-color 0.15s", boxSizing: "border-box",
  });

  return (
    <Card>
      <SectionHeader icon={<Settings size={18} />} title="Policy Studio" subtitle="Edit enforcement rules" />
      <div style={{ display: "grid", gap: 16 }}>
        {/* Daily Limit */}
        <div>
          <label style={{ fontSize: 12, color: T.textMuted, fontWeight: 600, marginBottom: 4, display: "block" }}>
            Daily Limit ($)
          </label>
          <input value={daily} onChange={e => setDaily(e.target.value)} style={inputStyle(errors.daily)}
            onFocus={e => e.target.style.borderColor = T.accent}
            onBlur={e => e.target.style.borderColor = errors.daily ? T.roseDim : T.border} />
          {errors.daily && <p style={{ color: T.rose, fontSize: 11, margin: "4px 0 0" }}>{errors.daily}</p>}
        </div>
        {/* Max per Transaction */}
        <div>
          <label style={{ fontSize: 12, color: T.textMuted, fontWeight: 600, marginBottom: 4, display: "block" }}>
            Max Per Transaction ($)
          </label>
          <input value={maxTxn} onChange={e => setMaxTxn(e.target.value)} style={inputStyle(errors.maxTxn)}
            onFocus={e => e.target.style.borderColor = T.accent}
            onBlur={e => e.target.style.borderColor = errors.maxTxn ? T.roseDim : T.border} />
          {errors.maxTxn && <p style={{ color: T.rose, fontSize: 11, margin: "4px 0 0" }}>{errors.maxTxn}</p>}
        </div>
        {/* Allowed Domains */}
        <div>
          <label style={{ fontSize: 12, color: T.textMuted, fontWeight: 600, marginBottom: 4, display: "block" }}>
            Allowed Domains <span style={{ fontWeight: 400, color: T.textDim }}>(comma-separated)</span>
          </label>
          <textarea value={domains} onChange={e => setDomains(e.target.value)} rows={3}
            style={{ ...inputStyle(errors.domains), resize: "vertical", fontFamily: "monospace", fontSize: 12 }}
            onFocus={e => e.target.style.borderColor = T.accent}
            onBlur={e => e.target.style.borderColor = errors.domains ? T.roseDim : T.border} />
          {errors.domains && <p style={{ color: T.rose, fontSize: 11, margin: "4px 0 0" }}>{errors.domains}</p>}
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 8 }}>
            {domains.split(",").map(d => d.trim()).filter(Boolean).map(d => (
              <Badge key={d} color={T.accent} style={{ fontSize: 10 }}><Globe size={10} /> {d}</Badge>
            ))}
          </div>
        </div>
        {/* Save */}
        <Btn variant="primary" onClick={onSave} style={{ justifyContent: "center", marginTop: 4 }}>
          {saved ? <><Check size={14} /> Saved</> : <><Save size={14} /> Save Policy</>}
        </Btn>
      </div>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// SYSTEM THROUGHPUT — Mini sparkline-style via Recharts
// ═══════════════════════════════════════════════════════════════════════════
function ThroughputMini() {
  const data = useMemo(() => Array.from({ length: 24 }, (_, i) => ({
    name: `${i}:00`, approved: Math.floor(Math.random() * 40 + 10), denied: Math.floor(Math.random() * 15),
  })), []);
  const total = data.reduce((s, d) => s + d.approved + d.denied, 0);
  return (
    <Card>
      <SectionHeader icon={<BarChart3 size={18} />} title="24h Throughput" subtitle={`${total} total requests`} />
      <div style={{ display: "flex", gap: 2, alignItems: "flex-end", height: 80 }}>
        {data.map((d, i) => {
          const max = 60;
          const aH = (d.approved / max) * 60;
          const dH = (d.denied / max) * 60;
          return (
            <div key={i} style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", gap: 1 }} title={`${d.name}: ${d.approved} approved, ${d.denied} denied`}>
              <div style={{ width: "100%", height: dH, background: T.rose + "60", borderRadius: "2px 2px 0 0" }} />
              <div style={{ width: "100%", height: aH, background: T.emerald + "60", borderRadius: "0 0 2px 2px" }} />
            </div>
          );
        })}
      </div>
      <div style={{ display: "flex", gap: 16, marginTop: 10, fontSize: 11, color: T.textDim }}>
        <span><span style={{ display: "inline-block", width: 8, height: 8, borderRadius: 2, background: T.emerald + "60", marginRight: 4, verticalAlign: "middle" }} />Approved</span>
        <span><span style={{ display: "inline-block", width: 8, height: 8, borderRadius: 2, background: T.rose + "60", marginRight: 4, verticalAlign: "middle" }} />Denied</span>
      </div>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN DASHBOARD
// ═══════════════════════════════════════════════════════════════════════════
export default function APEXCommand() {
  const mobile = useIsMobile();
  const [agents, setAgents] = useState(MOCK_AGENTS);
  const [logs, setLogs] = useState(INITIAL_LOGS);
  const [selectedLog, setSelectedLog] = useState(null);
  const [now, setNow] = useState(new Date());

  // Simulate live feed
  useEffect(() => {
    const interval = setInterval(() => {
      const newLog = generateAuditEntry(Date.now());
      newLog.timestamp = new Date().toISOString();
      setLogs(prev => [newLog, ...prev].slice(0, 200));
      setNow(new Date());
    }, 3000);
    return () => clearInterval(interval);
  }, []);

  const toggleAgent = (id) => {
    setAgents(prev => prev.map(a => a.id === id ? { ...a, status: a.status === "active" ? "suspended" : "active" } : a));
  };

  const totalSpend = agents.reduce((s, a) => s + a.dailySpend, 0);
  const activeCount = agents.filter(a => a.status === "active").length;
  const violations = logs.filter(l => l.status === "DENIED").length;

  return (
    <div style={{
      minHeight: "100vh", background: T.bg, color: T.text,
      fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
    }}>
      {/* Global inline animation */}
      <style>{`
        @keyframes slideIn { from { transform: translateX(100%); } to { transform: translateX(0); } }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
        * { scrollbar-width: thin; scrollbar-color: ${T.border} transparent; box-sizing: border-box; }
        *::-webkit-scrollbar { width: 6px; }
        *::-webkit-scrollbar-track { background: transparent; }
        *::-webkit-scrollbar-thumb { background: ${T.border}; border-radius: 3px; }
        html { -webkit-text-size-adjust: 100%; }
        input, textarea, button { font-size: 16px; }
        @media (min-width: 768px) { input, textarea, button { font-size: inherit; } }
      `}</style>

      {/* Header */}
      <header style={{
        borderBottom: `1px solid ${T.border}`, padding: mobile ? "10px 14px" : "14px 24px",
        display: "flex", alignItems: "center", justifyContent: "space-between",
        background: T.surface + "cc", backdropFilter: "blur(12px)",
        position: "sticky", top: 0, zIndex: 100,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: mobile ? 6 : 10 }}>
          <Shield size={mobile ? 18 : 22} color={T.accent} />
          <span style={{ fontSize: mobile ? 15 : 18, fontWeight: 800, letterSpacing: "-0.02em" }}>
            APEX<span style={{ color: T.accent }}>-Command</span>
          </span>
          {!mobile && (
            <Badge color={T.emerald} style={{ marginLeft: 8 }}>
              <span style={{ animation: "pulse 2s infinite" }}>●</span> LIVE
            </Badge>
          )}
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: mobile ? 6 : 12, fontSize: 12, color: T.textDim }}>
          {mobile && <span style={{ color: T.emerald, animation: "pulse 2s infinite", fontSize: 10 }}>●</span>}
          <Clock size={14} />
          {now.toLocaleTimeString()}
        </div>
      </header>

      {/* Content */}
      <main style={{ maxWidth: 1280, margin: "0 auto", padding: mobile ? 12 : 24, display: "grid", gap: mobile ? 14 : 20 }}>

        {/* Row 1: Stat Cards */}
        <div style={{ display: "grid", gridTemplateColumns: mobile ? "1fr" : "repeat(3, 1fr)", gap: mobile ? 10 : 16 }}>
          <StatCard icon={<DollarSign size={22} />} label="Total Spend (24h)" value={`$${totalSpend.toFixed(2)}`} sub="across all agents" color={T.accent} />
          <StatCard icon={<Users size={22} />} label="Active Agents" value={activeCount} sub={`${agents.length} registered`} color={T.emerald} />
          <StatCard icon={<AlertTriangle size={22} />} label="Policy Violations" value={violations} sub="denied in feed window" color={T.rose} />
        </div>

        {/* Row 2: Audit Feed + Sidebar */}
        {mobile ? (
          <>
            <AuditFeed logs={logs} onSelect={setSelectedLog} />
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
              <ThroughputMini />
              <Card>
                <SectionHeader icon={<Activity size={18} />} title="System Risk" subtitle="weighted avg" />
                <RiskMeter score={Math.round(agents.filter(a => a.status === "active").reduce((s, a) => s + a.riskAvg, 0) / Math.max(1, activeCount))} size={140} />
              </Card>
            </div>
          </>
        ) : (
          <div style={{ display: "grid", gridTemplateColumns: "1fr 340px", gap: 20 }}>
            <AuditFeed logs={logs} onSelect={setSelectedLog} />
            <div style={{ display: "grid", gap: 20 }}>
              <ThroughputMini />
              <Card>
                <SectionHeader icon={<Activity size={18} />} title="System Risk" subtitle="weighted average across agents" />
                <RiskMeter score={Math.round(agents.filter(a => a.status === "active").reduce((s, a) => s + a.riskAvg, 0) / Math.max(1, activeCount))} size={180} />
              </Card>
            </div>
          </div>
        )}

        {/* Row 3: Agent Registry + Policy Studio */}
        <div style={{ display: "grid", gridTemplateColumns: mobile ? "1fr" : "1fr 380px", gap: mobile ? 14 : 20 }}>
          <AgentRegistry agents={agents} onToggle={toggleAgent} />
          <PolicyStudio />
        </div>
      </main>

      {/* Slide-over */}
      <LogDetail log={selectedLog} onClose={() => setSelectedLog(null)} />
    </div>
  );
}
