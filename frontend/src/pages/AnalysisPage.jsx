import { useEffect, useMemo, useState } from 'react';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
  PieChart, Pie, Cell, Legend
} from 'recharts';

const LABELS = ['normal', 'DoS', 'Fuzzy', 'gear', 'RPM'];

// palette for pie
const PIE_COLORS = ['#3fb950', '#f85149', '#d29922', '#bc8cff', '#58a6ff'];

export default function AnalysisPage() {
  const [label, setLabel] = useState('normal');
  const [overview, setOverview] = useState([]);
  const [topIds, setTopIds] = useState([]);
  const [deltat, setDeltat] = useState([]);
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);

  // ---- Load overview once ----
  useEffect(() => {
    (async () => {
      try {
        const r = await fetch('/api/overview');
        const j = await r.json();
        setOverview(Array.isArray(j) ? j : []);
      } catch (e) { console.error(e); }
    })();
  }, []);

  // ---- Load label-dependent data ----
  useEffect(() => {
    if (!label) return;
    setLoading(true);
    (async () => {
      try {
        const [tid, dt] = await Promise.all([
          fetch(`/api/top-ids?label=${label}&top=15`).then(r => r.json()),
          fetch(`/api/deltat?label=${label}`).then(r => r.json()),
        ]);
        setTopIds(Array.isArray(tid) ? tid : []);
        setDeltat(Array.isArray(dt) ? dt : []);
      } catch (e) { console.error(e); }
      finally { setLoading(false); }
    })();
  }, [label]);

  // ---- Load sample rows ----
  const loadRows = async (labelSel, cid = '') => {
    try {
      const r = await fetch(`/api/rows?label=${labelSel}&limit=200&can_id=${cid}`);
      const j = await r.json();
      setRows(j.rows || []);
    } catch (e) { console.error(e); }
  };
  useEffect(() => { loadRows(label); }, [label]);

  // pie: distribution across labels (from overview)
  const pieData = useMemo(() => overview.map(o => ({
    name: o.label, value: o.rows,
  })), [overview]);

  // formatted stats for cards
  const totalRows = overview.reduce((s, o) => s + (o.rows || 0), 0);
  const current = overview.find(o => o.label === label);

  return (
    <div className="page">
      <h1 className="page-title">Analysis</h1>
      <p className="page-subtitle">
        Interactive exploration of the recorded CAN dataset — which IDs exist, their
        payload, how often they appear, and where they come from.
      </p>

      {/* Label selector */}
      <div className="card" style={{ marginBottom: 18 }}>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
          <span style={{ color: 'var(--text-1)', fontSize: 13, marginRight: 6 }}>Traffic type:</span>
          {LABELS.map(l => (
            <button
              key={l}
              onClick={() => setLabel(l)}
              style={{
                padding: '6px 14px', borderRadius: 6, cursor: 'pointer', fontFamily: 'inherit',
                fontWeight: 600, fontSize: 13,
                background: label === l ? 'var(--accent)' : 'var(--bg-2)',
                color: label === l ? '#0d1117' : 'var(--text-1)',
                border: '1px solid var(--border)',
              }}
            >
              {l}
            </button>
          ))}
        </div>
      </div>

      {/* Stat cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px,1fr))', gap: 14, marginBottom: 20 }}>
        <StatCard title="Total messages (all)" value={totalRows.toLocaleString()} />
        <StatCard title={`Messages (${label})`} value={(current ? current.rows : 0).toLocaleString()} />
        <StatCard title={`Unique IDs (${label})`} value={current ? current.unique_ids : 0} />
        <StatCard title="Periodicity range" value={loading ? '…' : `${deltat.length ? minDt(deltat) : 0}–${maxDt(deltat)} ms`} />
      </div>

      {(totalRows === 0 && !loading) && (
        <div className="card" style={{ textAlign: 'center', color: 'var(--text-2)', padding: 40 }}>
          Backend returned no data. Make sure the API is running on port 8000.
        </div>
      )}

      {/* Charts */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 20 }}>
        {/* Top IDs bar */}
        <div className="card">
          <h3>Top CAN IDs — {label}</h3>
          <div style={{ height: 260 }}>
            <ResponsiveContainer>
              <BarChart data={topIds} layout="vertical" margin={{ left: 8, right: 10, top: 5, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#30363d" />
                <XAxis type="number" stroke="#6e7681" fontSize={10} />
                <YAxis type="category" dataKey="hex" width={60} tick={{ fontFamily: 'monospace', fontSize: 10, fill: '#9ba7b4' }} />
                <Tooltip
                  contentStyle={{ background: '#161b22', border: '1px solid #30363d', fontSize: 12 }}
                  cursor={{ fill: 'rgba(88,166,255,0.06)' }}
                />
                <Bar dataKey="count" fill="#58a6ff" radius={[0,3,3,0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Pie */}
        <div className="card">
          <h3>Message distribution</h3>
          <div style={{ height: 260 }}>
            <ResponsiveContainer>
              <PieChart>
                <Pie data={pieData} dataKey="value" nameKey="name" outerRadius={90} label>
                  {pieData.map((_, i) => <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />)}
                </Pie>
                <Tooltip contentStyle={{ background: '#161b22', border: '1px solid #30363d', fontSize: 12 }} />
                <Legend wrapperStyle={{ fontSize: 12 }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Table: CAN IDs + periodicity */}
      <div className="card" style={{ marginBottom: 20 }}>
        <h3>CAN IDs — {label} (by frequency)</h3>
        <table>
          <thead>
            <tr>
              <th>Hex</th><th>Decimal</th><th>Count</th><th>Share %</th>
              <th>Period mean (ms)</th><th>Period median (ms)</th><th>Range</th>
            </tr>
          </thead>
          <tbody>
            {topIds.map(row => {
              const dt = deltat.find(d => d.hex === row.hex);
              return (
                <tr key={row.hex}>
                  <td className="mono" style={{ color: 'var(--accent)', fontWeight: 700 }}>{row.hex}</td>
                  <td className="mono">{row.can_id}</td>
                  <td className="mono">{row.count.toLocaleString()}</td>
                  <td className="mono">{row.pct.toFixed(2)}%</td>
                  <td className="mono">{dt ? dt.dt_mean_ms : '—'}</td>
                  <td className="mono">{dt ? dt.dt_median_ms : '—'}</td>
                  <td className="mono" style={{ color: 'var(--text-2)' }}>{dt ? `${dt.dt_min_ms}–${dt.dt_max_ms}` : '—'}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Sample message table */}
      <div className="card">
        <h3>Sample messages — {label}</h3>
        <table>
          <thead>
            <tr>
              <th>Timestamp</th><th>Hex</th><th>DLC</th><th>Payload (bytes, hex)</th>
            </tr>
          </thead>
          <tbody>
            {rows.slice(0, 12).map((r, i) => (
              <tr key={i}>
                <td className="mono" style={{ color: 'var(--text-1)' }}>{r.timestamp.toFixed(6)}</td>
                <td className="mono" style={{ color: 'var(--accent)', fontWeight: 700 }}>{r.hex}</td>
                <td className="mono">{r.dlc}</td>
                <td>
                  <span className="heat">
                    {r.payload.map((b, j) => <span key={j}>{b.toString(16).padStart(2, '0')}</span>)}
                  </span>
                </td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr><td colSpan="4" style={{ color: 'var(--text-2)', textAlign: 'center', padding: 20 }}>No messages loaded.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function StatCard({ title, value }) {
  return (
    <div className="card" style={{ textAlign: 'center', padding: '16px 10px' }}>
      <div style={{ fontSize: 22, fontWeight: 800, color: 'var(--accent)' }}>{value}</div>
      <div style={{ fontSize: 12, color: 'var(--text-2)', marginTop: 4 }}>{title}</div>
    </div>
  );
}

function minDt(a) { return a.reduce((m, x) => Math.min(m, x.dt_min_ms), Infinity); }
function maxDt(a) { return a.reduce((m, x) => Math.max(m, x.dt_max_ms), -Infinity); }
