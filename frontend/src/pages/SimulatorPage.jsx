/**
 * SimulatorPage — replays recorded CAN traffic as if it came from a live bus.
 *
 * Connects to the unified backend stream WebSocket:
 *     ws://<host>/ws/stream?source=sim&label=<label>&speed=<speed>
 * The same protocol is shared by the future Live mode (ESP32 / socketcan), so
 * this page keeps working when the source switches.
 */
import { useEffect, useMemo, useRef, useState } from 'react';

const LABELS = ['normal', 'DoS', 'Fuzzy', 'gear', 'RPM'];
const SPEED_MIN = 0.1;
const SPEED_MAX = 2000;
const RING = 200; // keep at most this many recent messages in the table

const wsUrl = () => {
  const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
  return `${proto}://${window.location.host}/ws/stream`;
};

const fmtInt = (n) => (typeof n === 'number' ? Math.round(n).toLocaleString('en-US') : '—');
const payloadAsBytes = (hex) => (hex && hex.match(/../g)) || [];

export default function SimulatorPage() {
  // user choices + connection state
  const [label, setLabel] = useState('normal');
  const [speed, setSpeed] = useState(25);
  const [running, setRunning] = useState(false);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState('');
  const [paused, setPausedLocal] = useState(false); // server-side state mirror

  // live counters / data
  const [runNo, setRunNo] = useState(null);
  const [tps, setTps] = useState(0);
  const [done, setDone] = useState(0);
  const [msgs, setMsgs] = useState([]);           // ring of recent messages (newest first)
  const [groundSeq, setGroundSeq] = useState(0);  // #sent when the current ring window began

  const wsRef = useRef(null);
  const ringRef = useRef([]);
  const streamSeq = useRef(0);  // absolute count received this run

  // ---- (re)open stream whenever controls change or when started/stopped ----
  useEffect(() => {
    if (!running) {
      setConnected(false);
      if (wsRef.current) { wsRef.current.close(); wsRef.current = null; }
      return;
    }
    setError('');
    setPausedLocal(false);
    setRunNo(null);
    setDone(0);
    ringRef.current = [];
    setMsgs([]);
    streamSeq.current = 0;

    const ws = new WebSocket(
      `${wsUrl()}?source=sim&label=${encodeURIComponent(label)}&speed=${speed}`,
    );
    wsRef.current = ws;

    ws.onopen = () => setConnected(true);
    ws.onerror = () => { setConnected(false); setError('WebSocket error.'); };

    ws.onmessage = (ev) => {
      let msg;
      try { msg = JSON.parse(ev.data); } catch { return; }

      if (msg.type === 'hello') {
        setConnected(true);
        setRunNo(msg.run);
        setError('');
        setDone(0);
        streamSeq.current = 0;
        ringRef.current = [];
        setMsgs([]);
      } else if (msg.type === 'messages') {
        const items = msg.items || [];
        setTps(msg.tps || 0);
        setDone(msg.done || 0);
        // ring buffer: newest first; each entry keeps its own solid sequence
        const withSeq = items.map((it) => {
          const n = ++streamSeq.current;
          return { ...it, seq: n };
        });
        ringRef.current = [...withSeq, ...ringRef.current].slice(0, RING);
        const oldest = ringRef.current[ringRef.current.length - 1];
        setGroundSeq(oldest ? oldest.seq : streamSeq.current);
        setMsgs(ringRef.current);
      } else if (msg.type === 'end') {
        setDone(msg.items_done || 0);
      } else if (msg.type === 'error') {
        setConnected(false);
        setError(msg.error || 'Stream error');
      }
    };

    ws.onclose = () => {
      setConnected(false);
      wsRef.current = null;
    };

    return () => {
      try { ws.close(); } catch { /* already closed */ }
      wsRef.current = null;
    };
  }, [running, label, speed]);

  // TPS shown to the user (raw server estimate)
  const shownTps = useMemo(() => tps, [tps]);

  const sendCmd = (cmd) => {
    const ws = wsRef.current;
    if (ws && ws.readyState === WebSocket.OPEN) {
      try { ws.send(JSON.stringify({ cmd })); } catch { /* ignore */ }
      if (cmd === 'pause') setPausedLocal(true);
      else if (cmd === 'resume') setPausedLocal(false);
    }
  };

  return (
    <div className="page">
      <h1 className="page-title">Simulator</h1>
      <p className="page-subtitle">
        Replays a recorded CAN dataset as if it were live — ideal for testing the
        stream pipeline and demoing without a car.
      </p>

      {/* ---------------- Control panel ---------------- */}
      <div className="card" style={{ marginBottom: 18 }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 14, alignItems: 'center' }}>
          {/* traffic source */}
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
            <span className="mono" style={{ color: 'var(--text-2)', fontSize: 10.5 }}>SOURCE</span>
            {LABELS.map((l) => (
              <button
                key={l}
                onClick={() => setLabel(l)}
                style={{
                  padding: '5px 11px', borderRadius: 6, cursor: 'pointer',
                  fontFamily: 'inherit', fontWeight: 600, fontSize: 12.5,
                  background: running && label === l ? 'var(--accent)' : 'var(--bg-2)',
                  color: running && label === l ? '#0d1117' : 'var(--text-1)',
                  border: '1px solid var(--border)',
                }}
              >
                {l}
              </button>
            ))}
          </div>

          <div style={{ width: 1, height: 26, background: 'var(--border)' }} />

          {/* transport / state toggle + controls */}
          <button
            onClick={() => { setRunning(v => !v); }}
            style={{
              padding: '8px 16px', borderRadius: 7, cursor: 'pointer',
              fontFamily: 'inherit', fontWeight: 700, fontSize: 13, border: 'none',
              background: running ? 'var(--red)' : 'var(--green)', color: '#0d1117',
            }}
          >
            {running ? '■ Stop' : '▶ Start'}
          </button>

          <StatusChip active={running} text={running ? (connected ? 'connected' : 'connecting…') : 'stopped'} />

          <div style={{ width: 1, height: 26, background: 'var(--border)' }} />

          <button disabled={!running} onClick={() => sendCmd('pause')} style={ctlBtn(paused)}>
            {paused ? '⏸ Paused' : 'Pause'}
          </button>
          <button disabled={!running} onClick={() => sendCmd('resume')} style={ctlBtn(false)}>
            Resume
          </button>
          <button disabled={!running} onClick={() => sendCmd('restart')} style={ctlBtn(false)}>
            ⟲ Restart
          </button>

          <div style={{ width: 1, height: 26, background: 'var(--border)' }} />

          {/* speed */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ color: 'var(--text-2)', fontSize: 12 }}>Speed</span>
            <input
              type="range" min={SPEED_MIN} max={SPEED_MAX} step={0.1}
              value={speed} disabled={!running}
              onChange={(e) => setSpeed(parseFloat(e.target.value))}
              style={{ width: 150 }}
            />
            <span className="mono" style={{ color: 'var(--accent)', fontWeight: 700, fontSize: 12.5 }}>
              {running ? `${speed.toFixed(1)}×` : `${speed.toFixed(1)}×`}
            </span>
          </div>
        </div>

        {error && <div style={{ marginTop: 12, color: 'var(--red)', fontSize: 13 }}>⚠ {error}</div>}
      </div>

      {/* ---------------- Stat cards ---------------- */}
      <div style={{
        display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(175px, 1fr))',
        gap: 14, marginBottom: 20,
      }}>
        <StatCard title="Run #" value={running ? runNo ?? '…' : '—'} accent />
        <StatCard title="Throughput" value={running ? `${fmtInt(shownTps)} msg/s` : '—'} accent />
        <StatCard title="Replayed this run" value={running ? fmtInt(done) : '—'} accent />
        <StatCard title="Recent msgs shown" value={msgs.length} accent={false} />
      </div>

      {/* ---------------- Live message table ---------------- */}
      <div className="card">
        <h3 style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span>Recent messages · {label}</span>
          <span className="badge" style={{
            background: running ? (connected ? 'rgba(63,185,80,.14)' : 'rgba(210,153,34,.14)')
                                : 'var(--bg-2)',
            color: running ? (connected ? 'var(--green)' : 'var(--orange)') : 'var(--text-2)',
            fontSize: 11,
          }}>
            {running ? (connected ? `streaming${paused ? ' (paused)' : ''}` : 'connecting…') : 'stopped'}
          </span>
        </h3>
        <div style={{ maxHeight: 440, overflowY: 'auto', marginTop: 10 }}>
          <table>
            <thead style={{ position: 'sticky', top: 0, background: 'var(--bg-1)', zIndex: 1 }}>
              <tr>
                <th style={{ width: 80 }}>Seq</th>
                <th style={{ width: 150 }}>Timestamp</th>
                <th style={{ width: 80 }}>Hex</th>
                <th style={{ width: 52 }}>DLC</th>
                <th>Payload (bytes · hex)</th>
              </tr>
            </thead>
            <tbody>
              {msgs.map((m) => (
                <tr key={m.seq}>
                  <td className="mono" style={{ color: 'var(--text-2)' }}>…{fmtInt(m.seq - groundSeq)}</td>
                  <td className="mono" style={{ color: 'var(--text-1)' }}>{m.ts.toFixed(6)}</td>
                  <td className="mono" style={{ color: 'var(--accent)', fontWeight: 700 }}>{m.hex}</td>
                  <td className="mono">{m.dlc}</td>
                  <td>
                    <span className="heat">
                      {payloadAsBytes(m.payload).map((b, idx) => (
                        <span key={idx}>{b}</span>
                      ))}
                    </span>
                  </td>
                </tr>
              ))}
              {msgs.length === 0 && (
                <tr>
                  <td colSpan="5" style={{ textAlign: 'center', color: 'var(--text-2)', padding: '26px 10px' }}>
                    {running ? 'Waiting for the first replay batch…' : 'Press ▶ Start to replay a recording.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="legend">
        The source is switched server-side to keep a single stream interface — the
        future Live mode (ESP32 / socketcan) reuses this same page and protocol.
      </div>
    </div>
  );
}

/* ------------- tiny presentational helpers ------------- */

function StatusChip({ active, text }) {
  return (
    <span
      className="mono"
      style={{
        padding: '3px 10px', borderRadius: 999, fontSize: 11, fontWeight: 600,
        background: active ? 'var(--accent-soft)' : 'var(--bg-2)',
        color: active ? 'var(--accent)' : 'var(--text-2)',
        border: '1px solid var(--border)',
      }}
    >
      {text}
    </span>
  );
}

function ctlBtn(highlight) {
  return {
    padding: '8px 13px', borderRadius: 7, cursor: 'pointer', fontFamily: 'inherit',
    fontWeight: 600, fontSize: 13,
    color: highlight ? 'var(--green)' : 'var(--text-1)',
    background: highlight ? 'rgba(63,185,80,.12)' : 'var(--bg-2)',
    border: `1px solid ${highlight ? 'rgba(63,185,80,.5)' : 'var(--border)'}`,
    opacity: 1,
  };
}

function StatCard({ title, value, accent }) {
  return (
    <div className="card" style={{ textAlign: 'center', padding: '16px 10px' }}>
      <div
        className="mono"
        style={{ fontSize: 22, fontWeight: 800, color: accent ? 'var(--accent)' : 'var(--text-0)' }}
      >
        {value}
      </div>
      <div style={{ fontSize: 12, color: 'var(--text-2)', marginTop: 4 }}>{title}</div>
    </div>
  );
}
