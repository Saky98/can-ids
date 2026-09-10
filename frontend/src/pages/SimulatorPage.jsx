/**
 * SimulatorPage — replays recorded CAN traffic as if it came from a live bus.
 *
 * Connects to the unified backend stream WebSocket:
 *     ws://<host>/ws/stream?source=sim&label=<label>&speed=<speed>&ids=<method>
 * The same protocol is shared by the future Live mode (ESP32 / socketcan).
 *
 * IDS + injection (thesis demo):
 *   - an inline detector (heuristic / isolation forest / one-class svm / off)
 *     scores every replayed frame per-frame; blocked frames are marked.
 *   - 4 inject buttons push a genuine attack (DoS = 8-frame burst, others =
 *     single spoof) onto the bus at the current position; injected frames are
 *     rendered red and, if caught, listed in the quarantine panel.
 */
import { useEffect, useMemo, useRef, useState } from 'react';

const LABELS = ['normal', 'DoS', 'Fuzzy', 'gear', 'RPM'];
const IDS_METHODS = [
  { key: 'off', label: 'Off' },
  { key: 'heuristic', label: 'Heuristic' },
  { key: 'isolation_forest', label: 'Isolation Forest' },
  { key: 'one_class_svm', label: 'One-Class SVM' },
];
const INJECT_ATTACKS = ['DoS', 'Fuzzy', 'gear', 'RPM'];
const SPEED_MIN = 0.1;
const SPEED_MAX = 2000;
const RING = 200;      // keep at most this many recent messages in the table
const QUARANTINE_MAX = 200;

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
  const [ids, setIds] = useState('heuristic');
  const [running, setRunning] = useState(false);
  const [connected, setConnected] = useState(false);
  const [idsReady, setIdsReady] = useState(false);
  const [error, setError] = useState('');
  const [paused, setPausedLocal] = useState(false); // server-side state mirror

  // live counters / data
  const [runNo, setRunNo] = useState(null);
  const [tps, setTps] = useState(0);
  const [done, setDone] = useState(0);
  const [msgs, setMsgs] = useState([]);           // ring of recent messages (newest first)
  const [groundSeq, setGroundSeq] = useState(0);  // #sent when the current ring window began
  const [quarantine, setQuarantine] = useState([]); // blocked frames (newest first)
  const [blockedCount, setBlockedCount] = useState(0);
  const [injectedCount, setInjectedCount] = useState(0);

  const wsRef = useRef(null);
  const ringRef = useRef([]);
  const streamSeq = useRef(0);  // absolute count received this run
  const quarantineRef = useRef([]);
  const blockedCountRef = useRef(0);
  const injectedCountRef = useRef(0);

  const pushQuarantine = (items) => {
    const blocked = items.filter((it) => it.blocked);
    if (blocked.length === 0) return;
    quarantineRef.current = [...blocked.map((it) => ({ ...it })), ...quarantineRef.current]
      .slice(0, QUARANTINE_MAX);
    blockedCountRef.current += blocked.length;
    setQuarantine(quarantineRef.current);
    setBlockedCount(blockedCountRef.current);
  };

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
    setIdsReady(false);
    ringRef.current = [];
    setMsgs([]);
    streamSeq.current = 0;
    quarantineRef.current = [];
    blockedCountRef.current = 0;
    injectedCountRef.current = 0;
    setQuarantine([]);
    setBlockedCount(0);
    setInjectedCount(0);

    const ws = new WebSocket(
      `${wsUrl()}?source=sim&label=${encodeURIComponent(label)}&speed=${speed}` +
      `&ids=${encodeURIComponent(ids)}`,
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
        setIdsReady(!!msg.ids_ready);
        streamSeq.current = 0;
        ringRef.current = [];
        setMsgs([]);
      } else if (msg.type === 'messages') {
        const items = msg.items || [];
        if (msg.done != null) {
          setTps(msg.tps || 0);
          setDone(msg.done || 0);
        }
        // injected batch vs replay batch
        if (msg.injected) {
          injectedCountRef.current += items.length;
          setInjectedCount(injectedCountRef.current);
          items.forEach((it) => { it.injected = true; });
        } else {
          items.forEach((it) => { it.injected = false; });
        }
        // ring buffer: newest first; each entry keeps its own solid sequence
        const withSeq = items.map((it) => {
          const n = ++streamSeq.current;
          return { ...it, seq: n };
        });
        ringRef.current = [...withSeq, ...ringRef.current].slice(0, RING);
        const oldest = ringRef.current[ringRef.current.length - 1];
        setGroundSeq(oldest ? oldest.seq : streamSeq.current);
        setMsgs(ringRef.current);
        // quarantine: collect blocked frames
        pushQuarantine(withSeq);
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
  }, [running, label, speed, ids]);

  const shownTps = useMemo(() => tps, [tps]);

  const sendCmd = (cmd) => {
    const ws = wsRef.current;
    if (ws && ws.readyState === WebSocket.OPEN) {
      try { ws.send(JSON.stringify({ cmd })); } catch { /* ignore */ }
      if (cmd === 'pause') setPausedLocal(true);
      else if (cmd === 'resume') setPausedLocal(false);
    }
  };

  const inject = (attack) => {
    const ws = wsRef.current;
    if (ws && ws.readyState === WebSocket.OPEN) {
      try { ws.send(JSON.stringify({ cmd: 'inject', attack })); } catch { /* ignore */ }
    }
  };

  return (
    <div className="page">
      <h1 className="page-title">Simulator</h1>
      <p className="page-subtitle">
        Replays a recorded CAN dataset as if it were live — with an inline IDS that
        flags anomalies and lets you inject attacks onto the bus.
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

          {/* IDS selector */}
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
            <span className="mono" style={{ color: 'var(--text-2)', fontSize: 10.5 }}>IDS</span>
            {IDS_METHODS.map((m) => (
              <button
                key={m.key}
                onClick={() => setIds(m.key)}
                style={{
                  padding: '5px 11px', borderRadius: 6, cursor: 'pointer',
                  fontFamily: 'inherit', fontWeight: 600, fontSize: 12,
                  background: ids === m.key
                    ? (m.key === 'off' ? 'var(--bg-2)' : 'var(--purple)')
                    : 'var(--bg-2)',
                  color: ids === m.key && m.key !== 'off' ? '#0d1117' : 'var(--text-1)',
                  border: '1px solid var(--border)',
                }}
              >
                {m.label}
              </button>
            ))}
            {running && ids !== 'off' && (
              <StatusChip active={idsReady} text={idsReady ? 'ids ready' : 'loading ids…'} />
            )}
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
              {`${speed.toFixed(1)}×`}
            </span>
          </div>
        </div>

        {/* ---------------- Attack injection row ---------------- */}
        <div style={{
          display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center',
          marginTop: 14, paddingTop: 14, borderTop: '1px solid var(--border)',
        }}>
          <span className="mono" style={{ color: 'var(--text-2)', fontSize: 10.5 }}>INJECT</span>
          {INJECT_ATTACKS.map((a) => (
            <button
              key={a}
              disabled={!running || !connected || ids === 'off'}
              onClick={() => inject(a)}
              style={{
                padding: '6px 12px', borderRadius: 6, cursor: 'pointer',
                fontFamily: 'inherit', fontWeight: 700, fontSize: 12.5,
                background: 'rgba(248,81,73,.14)',
                color: 'var(--red)',
                border: '1px solid rgba(248,81,73,.5)',
                opacity: (!running || !connected || ids === 'off') ? 0.45 : 1,
              }}
            >
              {a === 'DoS' ? '⚡ ' : '• '}{a}
            </button>
          ))}
          <span style={{ color: 'var(--text-2)', fontSize: 12, marginLeft: 4 }}>
            {ids === 'off' ? 'enable an IDS to inject & detect.' : 'injects at the live bus position; blocked frames → quarantine.'}
          </span>
        </div>

        {error && <div style={{ marginTop: 12, color: 'var(--red)', fontSize: 13 }}>⚠ {error}</div>}
      </div>

      {/* ---------------- Stat cards ---------------- */}
      <div style={{
        display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))',
        gap: 14, marginBottom: 20,
      }}>
        <StatCard title="Run #" value={running ? runNo ?? '…' : '—'} accent />
        <StatCard title="Throughput" value={running ? `${fmtInt(shownTps)} msg/s` : '—'} accent />
        <StatCard title="Replayed this run" value={running ? fmtInt(done) : '—'} accent />
        <StatCard title="Injected" value={fmtInt(injectedCount)} accent={false} />
        <StatCard title="Blocked (quarantine)" value={fmtInt(blockedCount)} accent={false} />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 16, alignItems: 'start' }}>
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
                  <th style={{ width: 64 }}>Seq</th>
                  <th style={{ width: 140 }}>Timestamp</th>
                  <th style={{ width: 74 }}>Hex</th>
                  <th style={{ width: 40 }}>DLC</th>
                  <th>Payload (bytes · hex)</th>
                  <th style={{ width: 54 }}>Verdict</th>
                </tr>
              </thead>
              <tbody>
                {msgs.map((m) => {
                  const injected = !!m.injected;
                  const blocked = !!m.blocked;
                  const rowStyle = injected
                    ? { background: 'rgba(248,81,73,.08)' }
                    : (blocked ? { background: 'rgba(210,153,34,.08)' } : undefined);
                  return (
                    <tr key={m.seq} style={rowStyle}>
                      <td className="mono" style={{ color: injected ? 'var(--red)' : 'var(--text-2)' }}>
                        {injected ? '⚠' : ''}{'…'}{fmtInt(m.seq - groundSeq)}
                      </td>
                      <td className="mono" style={{ color: injected ? 'var(--red)' : 'var(--text-1)' }}>
                        {m.ts.toFixed(6)}
                      </td>
                      <td className="mono" style={{ color: injected ? 'var(--red)' : 'var(--accent)', fontWeight: 700 }}>
                        {m.hex}
                      </td>
                      <td className="mono">{m.dlc}</td>
                      <td>
                        <span className="heat" style={{ color: injected ? 'var(--red)' : undefined }}>
                          {payloadAsBytes(m.payload).map((b, idx) => (
                            <span key={idx}>{b}</span>
                          ))}
                        </span>
                      </td>
                      <td className="mono" style={{
                        fontSize: 10.5, fontWeight: 700,
                        color: injected
                          ? (blocked ? 'var(--orange)' : 'var(--red)')
                          : (blocked ? 'var(--orange)' : 'var(--text-2)'),
                      }}>
                        {injected ? (blocked ? 'BLOCKED' : 'injected') : (blocked ? 'blocked' : '—')}
                      </td>
                    </tr>
                  );
                })}
                {msgs.length === 0 && (
                  <tr>
                    <td colSpan="6" style={{ textAlign: 'center', color: 'var(--text-2)', padding: '26px 10px' }}>
                      {running ? 'Waiting for the first replay batch…' : 'Press ▶ Start to replay a recording.'}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* ---------------- Quarantine panel ---------------- */}
        <div className="card">
          <h3 style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span>🛡 Quarantine</span>
            <span className="badge" style={{
              background: 'rgba(210,153,34,.14)', color: 'var(--orange)', fontSize: 11,
            }}>
              {quarantine.length ? `${quarantine.length} frame${quarantine.length > 1 ? 's' : ''}` : 'empty'}
            </span>
          </h3>
          <p style={{ fontSize: 12, color: 'var(--text-2)', marginTop: 4 }}>
            Frames flagged by the IDS are logged here as "blocked". Injected attacks are
            shown with a <span style={{ color: 'var(--red)' }}>⚠</span> marker.
          </p>
          <div style={{ maxHeight: 440, overflowY: 'auto', marginTop: 10 }}>
            <table>
              <thead style={{ position: 'sticky', top: 0, background: 'var(--bg-1)', zIndex: 1 }}>
                <tr>
                  <th style={{ width: 64 }}>Seq</th>
                  <th style={{ width: 74 }}>Hex</th>
                  <th>Reason</th>
                </tr>
              </thead>
              <tbody>
                {quarantine.map((q) => (
                  <tr key={q.seq} style={{ background: 'rgba(210,153,34,.06)' }}>
                    <td className="mono" style={{ color: 'var(--red)' }}>⚠{'…'}{fmtInt(q.seq - groundSeq)}</td>
                    <td className="mono" style={{ color: 'var(--accent)', fontWeight: 700 }}>{q.hex}</td>
                    <td className="mono" style={{ fontSize: 11.5, color: 'var(--orange)' }}>{q.reason || 'anomaly'}</td>
                  </tr>
                ))}
                {quarantine.length === 0 && (
                  <tr>
                    <td colSpan="3" style={{ textAlign: 'center', color: 'var(--text-2)', padding: '26px 10px' }}>
                      No blocked frames yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
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
