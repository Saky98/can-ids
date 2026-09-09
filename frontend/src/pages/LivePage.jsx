/**
 * LivePage — live CAN bus dashboard with built-in recording & export.
 *
 * Shows the traffic coming from the vehicle bus in real time (top), and below
 * it a Recording & Export section: Start/Stop the capture (written to both a
 * normalized CSV and a raw candump log), plus a list of previously saved
 * sessions you can download or delete.
 *
 * Live mode data source
 * ---------------------
 * Until the car is physically attached, the backend streams the recorded
 * dataset over the "live" channel (`source=live`) as a dev bridge so this page
 * and the recorder can be exercised end-to-end. The UI and save/export are
 * identical once a real ESP32 / socketcan reader is wired to the same channel.
 */
import { useCallback, useEffect, useRef, useState } from 'react';

const LABELS = ['normal', 'DoS', 'Fuzzy', 'gear', 'RPM'];
const SPEED_MIN = 0.1;
const SPEED_MAX = 2000;
const RING = 150;          // recents kept in the live table
const DEV = true;          // banner describing the temporary dev bridge

const wsHost = () => {
  const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
  return `${proto}://${window.location.host}/ws/stream?source=live`;
};
const bytesStr = (b) => {
  const n = Number(b) || 0;
  if (n >= 1e6) return (n / 1e6).toFixed(1) + ' MB';
  if (n >= 1e3) return (n / 1e3).toFixed(1) + ' kB';
  return n + ' B';
};
const payloadBytes = (hex) => (hex && hex.match(/../g)) || [];

export default function LivePage() {
  // stream / connection
  const [connected, setConnected] = useState(false);
  const [running, setRunning] = useState(false);
  const [label, setLabel] = useState('normal');
  const [speed, setSpeed] = useState(60);
  const [error, setError] = useState('');

  // live counters
  const [tps, setTps] = useState(0);
  const [received, setReceived] = useState(0);
  const [msgs, setMsgs] = useState([]);      // ring newest-first

  // recording
  const [recording, setRecording] = useState(false);
  const [recStem, setRecStem] = useState('');
  const [recCount, setRecCount] = useState(0);
  const [recLabel, setRecLabel] = useState('live');   // tag for this recording
  const [toast, setToast] = useState('');

  // saved sessions (REST)
  const [sessions, setSessions] = useState([]);

  const wsRef = useRef(null);
  const msgRing = useRef([]);
  const recordingRef = useRef(false);    // live mirror so onmessage sees fresh truth
  const recCountRef = useRef(0);
  const seq = useRef(0);

  const notify = (text) => {
    setToast(text);
    window.setTimeout(() => setToast(''), 4000);
  };

  const refreshSessions = useCallback(async () => {
    try {
      const r = await fetch('/api/recordings');
      const j = await r.json();
      setSessions(j.sessions || []);
    } catch { /* swallow */ }
  }, []);

  // fetch session list on mount
  useEffect(() => { refreshSessions(); }, [refreshSessions]);

  // ---- open/close the live stream ----
  useEffect(() => {
    if (!running) {
      setConnected(false);
      if (wsRef.current) { wsRef.current.close(); wsRef.current = null; }
      return;
    }
    setError('');
    msgRing.current = [];
    setMsgs([]);
    recordingRef.current = false;
    setRecording(false);
    recCountRef.current = 0;
    setRecCount(0);

    const url = `${wsHost()}&label=${encodeURIComponent(label)}&speed=${speed}`;
    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => setConnected(true);
    ws.onerror = () => { setConnected(false); setError('WebSocket error.'); };

    const reflectRecording = (on) => {
      recordingRef.current = on; setRecording(on);
      if (!on) setRecCount(recCountRef.current);
    };

    ws.onmessage = (ev) => {
      let m; try { m = JSON.parse(ev.data); } catch { return; }
      if (m.type === 'hello') {
        setError('');
        setReceived(0); seq.current = 0;
        if (recordingRef.current) recCountRef.current = 0;
      } else if (m.type === 'messages') {
        const items = m.items || [];
        setTps(m.tps || 0);
        const done = m.done || 0;
        setReceived(done);
        const tagged = items.map((it) => ({ ...it, oseq: ++seq.current }));
        msgRing.current = [...tagged, ...msgRing.current].slice(0, RING);
        setMsgs(msgRing.current);
        // counted frames (~ identical to recorded frames while capturing)
        if (recordingRef.current) { recCountRef.current = done; setRecCount(done); }
      } else if (m.type === 'recording_started') {
        reflectRecording(true);
        setRecStem(m.stem || '');
        notify(`Recording started → ${m.stem}`);
      } else if (m.type === 'record_stopped') {
        const meta = m.meta;
        reflectRecording(false);
        if (meta) {
          recCountRef.current = meta.count || recCountRef.current;
          setRecCount(meta.count || 0);
          notify(`Saved ${(meta.count || 0).toLocaleString('en-US')} frames as "${meta.label}"`);
          refreshSessions();
        }
      } else if (m.type === 'error') {
        setConnected(false); setError(m.error || 'Stream error');
      }
    };
    ws.onclose = () => { setConnected(false); wsRef.current = null; };
    return () => { try { ws.close(); } catch {} wsRef.current = null; };
  }, [running, label, speed]);   // eslint-disable-line react-hooks/exhaustive-deps

  const sendCmd = (cmd, extra = {}) => {
    const ws = wsRef.current;
    if (ws && ws.readyState === WebSocket.OPEN) {
      try { ws.send(JSON.stringify({ cmd, ...extra })); } catch { /* ignore */ }
    }
  };

  const startRecording = () => {
    if (!connected) { notify('Start the live stream before recording.'); return; }
    sendCmd('record_start', { label: (recLabel || 'live').trim() });
  };
  const stopRecording = () => sendCmd('record_stop');

  return (
    <div className="page">
      <h1 className="page-title">Live mode</h1>
      <p className="page-subtitle">
        Reads the CAN bus as captured — with built‑in recording (CSV + raw log).
      </p>

      {DEV && (
        <div className="card" style={{
          marginBottom: 18, background: 'rgba(210,153,34,.07)',
          borderColor: 'rgba(210,153,34,.4)',
        }}>
          <div style={{ fontSize: 13, color: 'var(--orange)' }}>
            <b>Development bridge.</b> No vehicle is connected yet — the backend
            streams a recorded dataset on the <code className="mono">source=live</code> channel so you
            can exercise the dashboard and recorder today. When the ESP32 / socketcan
            reader is wired to the same channel, nothing here needs to change.
          </div>
        </div>
      )}

      {/* ---- transport / source controls ---- */}
      <div className="card" style={{ marginBottom: 18 }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12, alignItems: 'center' }}>
          {LABELS.map((l) => (
            <button key={l} onClick={() => setLabel(l)} style={{
              padding: '5px 11px', borderRadius: 6, cursor: 'pointer', fontFamily: 'inherit',
              fontWeight: 600, fontSize: 12.5,
              background: running && label === l ? 'var(--accent)' : 'var(--bg-2)',
              color: running && label === l ? '#0d1117' : 'var(--text-1)',
              border: '1px solid var(--border)',
            }}>{l}</button>
          ))}
          <div style={{ width: 1, height: 26, background: 'var(--border)' }} />
          <button onClick={() => setRunning(v => !v)} style={{
            padding: '8px 16px', borderRadius: 7, cursor: 'pointer', fontFamily: 'inherit',
            fontWeight: 700, fontSize: 13, border: 'none',
            background: running ? 'var(--red)' : 'var(--accent)', color: '#0d1117',
          }}>
            {running ? '■ Disconnect' : '● Connect'}
          </button>
          <StatusChip active={connected} text={running ? (connected ? 'bus open' : 'connecting…') : 'off'} />

          <span style={{ color: 'var(--text-2)', fontSize: 12 }}>Speed</span>
          <input type="range" min={SPEED_MIN} max={SPEED_MAX} step={0.1} value={speed}
                 disabled={!running} onChange={(e) => setSpeed(parseFloat(e.target.value))} style={{ width: 130 }} />
          <span className="mono" style={{ color: 'var(--accent)', fontWeight: 700, fontSize: 12.5 }}>{speed.toFixed(1)}×</span>
        </div>
        {error && <div style={{ marginTop: 12, color: 'var(--red)', fontSize: 13 }}>⚠ {error}</div>}
      </div>

      {/* ---- stat cards ---- */}
      <div style={{ display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit,minmax(170px,1fr))', gap: 14, marginBottom: 18 }}>
        <StatCard title="Bus" value={running ? (connected ? '● live' : '…') : '—'} accent={connected} light={false} />
        <StatCard title="In / sec" value={running ? `${thousands(Math.round(tps))}` : '—'} light />
        <StatCard title="Received" value={running ? thousands(received) : '—'} accent />
        <StatCard title="Recorder" value={recording ? '● ON' : 'idle'}
                  tone={recording ? 'var(--red)' : 'var(--text-2)'} />
      </div>

      {/* ---- live table ---- */}
      <div className="card" style={{ marginBottom: 18 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h3 style={{ margin: 0 }}>Bus traffic · {label}</h3>
          <span className="badge" style={{ background: 'var(--bg-2)', color: running ? 'var(--green)' : 'var(--text-2)' }}>
            {running ? 'streaming' : 'stopped'}
          </span>
        </div>
        <div style={{ maxHeight: 360, overflowY: 'auto', marginTop: 8 }}>
          <table>
            <thead style={{ position: 'sticky', top: 0, background: 'var(--bg-1)', zIndex: 1 }}>
              <tr><th style={{ width: 80 }}>Seq</th><th style={{ width: 150 }}>Timestamp</th>
                <th style={{ width: 80 }}>Hex</th><th style={{ width: 50 }}>DLC</th><th>Payload</th></tr>
            </thead>
            <tbody>
              {msgs.length === 0 && (
                <tr><td colSpan="5" style={{ textAlign: 'center', color: 'var(--text-2)', padding: 22 }}>
                  {running ? 'Waiting for frames…' : 'Press ● Connect to open the bus.'}</td></tr>
              )}
              {msgs.map((m) => (
                <tr key={m.oseq}>
                  <td className="mono" style={{ color: 'var(--text-2)' }}>…{thousands(Math.max(0, received - m.oseq + 1))}</td>
                  <td className="mono" style={{ color: 'var(--text-1)' }}>{m.ts.toFixed(6)}</td>
                  <td className="mono" style={{ color: 'var(--accent)', fontWeight: 700 }}>{m.hex}</td>
                  <td className="mono">{m.dlc}</td>
                  <td><span className="heat">{payloadBytes(m.payload).map((b, i) => <span key={i}>{b}</span>)}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* ---- Recording & Export ---- */}
      <div className="card">
        <h3 style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span>Recording &amp; Export</span>
          <span className="badge" style={{ background: 'var(--bg-2)', color: recording ? 'var(--red)' : 'var(--text-2)' }}>
            {recording ? '● recording' : 'idle'}
          </span>
        </h3>

        {/* record controls */}
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12, alignItems: 'center', marginBottom: 6 }}>
          <input
            list="labelTags"
            value={recLabel}
            onChange={(e) => setRecLabel(e.target.value)}
            placeholder="tag (e.g. live-normal, attack-dos)"
            style={{
              background: 'var(--bg-2)', color: 'var(--text-0)', border: '1px solid var(--border)',
              borderRadius: 6, padding: '7px 10px', fontFamily: 'inherit', fontSize: 13, width: 220,
            }}
          />
          <datalist id="labelTags">
            <option value="live-normal" /><option value="attack-dos" />
            <option value="attack-fuzzy" /><option value="test-drive" />
          </datalist>

          {!recording ? (
            <button onClick={startRecording} style={actBtn('var(--red)', 'rgba(248,81,73,.12)')}>● Start recording</button>
          ) : (
            <button onClick={stopRecording} style={actBtn('var(--green)', 'rgba(63,185,80,.12)')}>■ Stop &amp; save</button>
          )}
          <span className="mono" style={{ color: 'var(--text-2)', fontSize: 12 }}>
            {recording
              ? <>capturing… <b style={{ color: 'var(--red)' }}>{thousands(recCount)}</b> frames</>
              : recStem ? <>last session had <b style={{ color: 'var(--accent)' }}>{thousands(recCount)}</b> frames</> : 'ready'}
          </span>
        </div>
        {recording && recStem && (
          <div className="legend" style={{ marginBottom: 10 }}>
            Writing to <code className="mono">{recStem}.csv</code> + <code className="mono">{recStem}.log</code>
          </div>
        )}
        {!recording && showFmtLegend()}

        {toast && <div style={{ margin: '6px 0', color: 'var(--green)', fontSize: 12.5 }}>✓ {toast}</div>}

        <div style={{ borderTop: '1px solid var(--border)', margin: '14px 0 10px' }} />

        {/* saved sessions */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
          <h4 style={{ fontSize: 13, margin: 0 }}>Saved sessions</h4>
          <button onClick={refreshSessions} style={miniBtn()}>↻ refresh</button>
        </div>
        {sessions.length === 0 ? (
          <div style={{ color: 'var(--text-2)', fontSize: 13, padding: '8px 2px' }}>
            No recordings yet. Start the stream, press <b>● Start recording</b>, then stop to save.
          </div>
        ) : (
          <div style={{ maxHeight: 360, overflowY: 'auto' }}>
            <table>
              <thead><tr style={{ position: 'sticky', top: 0, background: 'var(--bg-1)', zIndex: 1 }}>
                <th>Session</th><th>Source</th><th>Frames</th><th>Span</th><th>Size</th><th style={{ textAlign: 'right' }}>Actions</th>
              </tr></thead>
              <tbody>
                {sessions.map((s) => (
                  <SessionRow key={s.token} s={s} onRefresh={refreshSessions}
                              onNotify={(t) => notify(t)} bytesStr={bytesStr} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

function thousands(x) { return Number(x || 0).toLocaleString('en-US'); }
function showFmtLegend() {
  return (
    <div className="legend">
      Recording writes two files per session: an <b>analysis‑ready CSV</b> and a
      <b> raw candump log</b> (<code>{'<ts> CAN#payload'}</code>). Both open from the
      list below.
    </div>
  );
}

/* ------------- small components / helpers ------------- */
function StatusChip({ active, text }) {
  return <span className="mono" style={{
    padding: '3px 10px', borderRadius: 999, fontSize: 11, fontWeight: 600,
    background: active ? 'var(--accent-soft)' : 'var(--bg-2)',
    color: active ? 'var(--accent)' : 'var(--text-2)', border: '1px solid var(--border)' }}>{text}</span>;
}
function actBtn(color, bg) {
  return { padding: '8px 15px', borderRadius: 7, cursor: 'pointer', fontFamily: 'inherit',
    fontWeight: 700, fontSize: 13, color, background: bg, border: `1px solid ${color}` };
}
function miniBtn() {
  return { padding: '4px 10px', borderRadius: 6, cursor: 'pointer', fontFamily: 'inherit',
    fontWeight: 600, fontSize: 12, color: 'var(--text-1)', background: 'var(--bg-2)',
    border: '1px solid var(--border)' };
}
function StatCard({ title, value, accent, light, tone }) {
  return (
    <div className="card" style={{ textAlign: 'center', padding: '14px 8px' }}>
      <div className="mono" style={{ fontSize: 20, fontWeight: 800, color: tone || (accent ? 'var(--accent)' : 'var(--text-0)') }}>
        {value}
      </div>
      <div style={{ fontSize: 11.5, color: 'var(--text-2)', marginTop: 2 }}>{title}</div>
    </div>
  );
}
function SessionRow({ s, onRefresh, onNotify, bytesStr }) {
  const dl = (kind) => {
    const a = document.createElement('a');
    a.href = `/api/recordings/download?token=${encodeURIComponent(s.token)}&kind=${kind}`;
    a.download = '';
    document.body.appendChild(a); a.click(); a.remove();
  };
  const del = async () => {
    if (!window.confirm(`Delete session ${s.stem}?`)) return;
    const r = await fetch(`/api/recordings/delete?token=${encodeURIComponent(s.token)}`);
    const j = await r.json();
    if (j.removed && j.removed.length) { onNotify('Session deleted'); onRefresh(); }
    else onNotify('Nothing deleted');
  };
  const size = (s.bytes && (s.bytes.csv || 0)) + ((s.bytes && (s.bytes.log || 0)) || 0);
  return (
    <tr>
      <td className="mono" style={{ color: 'var(--text-0)' }}>{s.stem}</td>
      <td><span className="badge" style={{ background: s.source === 'live' ? 'rgba(88,166,255,.12)' : 'rgba(188,140,255,.12)', color: s.source === 'live' ? 'var(--accent)' : 'var(--purple)' }}>{s.source}</span></td>
      <td className="mono">{thousands(s.count)}</td>
      <td className="mono">{s.span_s != null ? `${s.span_s.toFixed(1)}s` : '—'}</td>
      <td className="mono">{bytesStr(size)}</td>
      <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
        <button onClick={() => dl('csv')} title="Download CSV" style={miniBtn()}>CSV</button>{' '}
        <button onClick={() => dl('log')} title="Download raw log" style={miniBtn()}>LOG</button>{' '}
        <button onClick={del} title="Delete" style={{ ...miniBtn(), color: 'var(--red)' }}>✕</button>
      </td>
    </tr>
  );
}
