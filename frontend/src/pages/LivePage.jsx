/**
 * LivePage — SKELETON (placeholder).
 * Later: reading from ESP32 (socketcan) plus sending to the bus, IDS alerts.
 */
export default function LivePage() {
  return (
    <div className="page">
      <h1 className="page-title">Live mode</h1>
      <p className="page-subtitle">
        Connected to the car — reading and sending messages in real time, TPS, IDS alerts. (In progress)
      </p>
      <div className="card" style={{ color: 'var(--text-2)', textAlign: 'center', padding: '60px 20px' }}>
        🚗 Live mode — bus traffic will be displayed here.
      </div>
    </div>
  );
}
