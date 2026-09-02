import CanFrameDiagram from '../components/CanFrameDiagram';

/**
 * HomePage — first page.
 * Introduction + INTERACTIVE CAN Frame Placer + educational field table.
 */

// Educational field table (static, for learning). `key` is used as an anchor ID
// so that clicking a bit/label in the diagram scrolls to this row.
const FRAME_FIELDS = [
  { key: 'SOF',  name: 'SOF', full: 'Start of Frame', bits: 1, desc: 'Start of frame. Always dominant (0).', color: '#d29922', pos: 'start' },
  { key: 'ID',   name: 'IDENTIFIER', full: 'Arbitration ID', bits: 11, desc: 'Message priority — lower ID = higher priority.', color: '#2ea043', pos: 'header' },
  { key: 'RTR',  name: 'RTR', full: 'Remote Transmission Request', bits: 1, desc: '0 = data frame, 1 = remote frame.', color: '#d4a72c', pos: 'header' },
  { key: 'IDE',  name: 'IDE', full: 'Identifier Extension', bits: 1, desc: '0 = standard 11-bit; 1 = extended 29-bit (CAN 2.0B).', color: '#d4a72c', pos: 'control' },
  { key: 'r0',   name: 'r0', full: 'Reserved bit', bits: 1, desc: 'Reserved (dominant).', color: '#57606a', pos: 'control' },
  { key: 'DLC',  name: 'DLC', full: 'Data Length Code', bits: 4, desc: 'Number of data bytes (0–8).', color: '#d4a72c', pos: 'control' },
  { key: 'DATA', name: 'DATA', full: 'Data Field', bits: '0–64 (0–8B)', desc: 'Actual message content (D0..D7).', color: '#da3633', pos: 'data' },
  { key: 'CRC',  name: 'CRC', full: 'Cyclic Redundancy Check', bits: 15, desc: 'Checksum for error detection.', color: '#388bfd', pos: 'end' },
  { key: 'ACK',  name: 'ACK', full: 'Acknowledgment', bits: 2, desc: 'Acknowledgement (slot + delimiter).', color: '#388bfd', pos: 'end' },
  { key: 'EOF',  name: 'EOF', full: 'End of Frame', bits: 7, desc: 'End of frame (recessive bits).', color: '#57606a', pos: 'end' },
];

export default function HomePage() {
  return (
    <div className="page">
      <h1 className="page-title">CAN frame — interactive guide</h1>
      <p className="page-subtitle">
        Enter ID, DLC and Data, then watch how the CAN frame is assembled into its binary
        state and waveform (CAN_HI / CAN_LO). A starting point for understanding the data
        we analyze in this project.
      </p>

      <h2 className="section">Interactive CAN Frame Placer</h2>
      <p style={{ color: 'var(--text-1)', fontSize: '14px', marginBottom: '14px' }}>
        A CAN message on the bus comprises several <strong>fields</strong>: identification (ID),
        control (DLC), content (DATA) and protection (CRC). Use the panel below to see the
        binary structure and physical waveform when ID/DLC/Data change.
      </p>

      <CanFrameDiagram />

      <h2 className="section">Field structure (overview)</h2>
      <div className="card">
        <table>
          <thead>
            <tr>
              <th style={{ width: 110 }}>Field</th>
              <th style={{ width: 190 }}>Full name</th>
              <th style={{ width: 80 }}>Bits</th>
              <th>Purpose / content</th>
            </tr>
          </thead>
          <tbody>
            {FRAME_FIELDS.map((f) => (
              <tr
                key={f.name}
                id={`field-${f.key}`}
                style={{ scrollMarginTop: 80 }}
              >
                <td><span className="mono" style={{ fontWeight: 700, color: f.color }}>{f.name}</span></td>
                <td className="mono" style={{ color: 'var(--text-1)' }}>{f.full}</td>
                <td className="mono">{f.bits}</td>
                <td style={{ color: 'var(--text-0)' }}>{f.desc}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <h2 className="section">What matters for our analysis</h2>
      <div className="card">
        <table>
          <thead>
            <tr>
              <th>Field</th>
              <th>Relevant for</th>
              <th>Note</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td className="mono" style={{ fontWeight: 700, color: 'var(--red)' }}>CAN_ID</td>
              <td>Message identification</td>
              <td>Each function in the car has its own ID (e.g. speed, RPM). ID analysis is key.</td>
            </tr>
            <tr>
              <td className="mono" style={{ fontWeight: 700, color: 'var(--purple)' }}>DLC</td>
              <td>How much data</td>
              <td>In our dataset it ranges from 2 to 8 bytes.</td>
            </tr>
            <tr>
              <td className="mono" style={{ fontWeight: 700, color: 'var(--green)' }}>DATA (B0..B7)</td>
              <td>Content / meaning</td>
              <td>Bytes are used to decode physical quantities (speed, temp...).</td>
            </tr>
            <tr>
              <td className="mono" style={{ fontWeight: 700, color: 'var(--orange)' }}>Timestamp</td>
              <td>Frequency / delta-t</td>
              <td>How often each message arrives = periodicity of each ID.</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div className="legend">
        📎 <strong>Data are read from a single normalized CSV</strong> (offline for now):
        columns <code className="mono">Timestamp, CAN_ID, DLC, B0..B7, Label</code>.
        Here we first understand the frame structure, then move on to analyzing real data.
      </div>
    </div>
  );
}
