/**
 * CanFrameDiagram — INTERACTIVE CAN Frame Placer (React).
 *
 * User enters CAN ID (hex), DLC and Data (hex) → the diagram updates dynamically:
 *   - binary row (bit by bit, with field colors)
 *   - waveform for CAN_HI and CAN_LO (V-levels: dominant/recessive)
 *
 * Frame fields (standard CAN 2.0A):
 *   SOF(1) + ID(11) + RTR(1) + IDE(1) + r0(1) + DLC(4) + DATA(DLC*8) + CRC(15) + DEL(1) + ACK(2) + EOF(7)
 *
 * Waveform levels (teaching display):
 *   - dominant ('0'): CAN_HI = high (e.g. +3.5V), CAN_LO = low (e.g. 1.5V) → split
 *   - recessive ('1'): both at mid level (2.5V) → joined
 */

import { useMemo, useState } from 'react';

// Width of each bit in pixels (larger = more horizontal space)
export const BIT_W = 32;

// Field colors (soft but distinguishable)
const FIELD_COLORS = {
  sofr: '#d29922',   // start / delimiter
  arc: '#2ea043',    // arbitration (ID) - green
  ctrl: '#d4a72c',   // control / DLC - yellow
  data: '#da3633',   // data - red
  crc: '#388bfd',    // CRC / ACK - blue
  other: '#57606a',  // other (r0, del, eof) - gray
};

export default function CanFrameDiagram() {
  const [idHex, setIdHex] = useState('123');
  const [dlc, setDlc] = useState(8);
  const [dataHex, setDataHex] = useState('DEADBEEF');

  // Scroll to a field row in the "Field structure" table on the page and flash it.
  const scrollToField = (key) => {
    const el = document.getElementById(`field-${key}`);
    if (!el) return;
    el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    // (Re)start the highlight animation on the target row.
    el.classList.remove('flash');
    // Force reflow so removing+re-adding restarts the animation on repeat clicks.
    void el.offsetWidth;
    el.classList.add('flash');
    setTimeout(() => el.classList.remove('flash'), 1250);
  };

  // Parser: hex to number (safe)
  const parseHex = (s) => {
    const clean = s.replace(/^0x/i, '').trim();
    if (!/^[0-9a-fA-F]*$/.test(clean)) return 0;
    return parseInt(clean, 16) || 0;
  };

  // Convert number to binary string with N bits (left-padded)
  const toBin = (num, bits) => {
    return (num >>> 0).toString(2).padStart(bits, '0').slice(-bits);
  };

  // Build full CAN frame as list of bits with metadata (field, index, label)
  const frame = useMemo(() => {
    const idNum = parseHex(idHex) & 0x7ff;          // 11 bit
    const dlcNum = Math.max(0, Math.min(8, parseInt(dlc, 10) || 0));
    const dataNum = parseHex(dataHex);

    const idBin = toBin(idNum, 11);
    const dlcBin = toBin(dlcNum, 4);
    const dataBin = toBin(dataNum, dlcNum * 8).padStart(dlcNum * 8, '0');

    // assemble fields in order
    // [SOF][ID 11][RTR][IDE][r0][DLC 4][DATA][CRC 15][DEL][ACK 2][EOF 7]
    const sections = [
      { name: 'SOF',   bits: '0',                cls: 'sofr', label: 'SOF',  fullName: 'Start of Frame' },
      { name: 'ID',    bits: idBin,              cls: 'arc',  label: 'ID',   fullName: 'Arbitration Identifier' },
      { name: 'RTR',   bits: '0',                cls: 'ctrl', label: 'RTR',  fullName: 'Remote Transmission Request' },
      { name: 'IDE',   bits: '0',                cls: 'ctrl', label: 'IDE',  fullName: 'Identifier Extension' },
      { name: 'r0',    bits: '0',                cls: 'other', label: 'r0',  fullName: 'Reserved bit' },
      { name: 'DLC',   bits: dlcBin,             cls: 'ctrl', label: 'DLC',  fullName: 'Data Length Code' },
      { name: 'DATA',  bits: dataBin,            cls: 'data', label: 'DATA', fullName: 'Data Field' },
      { name: 'CRC',   bits: toBin(0x3AB, 15),   cls: 'crc',  label: 'CRC',  fullName: 'Cyclic Redundancy Check' },
      { name: 'DEL',   bits: '1',                cls: 'other', label: 'DEL', fullName: 'ACK Delimiter' },
      { name: 'ACK',   bits: '11',               cls: 'crc',  label: 'ACK',  fullName: 'Acknowledgment' },
      { name: 'EOF',   bits: '1111111',          cls: 'other', label: 'EOF', fullName: 'End of Frame' },
    ];

    // unpack each bit into a list of objects
    let bits = [];
    sections.forEach((sec) => {
      for (let i = 0; i < sec.bits.length; i++) {
        bits.push({
          val: sec.bits[i],
          cls: sec.cls,
          secName: sec.name,
        });
      }
    });

    return { bits, sections, idNum, dlcNum };
  }, [idHex, dlc, dataHex]);

  // Waveform levels for each bit (canonical)
  const waveforms = useMemo(() => {
    const hi = [];
    const lo = [];
    frame.bits.forEach((b) => {
      if (b.val === '1') {
        // recessive: both mid (2.5V)
        hi.push(0.5);
        lo.push(0.5);
      } else {
        // dominant: HI high, LO low
        hi.push(0.9);
        lo.push(0.15);
      }
    });
    return { hi, lo };
  }, [frame]);

  // Simple SVG waveform: uses V-transitions for visual display
  const renderWave = (values, color) => {
    // bit width aligned with the binary box
    const bw = BIT_W;
    const w = values.length * bw;
    const h = 60;

    // Each bit keeps the same level across its whole box; transitions happen exactly
    // on the box boundaries (left/right edges of each bit cell).
    let d = `M0 ${h - values[0] * h}`;
    for (let i = 1; i < values.length; i++) {
      const x1 = i * bw;                      // right edge of previous bit = left edge of current
      const yPrev = h - values[i - 1] * h;     // level for the whole previous box
      const yCur = h - values[i] * h;          // level for the whole current box
      d += ` L${x1} ${yPrev}`;                 // hold level until the boundary
      if (yPrev !== yCur) d += ` L${x1} ${yCur}`; // snap vertically on the boundary
    }
    d += ` L${w} ${h - values[values.length - 1] * h}`;

    // Vertical guide lines at every bit boundary, so the waveform aligns with each box.
    let guides = '';
    for (let i = 0; i <= values.length; i++) {
      const x = i * bw;
      guides += ` M${x} 0 L${x} ${h}`;
    }

    return (
      <svg height={h + 10} width={w} style={{ display: 'block' }}>
        <path d={guides} fill="none" stroke="#9ba7b4" strokeWidth={0.5} strokeDasharray="2 3" opacity={0.5} />
        <path d={d} fill="none" stroke={color} strokeWidth={2} />
        <line x1="0" y1={h} x2={w} y2={h} stroke="#555" strokeDasharray="3 3" />
      </svg>
    );
  };

  // Render binary row of bit cells
  const renderBits = () => {
    let borders = [];
    let key = 0;
    let idx = 0;
    return (
      <div className="bits-scroll" style={{ width: '100%' }}>
        <div className="bit-grid" style={{ minWidth: frame.bits.length * BIT_W, display: 'flex' }}>
          {frame.bits.map((b, i) => {
            const isFieldStart = i === 0 || frame.bits[i].secName !== frame.bits[i - 1].secName;
            return (
              <div
                key={i}
                onClick={() => scrollToField(b.secName)}
                title={`Learn more about ${b.secName}`}
                style={{
                  width: BIT_W,
                  height: 34,
                  borderRight: '1px solid #333',
                  borderTop: '3px solid ' + FIELD_COLORS[b.cls],
                  textAlign: 'center',
                  lineHeight: '34px',
                  fontSize: '12px',
                  fontFamily: 'monospace',
                  color: b.val === '1' ? '#fff' : '#9ba7b4',
                  fontWeight: 700,
                  background: isFieldStart ? 'rgba(255,255,255,0.04)' : 'transparent',
                  cursor: 'pointer',
                }}
              >
                {b.val}
              </div>
            );
          })}
        </div>
      </div>
    );
  };

  // Labels above bits — each section in its own flex block width = bits*BIT_W.
  // No absolute + rotation (previous overlapped). Full name and short name
  // stack vertically inside each block.
  const renderSectionLabels = () => {
    let cursor = 0;
    const blocks = frame.sections.map((sec) => {
      const w = sec.bits.length * BIT_W;
      const wide = w >= 60; // wide enough for horizontal full name
      const start = cursor;
      cursor += sec.bits.length;

      return (
        <div
          key={sec.name}
          onClick={() => scrollToField(sec.name)}
          title={`Learn more: ${sec.fullName || sec.label}`}
          style={{
            width: w,
            flexShrink: 0,
            textAlign: 'center',
            padding: '0 2px',
            position: 'relative',
            cursor: 'pointer',
          }}
        >
          {/* Full name */}
          <div
            title={sec.fullName || sec.label}
            style={{
              fontSize: 9,
              fontWeight: 600,
              color: FIELD_COLORS[sec.cls],
              lineHeight: 1.15,
              maxHeight: wide ? 22 : 56,
              overflow: 'hidden',
              whiteSpace: wide ? 'nowrap' : 'normal',
              writingMode: wide ? 'horizontal-tb' : 'vertical-rl',
              letterSpacing: 0,
              textOverflow: 'ellipsis',
              marginBottom: 3,
            }}
          >
            {sec.fullName || sec.label}
          </div>
          {/* Short name */}
          <div
            style={{
              fontSize: 10,
              fontWeight: 700,
              color: FIELD_COLORS[sec.cls],
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
            }}
          >
            {sec.label}
          </div>
        </div>
      );
    });
    return (
      <div style={{ display: 'flex', minWidth: frame.bits.length * BIT_W, marginBottom: 6 }}>
        {blocks}
      </div>
    );
  };

  // bit counter
  const renderBitIndices = () => {
    let out = [];
    frame.bits.forEach((b, i) => {
      const show = i % 8 === 0 || i === frame.bits.length - 1;
      if (show) {
        out.push(<span key={i} style={{ minWidth: BIT_W, display: 'inline-block' }}>{i}</span>);
      } else {
        out.push(<span key={i} style={{ minWidth: BIT_W, display: 'inline-block' }}>&nbsp;</span>);
      }
    });
    return (
      <div style={{ display: 'flex', fontSize: '9px', color: '#6e7681', minWidth: frame.bits.length * BIT_W, overflow: 'hidden' }}>
        {out}
      </div>
    );
  };

  // FlexRow = horizontal row with a fixed left gutter (label slot) so that every
  // layer (bits, indices, CAN_HI / CAN_LO waveform) starts at the same X as the bits.
  const FlexRow = ({ label = '', height = 34, children }) => (
    <div style={{ display: 'flex', alignItems: 'center' }}>
      <div style={{
        width: 44,
        flexShrink: 0,
        height,
        color: '#6e7681',
        fontSize: 10,
        fontFamily: 'monospace',
        display: 'flex',
        alignItems: 'center',
        lineHeight: 1,
      }}>
        {label}
      </div>
      <div style={{ flex: 1 }}>{children}</div>
    </div>
  );

  return (
    <div className="canframe" style={{ margin: '6px 0' }}>
      {/* Control panel */}
      <div className="card" style={{ marginBottom: 20, maxWidth: 640 }}>
        <h3 style={{ marginBottom: 12 }}>🎛 CAN frame control panel</h3>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 16, alignItems: 'flex-end' }}>
          <label style={{ fontSize: 13 }}>
            CAN ID (hex)
            <div style={{ marginTop: 4 }}>
              <input value={idHex} onChange={(e) => setIdHex(e.target.value)} size={5}
                style={inputStyle} />
              <span className="badge gray" style={{ marginLeft: 6 }}>11-bit (0x000-0x7FF)</span>
            </div>
          </label>
          <label style={{ fontSize: 13 }}>
            DLC
            <div style={{ marginTop: 4 }}>
              <input type="number" value={dlc} onChange={(e) => setDlc(e.target.value)} min="0" max="8"
                style={{ ...inputStyle, width: 64 }} />
            </div>
          </label>
          <label style={{ fontSize: 13 }}>
            Data (hex)
            <div style={{ marginTop: 4 }}>
              <input value={dataHex} onChange={(e) => setDataHex(e.target.value)} size={16}
                style={inputStyle} />
              <span className="badge gray" style={{ marginLeft: 6 }}>{dlc} B → {dlc * 8} bit</span>
            </div>
          </label>
        </div>
        <div className="legend" style={{ marginTop: 10, fontSize: 12.5 }}>
          Enter all three values — the diagram below updates automatically.
        </div>
      </div>

      {/* Diagram — ONE shared horizontal scroll. Every row (labels, bits, indices, waves)
          shares the same left gutter so the waveform aligns exactly under the 0/1 columns. */}
      <div className="card" style={{ overflowX: 'auto', padding: '12px 16px' }}>
        <div style={{ minWidth: frame.bits.length * BIT_W }}>
          <FlexRow label="FIELD"    height={34}>{renderSectionLabels()}</FlexRow>
          <FlexRow label="BIT"      height={34}>{renderBits()}</FlexRow>
          <FlexRow label=""         height={16}>{renderBitIndices()}</FlexRow>
          <FlexRow label="CAN_HI"   height={72}>{renderWave(waveforms.hi, '#58a6ff')}</FlexRow>
          <FlexRow label="CAN_LO"   height={72}>{renderWave(waveforms.lo, '#39c5cf')}</FlexRow>

        </div>
      </div>

      {/* Legend */}
      <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap', marginTop: 12, fontSize: 12, color: '#9ba7b4' }}>
        <span><i style={{ background: FIELD_COLORS.arc, display: 'inline-block', width: 10, height: 10, borderRadius: 2, marginRight: 5 }} /> Arbitration / ID</span>
        <span><i style={{ background: FIELD_COLORS.ctrl, display: 'inline-block', width: 10, height: 10, borderRadius: 2, marginRight: 5 }} /> Control / DLC</span>
        <span><i style={{ background: FIELD_COLORS.data, display: 'inline-block', width: 10, height: 10, borderRadius: 2, marginRight: 5 }} /> Data</span>
        <span><i style={{ background: FIELD_COLORS.crc, display: 'inline-block', width: 10, height: 10, borderRadius: 2, marginRight: 5 }} /> CRC / ACK</span>
      </div>
      <div className="legend" style={{ marginTop: 8 }}>
        <strong>Binary:</strong> 0 = dominant bit, 1 = recessive bit.&nbsp;
        <strong>Waveform:</strong> dominant (0) → CAN_HI high / CAN_LO low (split); recessive (1) → both at mid level (joined).
      </div>
    </div>
  );
}

const inputStyle = {
  background: '#0d1117',
  border: '1px solid #30363d',
  color: '#e6edf3',
  borderRadius: 6,
  padding: '7px 10px',
  fontFamily: 'monospace',
  fontSize: 13,
};
