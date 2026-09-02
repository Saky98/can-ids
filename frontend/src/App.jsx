import { useState } from 'react';
import HomePage from './pages/HomePage';
import AnalysisPage from './pages/AnalysisPage';
import SimulatorPage from './pages/SimulatorPage';
import LivePage from './pages/LivePage';

const NAV = [
  { key: 'home', label: '📖 CAN Frame' },
  { key: 'analysis', label: '🔍 Analysis' },
  { key: 'simulator', label: '🎛 Simulator' },
  { key: 'live', label: '🚗 Live' },
];

export default function App() {
  const [page, setPage] = useState('home');

  const renderPage = () => {
    switch (page) {
      case 'analysis': return <AnalysisPage />;
      case 'simulator': return <SimulatorPage />;
      case 'live': return <LivePage />;
      default: return <HomePage />;
    }
  };

  return (
    <div className="app">
      <header className="app-header">
        <div className="brand">
          <span className="brand-logo">CAN</span>
          <span>CarHacking Web</span>
        </div>
        <nav className="app-nav">
          {NAV.map((item) => (
            <button
              key={item.key}
              className={`nav-link ${page === item.key ? 'active' : ''}`}
              // reset all button styles
              style={{
                background: 'transparent',
                border: 'none',
                cursor: 'pointer',
                fontFamily: 'inherit',
              }}
              onClick={() => setPage(item.key)}
            >
              {item.label}
            </button>
          ))}
        </nav>
      </header>

      <main className="app-main">{renderPage()}</main>

      <footer className="app-footer">
        Thesis — IDS for protecting CAN communication · Car-Hacking Dataset · React + FastAPI
      </footer>
    </div>
  );
}
