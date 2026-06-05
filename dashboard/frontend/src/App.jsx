import React, { useState } from 'react';
import Sidebar from './components/layout/Sidebar.jsx';
import LiveFeed from './components/pages/LiveFeed.jsx';
import Statistics from './components/pages/Statistics.jsx';
import Detectors from './components/pages/Detectors.jsx';
import ThreatMap from './components/pages/ThreatMap.jsx';
import SystemHealth from './components/pages/SystemHealth.jsx';
import Settings from './components/pages/Settings.jsx';
import { useStats } from './hooks/useApi.js';

export default function App() {
  const [page, setPage] = useState('feed');
  const { stats } = useStats();

  const totalAlerts    = stats?.total    || 0;
  const criticalAlerts = stats?.critical || 0;

  const PAGES = {
    feed:      <LiveFeed />,
    stats:     <Statistics />,
    detectors: <Detectors />,
    threats:   <ThreatMap />,
    system:    <SystemHealth />,
    settings:  <Settings />,
  };

  return (
    <div style={{ display: 'flex', minHeight: '100vh' }}>
      <Sidebar
        active={page}
        onNav={setPage}
        liveCount={totalAlerts}
        criticalCount={criticalAlerts}
      />
      <main style={{
        marginLeft: 'var(--sidebar-w)',
        flex: 1,
        padding: '28px 32px',
        maxWidth: '100%',
        overflowX: 'hidden',
      }}>
        {PAGES[page] || <LiveFeed />}
      </main>
    </div>
  );
}
