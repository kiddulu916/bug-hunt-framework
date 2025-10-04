'use client';

import { MainLayout } from '@/components/layout/MainLayout';
import { TargetsList } from '@/components/targets/TargetsList';
import { FrameworkPage } from '@/components/framework';
import { ResultsPage } from '@/components/results';
import { ReportsPage } from '@/components/reports';
import { ActiveScansPanel } from '@/components/scans';
import { ProtectedRoute } from '@/components/auth';
import { useLayoutStore } from '@/store/layout';
import { useState, useMemo } from 'react';
import { TrendingUp, TrendingDown, Activity, Coffee, DollarSign } from 'lucide-react';
import { useLiveMetrics } from '@/hooks/useLiveMetrics';
import { useLiveScans } from '@/hooks/useLiveScans';

// Temporary dashboard content
function DashboardContent() {
  const [timePeriod, setTimePeriod] = useState('week');

  // Live metrics from WebSocket
  const metrics = useLiveMetrics({
    targetsScanned: 23,
    vulnerabilitiesFound: 47,
    criticalVulns: 12,
    scanTimeSaved: 18.6,
  });

  // Live scans from WebSocket
  const scans = useLiveScans([]);

  // Static chart data to prevent hydration mismatch
  const chartData = useMemo(() => [
    { green: 85, blue: 25, yellow: 30 },
    { green: 65, blue: 35, yellow: 20 },
    { green: 75, blue: 20, yellow: 35 },
    { green: 90, blue: 30, yellow: 25 },
    { green: 55, blue: 25, yellow: 15 },
    { green: 80, blue: 35, yellow: 30 },
    { green: 70, blue: 20, yellow: 25 },
    { green: 60, blue: 30, yellow: 20 },
  ], []);

  return (
    <div className="space-y-6">
      {/* Active Scans Panel */}
      {scans.length > 0 && (
        <ActiveScansPanel scans={scans} />
      )}

      {/* Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 mb-3 gap-4">
        {/* Targets Scanned */}
        <div className="bg-[#1a1a1a] rounded-lg p-6 border border-gray-800 hover:border-gray-700 transition-colors">
          <div className="flex items-start justify-between mb-2">
            <div>
              <p className="text-gray-400 text-xs uppercase tracking-wide mb-2">Targets Scanned</p>
              <p className="text-5xl font-bold text-white mb-1">{metrics.targetsScanned}</p>
              <p className="text-gray-500 text-sm uppercase tracking-wide">This Week</p>
            </div>
            <div className="text-green-500">
              <Activity className="w-6 h-6 mb-1" />
            </div>
          </div>
          <div className="flex items-center gap-2 mt-4">
            <TrendingUp className="w-4 h-4 text-green-500" />
            <TrendingUp className="w-4 h-4 text-green-500" />
          </div>
        </div>

        {/* Vulnerabilities Found */}
        <div className="bg-[#1a1a1a] rounded-lg p-6 border border-gray-800 hover:border-gray-700 transition-colors">
          <div className="flex items-start justify-between mb-2">
            <div>
              <p className="text-gray-400 text-xs uppercase tracking-wide mb-2">Vulnerabilities Found</p>
              <p className="text-5xl font-bold text-white mb-1">{metrics.vulnerabilitiesFound}</p>
              <p className="text-orange-500 text-sm uppercase tracking-wide">Critical & High Severity</p>
            </div>
            <div className="text-orange-500">
              <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
              </svg>
            </div>
          </div>
          <div className="flex items-center gap-2 mt-4">
            <TrendingDown className="w-4 h-4 text-orange-500" />
            <TrendingDown className="w-4 h-4 text-orange-500" />
          </div>
        </div>

        {/* Scan Time Saved */}
        <div className="bg-[#1a1a1a] rounded-lg p-6 border border-gray-800 hover:border-gray-700 transition-colors">
          <div className="flex items-start justify-between mb-2">
            <div>
              <p className="text-gray-400 text-xs uppercase tracking-wide mb-2">Scan Time Saved</p>
              <div className="flex items-baseline gap-2">
                <p className="text-5xl font-bold text-white">{metrics.scanTimeSaved}H</p>
                <span className="text-blue-500 text-sm px-2 py-1 bg-blue-500/10 rounded">vs MANUAL</span>
              </div>
              <p className="text-blue-500 text-sm uppercase tracking-wide mt-1">Automated Testing</p>
            </div>
            <div className="text-blue-500">
              <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M11.3 1.046A1 1 0 0112 2v5h4a1 1 0 01.82 1.573l-7 10A1 1 0 018 18v-5H4a1 1 0 01-.82-1.573l7-10a1 1 0 011.12-.38z" clipRule="evenodd" />
              </svg>
            </div>
          </div>
        </div>
      </div>

      {/* Chart Section */}
      <div className="bg-[#1a1a1a] rounded-lg p-6 border border-gray-800">
        {/* Time Period Tabs */}
        <div className="flex items-center gap-3 mb-6">
          <button
            onClick={() => setTimePeriod('week')}
            className={`px-4 py-1.5 rounded text-sm font-medium transition-colors ${
              timePeriod === 'week'
                ? 'bg-blue-600 text-white'
                : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
            }`}
          >
            WEEK
          </button>
          <button
            onClick={() => setTimePeriod('month')}
            className={`px-4 py-1.5 rounded text-sm font-medium transition-colors ${
              timePeriod === 'month'
                ? 'bg-blue-600 text-white'
                : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
            }`}
          >
            MONTH
          </button>
          <button
            onClick={() => setTimePeriod('year')}
            className={`px-4 py-1.5 rounded text-sm font-medium transition-colors ${
              timePeriod === 'year'
                ? 'bg-blue-600 text-white'
                : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
            }`}
          >
            YEAR
          </button>
        </div>

        {/* Chart Legend */}
        <div className="flex items-center gap-6 mb-4">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 bg-blue-500 rounded-full"></div>
            <span className="text-gray-400 text-sm">SPENDINGS</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 bg-green-500 rounded-full"></div>
            <span className="text-gray-400 text-sm">SALES</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 bg-yellow-500 rounded-full"></div>
            <span className="text-gray-400 text-sm">COFFEE</span>
          </div>
        </div>

        {/* Placeholder Chart */}
        <div className="relative h-64 bg-[#0f0f0f] rounded-lg flex items-end justify-around p-4">
          {/* Simple bar chart visualization */}
          {chartData.map((data, i) => (
            <div key={i} className="flex flex-col items-center gap-1 flex-1">
              <div className="w-full flex flex-col items-center justify-end h-full">
                <div
                  className="w-3/4 bg-gradient-to-t from-green-600 to-green-400 rounded-t opacity-80"
                  style={{ height: `${data.green}%` }}
                ></div>
              </div>
              <div className="flex gap-0.5 w-full justify-center">
                <div
                  className="w-1/3 bg-blue-500 rounded opacity-70"
                  style={{ height: `${data.blue}px` }}
                ></div>
                <div
                  className="w-1/3 bg-yellow-500 rounded opacity-70"
                  style={{ height: `${data.yellow}px` }}
                ></div>
              </div>
              <span className="text-xs text-gray-600 mt-2">
                {String(i + 6).padStart(2, '0')}/07
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Security Status */}
      <div className="bg-[#1a1a1a] rounded-lg p-6 border border-gray-800 mt-3">
        <div className="flex items-center gap-2 mb-4">
          <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
          <h3 className="text-white text-sm font-medium uppercase tracking-wide">Security Status</h3>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-gray-400 text-sm">All systems operational</span>
          <span className="text-green-500 text-xs px-3 py-1 bg-green-500/10 rounded-full uppercase tracking-wide">
            Online
          </span>
        </div>
      </div>
    </div>
  );
}

function TargetsContent() {
  return <TargetsList />;
}

function FrameworkContent() {
  return <FrameworkPage />;
}

function ResultsContent() {
  return <ResultsPage />;
}

function ReportsContent() {
  return <ReportsPage />;
}

export default function Home() {
  const { activeSection } = useLayoutStore();

  const renderContent = () => {
    switch (activeSection) {
      case 'dashboard':
        return <DashboardContent />;
      case 'targets':
        return <TargetsContent />;
      case 'framework':
        return <FrameworkContent />;
      case 'results':
        return <ResultsContent />;
      case 'reports':
        return <ReportsContent />;
      default:
        return <DashboardContent />;
    }
  };

  return (
    <ProtectedRoute>
      <MainLayout>
        {renderContent()}
      </MainLayout>
    </ProtectedRoute>
  );
}
