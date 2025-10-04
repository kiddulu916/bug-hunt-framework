'use client';

import { useState } from 'react';
import { ScanConfiguration } from './ScanConfiguration';
import { ScanOrchestration } from './ScanOrchestration';
import { Settings2, Play, History } from 'lucide-react';

export function FrameworkPage() {
  const [activeTab, setActiveTab] = useState('configuration');

  const tabs = [
    { id: 'configuration', label: 'Scan Configuration', icon: Settings2 },
    { id: 'orchestration', label: 'Scan Orchestration', icon: Play },
    { id: 'history', label: 'Scan History', icon: History },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white mb-1">Automation Framework</h1>
          <p className="text-gray-400 text-sm">Configure and orchestrate security scans</p>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-800">
        <nav className="flex space-x-8">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`
                  flex items-center gap-2 py-3 px-1 border-b-2 font-medium text-sm transition-colors
                  ${
                    activeTab === tab.id
                      ? 'border-red-600 text-white'
                      : 'border-transparent text-gray-400 hover:text-gray-300 hover:border-gray-700'
                  }
                `}
              >
                <Icon className="w-4 h-4" />
                {tab.label}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Content */}
      <div className="mt-6">
        {activeTab === 'configuration' && <ScanConfiguration />}
        {activeTab === 'orchestration' && <ScanOrchestration />}
        {activeTab === 'history' && (
          <div className="bg-[#1a1a1a] rounded-lg p-8 border border-gray-800 text-center">
            <History className="w-12 h-12 text-gray-600 mx-auto mb-3" />
            <p className="text-gray-400">Scan history will be displayed here</p>
          </div>
        )}
      </div>
    </div>
  );
}
