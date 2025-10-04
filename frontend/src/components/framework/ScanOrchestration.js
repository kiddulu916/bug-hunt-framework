'use client';

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { Play, Square, Pause, Target, Clock, CheckCircle, XCircle, AlertCircle, Loader2 } from 'lucide-react';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';

export function ScanOrchestration() {
  const [selectedTarget, setSelectedTarget] = useState(null);
  const [scanType, setScanType] = useState('full');
  const [isStarting, setIsStarting] = useState(false);

  // Fetch targets
  const { data: targetsData, isLoading: targetsLoading } = useQuery({
    queryKey: ['targets'],
    queryFn: () => api.targets.list({ status: 'active' }),
  });

  // Fetch active scans
  const { data: activeScans, isLoading: scansLoading, refetch: refetchScans } = useQuery({
    queryKey: ['active-scans'],
    queryFn: () => api.scans.list({ status: 'running' }),
    refetchInterval: 5000, // Poll every 5 seconds
  });

  const targets = targetsData?.results || [];
  const scans = activeScans?.results || [];

  const handleStartScan = async () => {
    if (!selectedTarget) {
      toast.error('Please select a target');
      return;
    }

    setIsStarting(true);
    try {
      const scanData = {
        target_id: selectedTarget,
        scan_type: scanType,
        config: {
          // This would come from the saved configuration
          tools: {
            nuclei: true,
            custom_web: true,
            custom_api: true,
            custom_infra: true,
          },
          phases: {
            reconnaissance: { enabled: true },
            exploitation: { enabled: scanType === 'full' },
          },
        },
      };

      await api.scans.create(scanData);
      toast.success('Scan started successfully');
      setSelectedTarget(null);
      refetchScans();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to start scan');
    } finally {
      setIsStarting(false);
    }
  };

  const handleCancelScan = async (scanId) => {
    try {
      await api.scans.cancel(scanId);
      toast.success('Scan cancelled');
      refetchScans();
    } catch (error) {
      toast.error('Failed to cancel scan');
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'running':
        return <Loader2 className="w-4 h-4 text-blue-500 animate-spin" />;
      case 'completed':
        return <CheckCircle className="w-4 h-4 text-green-500" />;
      case 'failed':
        return <XCircle className="w-4 h-4 text-red-500" />;
      case 'cancelled':
        return <Square className="w-4 h-4 text-gray-500" />;
      default:
        return <AlertCircle className="w-4 h-4 text-yellow-500" />;
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'running':
        return 'text-blue-500 bg-blue-500/10';
      case 'completed':
        return 'text-green-500 bg-green-500/10';
      case 'failed':
        return 'text-red-500 bg-red-500/10';
      case 'cancelled':
        return 'text-gray-500 bg-gray-500/10';
      default:
        return 'text-yellow-500 bg-yellow-500/10';
    }
  };

  return (
    <div className="space-y-6">
      {/* Start New Scan */}
      <div className="bg-[#1a1a1a] rounded-lg border border-gray-800 p-6">
        <h3 className="text-white font-medium mb-4 flex items-center gap-2">
          <Play className="w-5 h-5 text-red-500" />
          Start New Scan
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
          {/* Target Selection */}
          <div>
            <label className="text-gray-400 text-sm mb-2 block">Select Target</label>
            {targetsLoading ? (
              <div className="bg-gray-800 rounded-lg p-3 flex items-center gap-2">
                <Loader2 className="w-4 h-4 animate-spin text-gray-400" />
                <span className="text-gray-400 text-sm">Loading targets...</span>
              </div>
            ) : (
              <select
                value={selectedTarget || ''}
                onChange={(e) => setSelectedTarget(e.target.value)}
                className="bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 text-white w-full focus:outline-none focus:border-red-500"
              >
                <option value="">Choose a target...</option>
                {targets.map((target) => (
                  <option key={target.id} value={target.id}>
                    {target.name} - {target.target_url}
                  </option>
                ))}
              </select>
            )}
          </div>

          {/* Scan Type */}
          <div>
            <label className="text-gray-400 text-sm mb-2 block">Scan Type</label>
            <select
              value={scanType}
              onChange={(e) => setScanType(e.target.value)}
              className="bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 text-white w-full focus:outline-none focus:border-red-500"
            >
              <option value="full">Full Scan (Recon + Exploitation)</option>
              <option value="recon">Reconnaissance Only</option>
              <option value="exploit">Exploitation Only</option>
              <option value="quick">Quick Scan</option>
            </select>
          </div>
        </div>

        <button
          onClick={handleStartScan}
          disabled={!selectedTarget || isStarting}
          className={cn(
            'w-full py-3 rounded-lg font-medium flex items-center justify-center gap-2 transition-colors',
            selectedTarget && !isStarting
              ? 'bg-red-600 hover:bg-red-700 text-white'
              : 'bg-gray-800 text-gray-500 cursor-not-allowed'
          )}
        >
          {isStarting ? (
            <>
              <Loader2 className="w-5 h-5 animate-spin" />
              Starting Scan...
            </>
          ) : (
            <>
              <Play className="w-5 h-5" />
              Start Scan
            </>
          )}
        </button>
      </div>

      {/* Active Scans */}
      <div className="bg-[#1a1a1a] rounded-lg border border-gray-800 p-6">
        <h3 className="text-white font-medium mb-4 flex items-center gap-2">
          <Loader2 className="w-5 h-5 text-blue-500" />
          Active Scans
          {scans.length > 0 && (
            <span className="ml-auto text-sm text-gray-400">({scans.length} running)</span>
          )}
        </h3>

        {scansLoading ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="w-6 h-6 animate-spin text-gray-400" />
          </div>
        ) : scans.length === 0 ? (
          <div className="text-center py-8">
            <Target className="w-12 h-12 text-gray-600 mx-auto mb-3" />
            <p className="text-gray-400">No active scans</p>
            <p className="text-gray-500 text-sm">Start a new scan to see it here</p>
          </div>
        ) : (
          <div className="space-y-3">
            {scans.map((scan) => (
              <div
                key={scan.id}
                className="bg-gray-800/50 rounded-lg p-4 border border-gray-700 hover:border-gray-600 transition-colors"
              >
                <div className="flex items-start justify-between mb-3">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <h4 className="text-white font-medium">{scan.target_name}</h4>
                      <span
                        className={cn(
                          'px-2 py-0.5 rounded text-xs uppercase tracking-wide flex items-center gap-1',
                          getStatusColor(scan.status)
                        )}
                      >
                        {getStatusIcon(scan.status)}
                        {scan.status}
                      </span>
                    </div>
                    <p className="text-gray-400 text-sm">{scan.target_url}</p>
                  </div>

                  {scan.status === 'running' && (
                    <button
                      onClick={() => handleCancelScan(scan.id)}
                      className="p-2 rounded-lg bg-gray-700 hover:bg-gray-600 text-gray-300 transition-colors"
                      title="Cancel scan"
                    >
                      <Square className="w-4 h-4" />
                    </button>
                  )}
                </div>

                {/* Progress */}
                {scan.status === 'running' && (
                  <div className="space-y-2">
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-gray-400">{scan.current_phase || 'Initializing...'}</span>
                      <span className="text-gray-300">{scan.total_progress || 0}%</span>
                    </div>
                    <div className="w-full bg-gray-700 rounded-full h-2">
                      <div
                        className="bg-blue-500 h-2 rounded-full transition-all duration-500"
                        style={{ width: `${scan.total_progress || 0}%` }}
                      />
                    </div>
                  </div>
                )}

                {/* Stats */}
                <div className="grid grid-cols-3 gap-4 mt-3 pt-3 border-t border-gray-700">
                  <div>
                    <p className="text-gray-500 text-xs mb-1">Subdomains</p>
                    <p className="text-white font-medium">{scan.total_subdomains_found || 0}</p>
                  </div>
                  <div>
                    <p className="text-gray-500 text-xs mb-1">Endpoints</p>
                    <p className="text-white font-medium">{scan.total_endpoints_found || 0}</p>
                  </div>
                  <div>
                    <p className="text-gray-500 text-xs mb-1">Vulnerabilities</p>
                    <p className="text-white font-medium">{scan.vulnerabilities_found || 0}</p>
                  </div>
                </div>

                {/* Timing */}
                <div className="flex items-center gap-4 mt-3 text-xs text-gray-500">
                  <div className="flex items-center gap-1">
                    <Clock className="w-3 h-3" />
                    Started: {new Date(scan.started_at).toLocaleString()}
                  </div>
                  {scan.estimated_completion && (
                    <div className="flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      ETA: {new Date(scan.estimated_completion).toLocaleString()}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Quick Actions */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <button className="bg-[#1a1a1a] border border-gray-800 rounded-lg p-4 text-left hover:border-gray-700 transition-colors">
          <div className="flex items-center gap-3 mb-2">
            <div className="p-2 bg-blue-500/10 rounded-lg">
              <Play className="w-5 h-5 text-blue-500" />
            </div>
            <h4 className="text-white font-medium">Quick Scan</h4>
          </div>
          <p className="text-gray-400 text-sm">Run a fast vulnerability scan</p>
        </button>

        <button className="bg-[#1a1a1a] border border-gray-800 rounded-lg p-4 text-left hover:border-gray-700 transition-colors">
          <div className="flex items-center gap-3 mb-2">
            <div className="p-2 bg-green-500/10 rounded-lg">
              <Target className="w-5 h-5 text-green-500" />
            </div>
            <h4 className="text-white font-medium">Scan All Active</h4>
          </div>
          <p className="text-gray-400 text-sm">Scan all active targets</p>
        </button>

        <button className="bg-[#1a1a1a] border border-gray-800 rounded-lg p-4 text-left hover:border-gray-700 transition-colors">
          <div className="flex items-center gap-3 mb-2">
            <div className="p-2 bg-purple-500/10 rounded-lg">
              <Clock className="w-5 h-5 text-purple-500" />
            </div>
            <h4 className="text-white font-medium">Schedule Scan</h4>
          </div>
          <p className="text-gray-400 text-sm">Schedule a scan for later</p>
        </button>
      </div>
    </div>
  );
}
