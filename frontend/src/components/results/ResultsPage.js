'use client';

import { useState, useMemo } from 'react';
import { useVulnerabilities } from '@/hooks/api/useVulnerabilities';
import { Search, Filter, ChevronDown, AlertTriangle, Shield, Bug } from 'lucide-react';
import { VulnerabilityCard } from './VulnerabilityCard';
import { VulnerabilityTable } from './VulnerabilityTable';
import { VulnerabilityFilters } from './VulnerabilityFilters';

export function ResultsPage() {
  const [viewMode, setViewMode] = useState('cards'); // 'cards' or 'table'
  const [searchQuery, setSearchQuery] = useState('');
  const [filters, setFilters] = useState({
    severity: [],
    status: [],
    target: null,
  });
  const [showFilters, setShowFilters] = useState(false);

  // Fetch vulnerabilities with filters
  const { data, isLoading, error } = useVulnerabilities({
    severity: filters.severity.join(','),
    status: filters.status.join(','),
    target_id: filters.target,
    search: searchQuery,
  });

  const vulnerabilities = data?.results || [];
  const totalCount = data?.count || 0;

  // Calculate statistics
  const stats = useMemo(() => {
    const critical = vulnerabilities.filter(v => v.severity === 'CRITICAL').length;
    const high = vulnerabilities.filter(v => v.severity === 'HIGH').length;
    const medium = vulnerabilities.filter(v => v.severity === 'MEDIUM').length;
    const low = vulnerabilities.filter(v => v.severity === 'LOW').length;
    const info = vulnerabilities.filter(v => v.severity === 'INFO').length;

    return { critical, high, medium, low, info };
  }, [vulnerabilities]);

  const handleFilterChange = (newFilters) => {
    setFilters(newFilters);
  };

  if (error) {
    return (
      <div className="text-white">
        <div className="bg-red-900/20 border border-red-900/50 rounded-lg p-6">
          <div className="flex items-center gap-3">
            <AlertTriangle className="w-6 h-6 text-red-500" />
            <div>
              <h3 className="text-lg font-semibold text-red-500">Error Loading Vulnerabilities</h3>
              <p className="text-gray-400 mt-1">{error.message || 'Failed to fetch vulnerability data'}</p>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header Section */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Scan Results & Vulnerabilities</h1>
          <p className="text-gray-400">
            {totalCount} {totalCount === 1 ? 'vulnerability' : 'vulnerabilities'} found across all targets
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setViewMode('cards')}
            className={`px-4 py-2 rounded text-sm font-medium transition-colors ${
              viewMode === 'cards'
                ? 'bg-blue-600 text-white'
                : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
            }`}
          >
            Cards
          </button>
          <button
            onClick={() => setViewMode('table')}
            className={`px-4 py-2 rounded text-sm font-medium transition-colors ${
              viewMode === 'table'
                ? 'bg-blue-600 text-white'
                : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
            }`}
          >
            Table
          </button>
        </div>
      </div>

      {/* Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        <div className="bg-red-900/20 border border-red-900/50 rounded-lg p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-red-400 text-xs uppercase tracking-wide font-medium">Critical</span>
            <Bug className="w-4 h-4 text-red-500" />
          </div>
          <p className="text-3xl font-bold text-white">{stats.critical}</p>
        </div>

        <div className="bg-orange-900/20 border border-orange-900/50 rounded-lg p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-orange-400 text-xs uppercase tracking-wide font-medium">High</span>
            <AlertTriangle className="w-4 h-4 text-orange-500" />
          </div>
          <p className="text-3xl font-bold text-white">{stats.high}</p>
        </div>

        <div className="bg-yellow-900/20 border border-yellow-900/50 rounded-lg p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-yellow-400 text-xs uppercase tracking-wide font-medium">Medium</span>
            <AlertTriangle className="w-4 h-4 text-yellow-500" />
          </div>
          <p className="text-3xl font-bold text-white">{stats.medium}</p>
        </div>

        <div className="bg-blue-900/20 border border-blue-900/50 rounded-lg p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-blue-400 text-xs uppercase tracking-wide font-medium">Low</span>
            <Shield className="w-4 h-4 text-blue-500" />
          </div>
          <p className="text-3xl font-bold text-white">{stats.low}</p>
        </div>

        <div className="bg-gray-800/50 border border-gray-700 rounded-lg p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-gray-400 text-xs uppercase tracking-wide font-medium">Info</span>
            <Shield className="w-4 h-4 text-gray-500" />
          </div>
          <p className="text-3xl font-bold text-white">{stats.info}</p>
        </div>
      </div>

      {/* Search and Filter Bar */}
      <div className="bg-[#1a1a1a] rounded-lg p-4 border border-gray-800">
        <div className="flex items-center gap-4">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-500" />
            <input
              type="text"
              placeholder="Search vulnerabilities by title, CVE, or description..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-[#0f0f0f] border border-gray-700 rounded-lg pl-10 pr-4 py-2.5 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>
          <button
            onClick={() => setShowFilters(!showFilters)}
            className={`flex items-center gap-2 px-4 py-2.5 rounded-lg font-medium transition-colors ${
              showFilters
                ? 'bg-blue-600 text-white'
                : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
            }`}
          >
            <Filter className="w-5 h-5" />
            Filters
            <ChevronDown className={`w-4 h-4 transition-transform ${showFilters ? 'rotate-180' : ''}`} />
          </button>
        </div>

        {/* Filter Panel */}
        {showFilters && (
          <div className="mt-4 pt-4 border-t border-gray-800">
            <VulnerabilityFilters
              filters={filters}
              onFilterChange={handleFilterChange}
            />
          </div>
        )}
      </div>

      {/* Loading State */}
      {isLoading && (
        <div className="flex items-center justify-center py-12">
          <div className="text-center">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
            <p className="text-gray-400">Loading vulnerabilities...</p>
          </div>
        </div>
      )}

      {/* No Results */}
      {!isLoading && vulnerabilities.length === 0 && (
        <div className="bg-[#1a1a1a] rounded-lg p-12 border border-gray-800 text-center">
          <Shield className="w-16 h-16 text-gray-600 mx-auto mb-4" />
          <h3 className="text-xl font-semibold text-white mb-2">No Vulnerabilities Found</h3>
          <p className="text-gray-400">
            {searchQuery || filters.severity.length > 0 || filters.status.length > 0
              ? 'Try adjusting your search or filters'
              : 'Run a scan to discover vulnerabilities'}
          </p>
        </div>
      )}

      {/* Results Display */}
      {!isLoading && vulnerabilities.length > 0 && (
        <div>
          {viewMode === 'cards' ? (
            <div className="grid grid-cols-1 gap-4">
              {vulnerabilities.map((vulnerability) => (
                <VulnerabilityCard
                  key={vulnerability.id}
                  vulnerability={vulnerability}
                />
              ))}
            </div>
          ) : (
            <VulnerabilityTable vulnerabilities={vulnerabilities} />
          )}
        </div>
      )}
    </div>
  );
}
