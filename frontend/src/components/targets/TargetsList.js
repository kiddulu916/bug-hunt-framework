'use client';

import { useState } from 'react';
import { motion } from 'framer-motion';
import {
  Plus,
  Target,
  Globe,
  Clock,
  AlertTriangle,
  CheckCircle,
  Play,
  Pause,
  Settings,
  Trash2,
  Edit,
  ExternalLink,
  Search,
  Filter,
  ChevronLeft,
  ChevronRight
} from 'lucide-react';
import { TargetCreationWizard } from './TargetCreationWizard';
import { TargetEditModal } from './TargetEditModal';
import { TargetDeleteConfirmation } from './TargetDeleteConfirmation';
import { useTargets, useCreateTarget, useDeleteTarget } from '@/hooks/api/useTargets';
import { cn } from '@/lib/utils';
import { toast } from 'sonner';

const BUG_BOUNTY_PLATFORMS = [
  { value: '', label: 'All Platforms' },
  { value: 'hackerone', label: 'HackerOne' },
  { value: 'bugcrowd', label: 'Bugcrowd' },
  { value: 'intigriti', label: 'Intigriti' },
  { value: 'synack', label: 'Synack' },
  { value: 'yeswehack', label: 'YesWeHack' },
  { value: 'private', label: 'Private Program' }
];

export function TargetsList() {
  const [showWizard, setShowWizard] = useState(false);
  const [editingTarget, setEditingTarget] = useState(null);
  const [deletingTarget, setDeletingTarget] = useState(null);

  // Filters and pagination
  const [filters, setFilters] = useState({
    page: 1,
    page_size: 20,
    platform: '',
    is_active: null,
    search: '',
    sort_by: 'created_at',
    sort_order: 'desc'
  });

  // Fetch targets with current filters
  const { data, isLoading, error, refetch } = useTargets(filters);
  const createTargetMutation = useCreateTarget();
  const deleteTargetMutation = useDeleteTarget();

  const handleCreateTarget = async (targetData) => {
    try {
      await createTargetMutation.mutateAsync(targetData);
      toast.success('Target created successfully');
      setShowWizard(false);
      refetch();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to create target');
    }
  };

  const handleDeleteTarget = async (targetId) => {
    try {
      await deleteTargetMutation.mutateAsync(targetId);
      toast.success('Target deleted successfully');
      setDeletingTarget(null);
      refetch();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to delete target');
    }
  };

  const updateFilter = (key, value) => {
    setFilters(prev => ({
      ...prev,
      [key]: value,
      page: key !== 'page' ? 1 : value // Reset to page 1 when changing filters
    }));
  };

  const handlePageChange = (newPage) => {
    updateFilter('page', newPage);
  };

  const getStatusIcon = (isActive) => {
    return isActive ? (
      <CheckCircle className="w-4 h-4 text-green-500" />
    ) : (
      <Pause className="w-4 h-4 text-gray-500" />
    );
  };

  const getStatusColor = (isActive) => {
    return isActive
      ? 'text-green-500 bg-green-500 bg-opacity-20'
      : 'text-gray-500 bg-gray-500 bg-opacity-20';
  };

  const getPlatformLabel = (platform) => {
    const found = BUG_BOUNTY_PLATFORMS.find(p => p.value === platform);
    return found?.label || platform;
  };

  // Loading state
  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-center">
          <div className="w-16 h-16 border-4 border-red-600 border-t-transparent rounded-full animate-spin mx-auto mb-4" />
          <p className="text-gray-400">Loading targets...</p>
        </div>
      </div>
    );
  }

  // Error state
  if (error) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-center max-w-md">
          <AlertTriangle className="w-16 h-16 text-red-500 mx-auto mb-4" />
          <h3 className="text-xl font-semibold text-white mb-2">Error Loading Targets</h3>
          <p className="text-gray-400 mb-6">
            {error.response?.data?.detail || 'Failed to load targets. Please try again.'}
          </p>
          <button
            onClick={() => refetch()}
            className="px-6 py-3 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  const targets = data?.targets || [];
  const pagination = data?.pagination || {};
  const platformCounts = data?.platform_counts || {};

  // Empty state
  if (targets.length === 0 && !filters.search && !filters.platform && !showWizard) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-center max-w-md">
          <Target className="w-16 h-16 text-gray-600 mx-auto mb-4" />
          <h3 className="text-xl font-semibold text-white mb-2">No Targets Yet</h3>
          <p className="text-gray-400 mb-6">
            Get started by creating your first target profile. Define the scope, configure settings,
            and begin automated security testing.
          </p>
          <button
            onClick={() => setShowWizard(true)}
            className="flex items-center justify-center w-full px-6 py-3 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors"
          >
            <Plus className="w-5 h-5 mr-2" />
            Create Your First Target
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white">Target Management</h2>
          <p className="text-gray-400 mt-1">
            {pagination.count ? `${pagination.count} target${pagination.count !== 1 ? 's' : ''}` : 'Manage bug bounty targets'}
          </p>
        </div>
        <button
          onClick={() => setShowWizard(true)}
          className="flex items-center px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors"
        >
          <Plus className="w-4 h-4 mr-2" />
          Add Target
        </button>
      </div>

      {/* Filters */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {/* Search */}
          <div className="md:col-span-2">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
              <input
                type="text"
                value={filters.search}
                onChange={(e) => updateFilter('search', e.target.value)}
                placeholder="Search targets..."
                className="w-full pl-10 pr-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-red-600"
              />
            </div>
          </div>

          {/* Platform Filter */}
          <div>
            <select
              value={filters.platform}
              onChange={(e) => updateFilter('platform', e.target.value)}
              className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-red-600"
            >
              {BUG_BOUNTY_PLATFORMS.map(platform => (
                <option key={platform.value} value={platform.value}>
                  {platform.label}
                  {platformCounts[platform.value] ? ` (${platformCounts[platform.value]})` : ''}
                </option>
              ))}
            </select>
          </div>

          {/* Status Filter */}
          <div>
            <select
              value={filters.is_active === null ? '' : filters.is_active.toString()}
              onChange={(e) => updateFilter('is_active', e.target.value === '' ? null : e.target.value === 'true')}
              className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-red-600"
            >
              <option value="">All Status</option>
              <option value="true">Active</option>
              <option value="false">Inactive</option>
            </select>
          </div>
        </div>
      </div>

      {/* No results */}
      {targets.length === 0 && (filters.search || filters.platform) && (
        <div className="text-center py-12">
          <Filter className="w-12 h-12 text-gray-600 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-white mb-2">No targets found</h3>
          <p className="text-gray-400 mb-4">Try adjusting your filters</p>
          <button
            onClick={() => setFilters({
              page: 1,
              page_size: 20,
              platform: '',
              is_active: null,
              search: '',
              sort_by: 'created_at',
              sort_order: 'desc'
            })}
            className="px-4 py-2 text-red-400 hover:text-red-300 transition-colors"
          >
            Clear filters
          </button>
        </div>
      )}

      {/* Targets Grid */}
      {targets.length > 0 && (
        <>
          <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
            {targets.map(target => (
              <motion.div
                key={target.id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                className="bg-gray-900 border border-gray-800 rounded-lg p-6 hover:border-gray-700 transition-colors"
              >
                {/* Header */}
                <div className="flex items-start justify-between mb-4">
                  <div className="flex-1">
                    <h3 className="text-lg font-semibold text-white truncate">
                      {target.target_name}
                    </h3>
                    <div className="flex items-center text-sm text-gray-400 mt-1">
                      <Globe className="w-3 h-3 mr-1" />
                      <span className="truncate">{target.main_url}</span>
                    </div>
                  </div>
                  <div className="relative group">
                    <button className="p-1 text-gray-400 hover:text-white">
                      <Settings className="w-4 h-4" />
                    </button>

                    {/* Dropdown menu */}
                    <div className="absolute right-0 mt-2 w-48 bg-gray-800 border border-gray-700 rounded-lg shadow-lg opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 z-10">
                      <div className="py-1">
                        <button
                          onClick={() => setEditingTarget(target)}
                          className="flex items-center w-full px-4 py-2 text-sm text-gray-300 hover:bg-gray-700 hover:text-white"
                        >
                          <Edit className="w-4 h-4 mr-3" />
                          Edit Target
                        </button>
                        <button className="flex items-center w-full px-4 py-2 text-sm text-gray-300 hover:bg-gray-700 hover:text-white">
                          <ExternalLink className="w-4 h-4 mr-3" />
                          View Details
                        </button>
                        <button
                          onClick={() => setDeletingTarget(target)}
                          className="flex items-center w-full px-4 py-2 text-sm text-red-400 hover:bg-gray-700 hover:text-red-300"
                        >
                          <Trash2 className="w-4 h-4 mr-3" />
                          Delete
                        </button>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Status */}
                <div className="flex items-center justify-between mb-4">
                  <span className={cn(
                    'flex items-center px-2 py-1 rounded-full text-xs font-medium',
                    getStatusColor(target.is_active)
                  )}>
                    {getStatusIcon(target.is_active)}
                    <span className="ml-1 capitalize">{target.is_active ? 'Active' : 'Inactive'}</span>
                  </span>

                  <div className="text-right">
                    <div className="text-sm text-gray-400">Created</div>
                    <div className="text-xs text-gray-500">
                      {new Date(target.created_at).toLocaleDateString()}
                    </div>
                  </div>
                </div>

                {/* Metrics */}
                <div className="grid grid-cols-2 gap-4 mb-4">
                  <div className="text-center">
                    <div className="text-2xl font-bold text-white">
                      {target.in_scope_urls?.length || 0}
                    </div>
                    <div className="text-xs text-gray-400">In-Scope URLs</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-white">
                      {target.requests_per_second || 5}
                    </div>
                    <div className="text-xs text-gray-400">Req/sec</div>
                  </div>
                </div>

                {/* Platform */}
                <div className="border-t border-gray-800 pt-4">
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-gray-400">Platform:</span>
                    <span className="text-white">{getPlatformLabel(target.platform)}</span>
                  </div>
                  <div className="flex items-center justify-between text-sm mt-1">
                    <span className="text-gray-400">Username:</span>
                    <span className="text-white truncate ml-2">{target.researcher_username}</span>
                  </div>
                </div>

                {/* Action Buttons */}
                <div className="flex space-x-2 mt-4">
                  <button className="flex-1 flex items-center justify-center px-3 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 transition-colors">
                    <Play className="w-4 h-4 mr-1" />
                    Scan
                  </button>
                  <button
                    onClick={() => setEditingTarget(target)}
                    className="flex-1 flex items-center justify-center px-3 py-2 bg-gray-700 text-white rounded-md hover:bg-gray-600 transition-colors"
                  >
                    <Settings className="w-4 h-4 mr-1" />
                    Configure
                  </button>
                </div>
              </motion.div>
            ))}
          </div>

          {/* Pagination */}
          {pagination.total_pages > 1 && (
            <div className="flex items-center justify-between">
              <div className="text-sm text-gray-400">
                Showing {((pagination.current_page - 1) * pagination.page_size) + 1} to{' '}
                {Math.min(pagination.current_page * pagination.page_size, pagination.count)} of{' '}
                {pagination.count} targets
              </div>

              <div className="flex items-center space-x-2">
                <button
                  onClick={() => handlePageChange(pagination.current_page - 1)}
                  disabled={!pagination.has_previous}
                  className={cn(
                    'p-2 rounded-lg transition-colors',
                    pagination.has_previous
                      ? 'bg-gray-800 text-white hover:bg-gray-700'
                      : 'bg-gray-900 text-gray-600 cursor-not-allowed'
                  )}
                >
                  <ChevronLeft className="w-5 h-5" />
                </button>

                <div className="flex items-center space-x-1">
                  {[...Array(pagination.total_pages)].map((_, i) => {
                    const page = i + 1;
                    // Show first, last, current, and pages around current
                    if (
                      page === 1 ||
                      page === pagination.total_pages ||
                      (page >= pagination.current_page - 1 && page <= pagination.current_page + 1)
                    ) {
                      return (
                        <button
                          key={page}
                          onClick={() => handlePageChange(page)}
                          className={cn(
                            'w-10 h-10 rounded-lg transition-colors',
                            page === pagination.current_page
                              ? 'bg-red-600 text-white'
                              : 'bg-gray-800 text-gray-300 hover:bg-gray-700'
                          )}
                        >
                          {page}
                        </button>
                      );
                    } else if (
                      page === pagination.current_page - 2 ||
                      page === pagination.current_page + 2
                    ) {
                      return <span key={page} className="text-gray-600">...</span>;
                    }
                    return null;
                  })}
                </div>

                <button
                  onClick={() => handlePageChange(pagination.current_page + 1)}
                  disabled={!pagination.has_next}
                  className={cn(
                    'p-2 rounded-lg transition-colors',
                    pagination.has_next
                      ? 'bg-gray-800 text-white hover:bg-gray-700'
                      : 'bg-gray-900 text-gray-600 cursor-not-allowed'
                  )}
                >
                  <ChevronRight className="w-5 h-5" />
                </button>
              </div>
            </div>
          )}
        </>
      )}

      {/* Modals */}
      {showWizard && (
        <TargetCreationWizard
          onClose={() => setShowWizard(false)}
          onSubmit={handleCreateTarget}
          isLoading={createTargetMutation.isPending}
        />
      )}

      {editingTarget && (
        <TargetEditModal
          target={editingTarget}
          onClose={() => setEditingTarget(null)}
          onSuccess={() => {
            setEditingTarget(null);
            refetch();
          }}
        />
      )}

      {deletingTarget && (
        <TargetDeleteConfirmation
          target={deletingTarget}
          onClose={() => setDeletingTarget(null)}
          onConfirm={() => handleDeleteTarget(deletingTarget.id)}
          isDeleting={deleteTargetMutation.isPending}
        />
      )}
    </div>
  );
}