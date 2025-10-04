'use client';

import { useState, useEffect } from 'react';
import {
  FileText,
  Download,
  Share2,
  FileCheck,
  Calendar,
  Filter,
  Search,
  Plus,
  Eye,
  Trash2,
  RefreshCw,
  ChevronDown
} from 'lucide-react';
import { ReportGenerationModal } from './ReportGenerationModal';
import { ReportTemplateSelector } from './ReportTemplateSelector';

export function ReportsPage() {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState('all');
  const [showGenerationModal, setShowGenerationModal] = useState(false);
  const [selectedReport, setSelectedReport] = useState(null);
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);

  useEffect(() => {
    fetchReports();
  }, [currentPage, filterType, searchQuery]);

  const fetchReports = async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({
        page: currentPage,
        page_size: 10,
        ...(filterType !== 'all' && { report_type: filterType }),
        ...(searchQuery && { search: searchQuery }),
      });

      const response = await fetch(`http://localhost:8000/api/reports/?${params}`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
        },
      });

      const data = await response.json();
      setReports(data.reports || []);
      setTotalPages(data.pagination?.total_pages || 1);
    } catch (error) {
      console.error('Error fetching reports:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = async (reportId, format) => {
    try {
      const response = await fetch(
        `http://localhost:8000/api/reports/${reportId}/download/${format}`,
        {
          headers: {
            'Authorization': `Bearer ${localStorage.getItem('token')}`,
          },
        }
      );

      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `report_${reportId}.${format}`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
      }
    } catch (error) {
      console.error('Error downloading report:', error);
    }
  };

  const handleShare = (reportId) => {
    // Copy share link to clipboard
    const shareUrl = `${window.location.origin}/reports/${reportId}`;
    navigator.clipboard.writeText(shareUrl);
    alert('Share link copied to clipboard!');
  };

  const handleRegenerate = async (reportId) => {
    try {
      const response = await fetch(
        `http://localhost:8000/api/reports/${reportId}/regenerate`,
        {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${localStorage.getItem('token')}`,
            'Content-Type': 'application/json',
          },
        }
      );

      if (response.ok) {
        alert('Report regeneration started');
        fetchReports();
      }
    } catch (error) {
      console.error('Error regenerating report:', error);
    }
  };

  const handleDelete = async (reportId) => {
    if (!confirm('Are you sure you want to delete this report?')) return;

    try {
      const response = await fetch(
        `http://localhost:8000/api/reports/${reportId}`,
        {
          method: 'DELETE',
          headers: {
            'Authorization': `Bearer ${localStorage.getItem('token')}`,
          },
        }
      );

      if (response.ok) {
        fetchReports();
      }
    } catch (error) {
      console.error('Error deleting report:', error);
    }
  };

  const getSeverityColor = (count, severity) => {
    if (count === 0) return 'text-gray-500';
    switch (severity) {
      case 'critical':
        return 'text-red-500';
      case 'high':
        return 'text-orange-500';
      case 'medium':
        return 'text-yellow-500';
      case 'low':
        return 'text-blue-500';
      default:
        return 'text-gray-500';
    }
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Security Reports</h1>
          <p className="text-gray-400 text-sm mt-1">
            Generate and manage vulnerability reports
          </p>
        </div>
        <button
          onClick={() => setShowGenerationModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
        >
          <Plus className="w-4 h-4" />
          Generate Report
        </button>
      </div>

      {/* Filters and Search */}
      <div className="bg-[#1a1a1a] rounded-lg p-4 border border-gray-800">
        <div className="flex flex-col md:flex-row gap-4">
          {/* Search */}
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-500" />
            <input
              type="text"
              placeholder="Search reports..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-[#0f0f0f] border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          {/* Type Filter */}
          <div className="relative">
            <select
              value={filterType}
              onChange={(e) => setFilterType(e.target.value)}
              className="appearance-none px-4 py-2 pr-10 bg-[#0f0f0f] border border-gray-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
            >
              <option value="all">All Types</option>
              <option value="technical">Technical</option>
              <option value="executive">Executive</option>
              <option value="bug_bounty">Bug Bounty</option>
              <option value="compliance">Compliance</option>
            </select>
            <ChevronDown className="absolute right-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-500 pointer-events-none" />
          </div>
        </div>
      </div>

      {/* Reports List */}
      <div className="space-y-4">
        {loading ? (
          <div className="bg-[#1a1a1a] rounded-lg p-8 border border-gray-800 text-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500 mx-auto"></div>
            <p className="text-gray-400 mt-4">Loading reports...</p>
          </div>
        ) : reports.length === 0 ? (
          <div className="bg-[#1a1a1a] rounded-lg p-8 border border-gray-800 text-center">
            <FileText className="w-12 h-12 text-gray-600 mx-auto mb-4" />
            <p className="text-gray-400">No reports found</p>
            <button
              onClick={() => setShowGenerationModal(true)}
              className="mt-4 text-blue-500 hover:text-blue-400"
            >
              Generate your first report
            </button>
          </div>
        ) : (
          reports.map((report) => (
            <div
              key={report.id}
              className="bg-[#1a1a1a] rounded-lg p-6 border border-gray-800 hover:border-gray-700 transition-colors"
            >
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    <FileCheck className="w-5 h-5 text-blue-500" />
                    <h3 className="text-white font-semibold text-lg">
                      {report.report_name}
                    </h3>
                    <span className="px-2 py-1 bg-gray-800 text-gray-400 text-xs rounded uppercase">
                      {report.report_type}
                    </span>
                    {report.pii_redacted && (
                      <span className="px-2 py-1 bg-green-500/10 text-green-500 text-xs rounded">
                        PII Redacted
                      </span>
                    )}
                  </div>

                  <div className="flex items-center gap-4 text-sm text-gray-400 mb-4">
                    <div className="flex items-center gap-1">
                      <Calendar className="w-4 h-4" />
                      {formatDate(report.generated_at)}
                    </div>
                    <div>
                      By {report.generated_by}
                    </div>
                    {report.generation_time_seconds && (
                      <div>
                        Generated in {report.generation_time_seconds.toFixed(1)}s
                      </div>
                    )}
                  </div>

                  {/* Vulnerability Summary */}
                  <div className="flex items-center gap-6 text-sm">
                    <div className="flex items-center gap-2">
                      <span className="text-gray-400">Total:</span>
                      <span className="text-white font-semibold">
                        {report.total_vulnerabilities_reported}
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className={getSeverityColor(report.critical_count, 'critical')}>
                        Critical: {report.critical_count}
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className={getSeverityColor(report.high_count, 'high')}>
                        High: {report.high_count}
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className={getSeverityColor(report.medium_count, 'medium')}>
                        Medium: {report.medium_count}
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className={getSeverityColor(report.low_count, 'low')}>
                        Low: {report.low_count}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Actions */}
                <div className="flex items-center gap-2">
                  {/* Download Dropdown */}
                  <div className="relative group">
                    <button className="p-2 bg-[#0f0f0f] hover:bg-gray-800 rounded-lg transition-colors border border-gray-700">
                      <Download className="w-4 h-4 text-gray-400" />
                    </button>
                    <div className="absolute right-0 mt-2 w-32 bg-[#0f0f0f] border border-gray-700 rounded-lg shadow-lg opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all z-10">
                      {report.pdf_file_path && (
                        <button
                          onClick={() => handleDownload(report.id, 'pdf')}
                          className="w-full px-4 py-2 text-left text-gray-300 hover:bg-gray-800 first:rounded-t-lg"
                        >
                          PDF
                        </button>
                      )}
                      {report.html_file_path && (
                        <button
                          onClick={() => handleDownload(report.id, 'html')}
                          className="w-full px-4 py-2 text-left text-gray-300 hover:bg-gray-800"
                        >
                          HTML
                        </button>
                      )}
                      {report.json_file_path && (
                        <button
                          onClick={() => handleDownload(report.id, 'json')}
                          className="w-full px-4 py-2 text-left text-gray-300 hover:bg-gray-800 last:rounded-b-lg"
                        >
                          JSON
                        </button>
                      )}
                    </div>
                  </div>

                  <button
                    onClick={() => handleShare(report.id)}
                    className="p-2 bg-[#0f0f0f] hover:bg-gray-800 rounded-lg transition-colors border border-gray-700"
                  >
                    <Share2 className="w-4 h-4 text-gray-400" />
                  </button>

                  <button
                    onClick={() => handleRegenerate(report.id)}
                    className="p-2 bg-[#0f0f0f] hover:bg-gray-800 rounded-lg transition-colors border border-gray-700"
                  >
                    <RefreshCw className="w-4 h-4 text-gray-400" />
                  </button>

                  <button
                    onClick={() => handleDelete(report.id)}
                    className="p-2 bg-[#0f0f0f] hover:bg-red-900/30 rounded-lg transition-colors border border-gray-700 hover:border-red-500"
                  >
                    <Trash2 className="w-4 h-4 text-gray-400 hover:text-red-500" />
                  </button>
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-2">
          <button
            onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
            disabled={currentPage === 1}
            className="px-4 py-2 bg-[#1a1a1a] border border-gray-800 rounded-lg text-white disabled:opacity-50 disabled:cursor-not-allowed hover:border-gray-700"
          >
            Previous
          </button>
          <span className="text-gray-400">
            Page {currentPage} of {totalPages}
          </span>
          <button
            onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
            disabled={currentPage === totalPages}
            className="px-4 py-2 bg-[#1a1a1a] border border-gray-800 rounded-lg text-white disabled:opacity-50 disabled:cursor-not-allowed hover:border-gray-700"
          >
            Next
          </button>
        </div>
      )}

      {/* Report Generation Modal */}
      {showGenerationModal && (
        <ReportGenerationModal
          onClose={() => setShowGenerationModal(false)}
          onGenerate={() => {
            setShowGenerationModal(false);
            fetchReports();
          }}
        />
      )}
    </div>
  );
}
