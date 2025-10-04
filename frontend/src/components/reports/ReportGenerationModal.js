'use client';

import { useState, useEffect } from 'react';
import { X, FileText, Settings, CheckCircle2 } from 'lucide-react';

export function ReportGenerationModal({ onClose, onGenerate }) {
  const [step, setStep] = useState(1);
  const [scanSessions, setScanSessions] = useState([]);
  const [templates, setTemplates] = useState([]);
  const [formData, setFormData] = useState({
    report_name: '',
    report_type: 'technical',
    scan_session_ids: [],
    template_name: '',
    output_formats: ['pdf'],
    include_executive_summary: true,
    include_technical_details: true,
    include_methodology: true,
    include_recommendations: true,
    include_raw_outputs: false,
    include_evidence: true,
    severity_filter: null,
    verified_only: false,
    exclude_false_positives: true,
    pii_redaction: true,
    redaction_level: 'standard',
  });

  useEffect(() => {
    fetchScanSessions();
  }, []);

  useEffect(() => {
    if (formData.report_type) {
      fetchTemplates(formData.report_type);
    }
  }, [formData.report_type]);

  const fetchScanSessions = async () => {
    try {
      const response = await fetch('http://localhost:8000/api/scans/', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
        },
      });
      const data = await response.json();
      setScanSessions(data.scan_sessions || []);
    } catch (error) {
      console.error('Error fetching scan sessions:', error);
    }
  };

  const fetchTemplates = async (reportType) => {
    try {
      const response = await fetch(
        `http://localhost:8000/api/reports/templates/?report_type=${reportType}`,
        {
          headers: {
            'Authorization': `Bearer ${localStorage.getItem('token')}`,
          },
        }
      );
      const data = await response.json();
      setTemplates(data || []);
      if (data.length > 0) {
        setFormData(prev => ({ ...prev, template_name: data[0].template_name }));
      }
    } catch (error) {
      console.error('Error fetching templates:', error);
    }
  };

  const handleSubmit = async () => {
    try {
      const response = await fetch('http://localhost:8000/api/reports/generate', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(formData),
      });

      if (response.ok) {
        onGenerate();
      }
    } catch (error) {
      console.error('Error generating report:', error);
    }
  };

  const toggleFormat = (format) => {
    setFormData(prev => ({
      ...prev,
      output_formats: prev.output_formats.includes(format)
        ? prev.output_formats.filter(f => f !== format)
        : [...prev.output_formats, format],
    }));
  };

  const toggleScanSession = (sessionId) => {
    setFormData(prev => ({
      ...prev,
      scan_session_ids: prev.scan_session_ids.includes(sessionId)
        ? prev.scan_session_ids.filter(id => id !== sessionId)
        : [...prev.scan_session_ids, sessionId],
    }));
  };

  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-[#1a1a1a] rounded-lg border border-gray-800 w-full max-w-4xl max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-gray-800">
          <div>
            <h2 className="text-xl font-bold text-white">Generate Security Report</h2>
            <p className="text-gray-400 text-sm mt-1">
              Step {step} of 3: {step === 1 ? 'Basic Information' : step === 2 ? 'Template & Format' : 'Options & Filters'}
            </p>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-gray-800 rounded-lg transition-colors"
          >
            <X className="w-5 h-5 text-gray-400" />
          </button>
        </div>

        {/* Progress Indicator */}
        <div className="flex items-center px-6 py-4 border-b border-gray-800">
          <div className="flex items-center flex-1">
            <div className={`flex items-center justify-center w-8 h-8 rounded-full ${step >= 1 ? 'bg-blue-600' : 'bg-gray-700'}`}>
              {step > 1 ? <CheckCircle2 className="w-5 h-5 text-white" /> : <span className="text-white text-sm">1</span>}
            </div>
            <div className={`flex-1 h-1 mx-2 ${step >= 2 ? 'bg-blue-600' : 'bg-gray-700'}`}></div>
          </div>
          <div className="flex items-center flex-1">
            <div className={`flex items-center justify-center w-8 h-8 rounded-full ${step >= 2 ? 'bg-blue-600' : 'bg-gray-700'}`}>
              {step > 2 ? <CheckCircle2 className="w-5 h-5 text-white" /> : <span className="text-white text-sm">2</span>}
            </div>
            <div className={`flex-1 h-1 mx-2 ${step >= 3 ? 'bg-blue-600' : 'bg-gray-700'}`}></div>
          </div>
          <div className="flex items-center">
            <div className={`flex items-center justify-center w-8 h-8 rounded-full ${step >= 3 ? 'bg-blue-600' : 'bg-gray-700'}`}>
              <span className="text-white text-sm">3</span>
            </div>
          </div>
        </div>

        {/* Content */}
        <div className="p-6">
          {step === 1 && (
            <div className="space-y-6">
              {/* Report Name */}
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Report Name *
                </label>
                <input
                  type="text"
                  value={formData.report_name}
                  onChange={(e) => setFormData({ ...formData, report_name: e.target.value })}
                  placeholder="e.g., Q1 Security Assessment - Example Corp"
                  className="w-full px-4 py-2 bg-[#0f0f0f] border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                />
              </div>

              {/* Report Type */}
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Report Type *
                </label>
                <div className="grid grid-cols-2 gap-3">
                  {['technical', 'executive', 'bug_bounty', 'compliance'].map((type) => (
                    <button
                      key={type}
                      onClick={() => setFormData({ ...formData, report_type: type })}
                      className={`p-4 rounded-lg border-2 transition-all ${
                        formData.report_type === type
                          ? 'border-blue-500 bg-blue-500/10'
                          : 'border-gray-700 hover:border-gray-600'
                      }`}
                    >
                      <div className="text-left">
                        <div className="font-medium text-white capitalize">{type.replace('_', ' ')}</div>
                        <div className="text-xs text-gray-400 mt-1">
                          {type === 'technical' && 'Detailed technical analysis'}
                          {type === 'executive' && 'High-level summary for executives'}
                          {type === 'bug_bounty' && 'Bug bounty submission format'}
                          {type === 'compliance' && 'Compliance and audit reports'}
                        </div>
                      </div>
                    </button>
                  ))}
                </div>
              </div>

              {/* Scan Sessions */}
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Select Scan Sessions *
                </label>
                <div className="space-y-2 max-h-64 overflow-y-auto border border-gray-700 rounded-lg p-3 bg-[#0f0f0f]">
                  {scanSessions.map((session) => (
                    <label
                      key={session.id}
                      className="flex items-center gap-3 p-3 hover:bg-gray-800 rounded-lg cursor-pointer"
                    >
                      <input
                        type="checkbox"
                        checked={formData.scan_session_ids.includes(session.id)}
                        onChange={() => toggleScanSession(session.id)}
                        className="w-4 h-4 text-blue-600 bg-gray-700 border-gray-600 rounded focus:ring-blue-500"
                      />
                      <div className="flex-1">
                        <div className="text-white text-sm">{session.target_name || session.id}</div>
                        <div className="text-gray-400 text-xs">
                          {new Date(session.created_at).toLocaleDateString()}
                        </div>
                      </div>
                      <div className="text-xs text-gray-500">
                        {session.vulnerabilities_found || 0} vulns
                      </div>
                    </label>
                  ))}
                </div>
              </div>
            </div>
          )}

          {step === 2 && (
            <div className="space-y-6">
              {/* Template Selection */}
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Report Template *
                </label>
                <div className="grid grid-cols-1 gap-3">
                  {templates.map((template) => (
                    <button
                      key={template.template_name}
                      onClick={() => setFormData({ ...formData, template_name: template.template_name })}
                      className={`p-4 rounded-lg border-2 transition-all text-left ${
                        formData.template_name === template.template_name
                          ? 'border-blue-500 bg-blue-500/10'
                          : 'border-gray-700 hover:border-gray-600'
                      }`}
                    >
                      <div className="font-medium text-white">{template.display_name}</div>
                      <div className="text-xs text-gray-400 mt-1">{template.description}</div>
                      <div className="flex gap-2 mt-2">
                        {template.supported_formats?.map((format) => (
                          <span key={format} className="px-2 py-1 bg-gray-800 text-gray-400 text-xs rounded uppercase">
                            {format}
                          </span>
                        ))}
                      </div>
                    </button>
                  ))}
                </div>
              </div>

              {/* Output Formats */}
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Output Formats *
                </label>
                <div className="flex gap-3">
                  {['pdf', 'html', 'json'].map((format) => (
                    <button
                      key={format}
                      onClick={() => toggleFormat(format)}
                      className={`px-6 py-3 rounded-lg border-2 transition-all uppercase font-medium ${
                        formData.output_formats.includes(format)
                          ? 'border-blue-500 bg-blue-500/10 text-blue-500'
                          : 'border-gray-700 text-gray-400 hover:border-gray-600'
                      }`}
                    >
                      {format}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          )}

          {step === 3 && (
            <div className="space-y-6">
              {/* Content Options */}
              <div>
                <h3 className="text-sm font-medium text-gray-300 mb-3">Content Options</h3>
                <div className="space-y-2">
                  {[
                    { key: 'include_executive_summary', label: 'Executive Summary' },
                    { key: 'include_technical_details', label: 'Technical Details' },
                    { key: 'include_methodology', label: 'Methodology Section' },
                    { key: 'include_recommendations', label: 'Recommendations' },
                    { key: 'include_evidence', label: 'Vulnerability Evidence' },
                    { key: 'include_raw_outputs', label: 'Raw Tool Outputs' },
                  ].map((option) => (
                    <label key={option.key} className="flex items-center gap-3 p-3 hover:bg-gray-800 rounded-lg cursor-pointer">
                      <input
                        type="checkbox"
                        checked={formData[option.key]}
                        onChange={(e) => setFormData({ ...formData, [option.key]: e.target.checked })}
                        className="w-4 h-4 text-blue-600 bg-gray-700 border-gray-600 rounded focus:ring-blue-500"
                      />
                      <span className="text-gray-300">{option.label}</span>
                    </label>
                  ))}
                </div>
              </div>

              {/* Filtering Options */}
              <div>
                <h3 className="text-sm font-medium text-gray-300 mb-3">Filtering Options</h3>
                <div className="space-y-2">
                  <label className="flex items-center gap-3 p-3 hover:bg-gray-800 rounded-lg cursor-pointer">
                    <input
                      type="checkbox"
                      checked={formData.verified_only}
                      onChange={(e) => setFormData({ ...formData, verified_only: e.target.checked })}
                      className="w-4 h-4 text-blue-600 bg-gray-700 border-gray-600 rounded focus:ring-blue-500"
                    />
                    <span className="text-gray-300">Verified Vulnerabilities Only</span>
                  </label>
                  <label className="flex items-center gap-3 p-3 hover:bg-gray-800 rounded-lg cursor-pointer">
                    <input
                      type="checkbox"
                      checked={formData.exclude_false_positives}
                      onChange={(e) => setFormData({ ...formData, exclude_false_positives: e.target.checked })}
                      className="w-4 h-4 text-blue-600 bg-gray-700 border-gray-600 rounded focus:ring-blue-500"
                    />
                    <span className="text-gray-300">Exclude False Positives</span>
                  </label>
                </div>
              </div>

              {/* PII Redaction */}
              <div>
                <h3 className="text-sm font-medium text-gray-300 mb-3">Privacy & Security</h3>
                <label className="flex items-center gap-3 p-3 hover:bg-gray-800 rounded-lg cursor-pointer mb-3">
                  <input
                    type="checkbox"
                    checked={formData.pii_redaction}
                    onChange={(e) => setFormData({ ...formData, pii_redaction: e.target.checked })}
                    className="w-4 h-4 text-blue-600 bg-gray-700 border-gray-600 rounded focus:ring-blue-500"
                  />
                  <span className="text-gray-300">Apply PII Redaction</span>
                </label>
                {formData.pii_redaction && (
                  <select
                    value={formData.redaction_level}
                    onChange={(e) => setFormData({ ...formData, redaction_level: e.target.value })}
                    className="w-full px-4 py-2 bg-[#0f0f0f] border border-gray-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
                  >
                    <option value="minimal">Minimal Redaction</option>
                    <option value="standard">Standard Redaction</option>
                    <option value="aggressive">Aggressive Redaction</option>
                  </select>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between p-6 border-t border-gray-800">
          <button
            onClick={() => step > 1 ? setStep(step - 1) : onClose()}
            className="px-4 py-2 text-gray-400 hover:text-white transition-colors"
          >
            {step === 1 ? 'Cancel' : 'Previous'}
          </button>
          <button
            onClick={() => {
              if (step < 3) {
                setStep(step + 1);
              } else {
                handleSubmit();
              }
            }}
            disabled={step === 1 && (!formData.report_name || formData.scan_session_ids.length === 0)}
            className="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {step === 3 ? 'Generate Report' : 'Next'}
          </button>
        </div>
      </div>
    </div>
  );
}
