'use client';

import { useState, useEffect } from 'react';
import { FileText, CheckCircle2, Eye } from 'lucide-react';

export function ReportTemplateSelector({ reportType, selectedTemplate, onSelect }) {
  const [templates, setTemplates] = useState([]);
  const [loading, setLoading] = useState(true);
  const [previewTemplate, setPreviewTemplate] = useState(null);

  useEffect(() => {
    fetchTemplates();
  }, [reportType]);

  const fetchTemplates = async () => {
    setLoading(true);
    try {
      const url = reportType
        ? `http://localhost:8000/api/reports/templates/?report_type=${reportType}`
        : 'http://localhost:8000/api/reports/templates/';

      const response = await fetch(url, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
        },
      });

      const data = await response.json();
      setTemplates(data || []);

      // Auto-select first template if none selected
      if (data.length > 0 && !selectedTemplate) {
        onSelect(data[0].template_name);
      }
    } catch (error) {
      console.error('Error fetching templates:', error);
    } finally {
      setLoading(false);
    }
  };

  const handlePreview = async (templateName) => {
    try {
      const response = await fetch(
        `http://localhost:8000/api/reports/templates/${templateName}`,
        {
          headers: {
            'Authorization': `Bearer ${localStorage.getItem('token')}`,
          },
        }
      );

      const data = await response.json();
      setPreviewTemplate(data);
    } catch (error) {
      console.error('Error fetching template details:', error);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center p-8">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  return (
    <div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {templates.map((template) => (
          <div
            key={template.template_name}
            onClick={() => onSelect(template.template_name)}
            className={`relative p-6 rounded-lg border-2 cursor-pointer transition-all ${
              selectedTemplate === template.template_name
                ? 'border-blue-500 bg-blue-500/10'
                : 'border-gray-700 hover:border-gray-600 bg-[#0f0f0f]'
            }`}
          >
            {/* Selection Indicator */}
            {selectedTemplate === template.template_name && (
              <div className="absolute top-4 right-4">
                <CheckCircle2 className="w-5 h-5 text-blue-500" />
              </div>
            )}

            {/* Template Info */}
            <div className="flex items-start gap-4">
              <div className="p-3 bg-gray-800 rounded-lg">
                <FileText className="w-6 h-6 text-blue-500" />
              </div>
              <div className="flex-1">
                <h3 className="text-white font-semibold mb-1">
                  {template.display_name}
                </h3>
                <p className="text-gray-400 text-sm mb-3">
                  {template.description}
                </p>

                {/* Template Details */}
                <div className="space-y-2">
                  {/* Supported Formats */}
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-gray-500">Formats:</span>
                    <div className="flex gap-1">
                      {template.supported_formats?.map((format) => (
                        <span
                          key={format}
                          className="px-2 py-0.5 bg-gray-800 text-gray-400 text-xs rounded uppercase"
                        >
                          {format}
                        </span>
                      ))}
                    </div>
                  </div>

                  {/* Default Sections */}
                  {template.default_sections && template.default_sections.length > 0 && (
                    <div className="flex items-start gap-2">
                      <span className="text-xs text-gray-500">Sections:</span>
                      <div className="flex flex-wrap gap-1">
                        {template.default_sections.slice(0, 3).map((section) => (
                          <span
                            key={section}
                            className="px-2 py-0.5 bg-gray-800/50 text-gray-500 text-xs rounded"
                          >
                            {section.replace('_', ' ')}
                          </span>
                        ))}
                        {template.default_sections.length > 3 && (
                          <span className="px-2 py-0.5 text-gray-500 text-xs">
                            +{template.default_sections.length - 3} more
                          </span>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Is Default Badge */}
                  {template.is_default && (
                    <div className="inline-flex items-center gap-1 px-2 py-1 bg-green-500/10 text-green-500 text-xs rounded">
                      <CheckCircle2 className="w-3 h-3" />
                      Default Template
                    </div>
                  )}
                </div>

                {/* Preview Button */}
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    handlePreview(template.template_name);
                  }}
                  className="mt-4 flex items-center gap-2 text-sm text-blue-500 hover:text-blue-400 transition-colors"
                >
                  <Eye className="w-4 h-4" />
                  Preview Template
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Template Preview Modal */}
      {previewTemplate && (
        <div
          className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4"
          onClick={() => setPreviewTemplate(null)}
        >
          <div
            className="bg-[#1a1a1a] rounded-lg border border-gray-800 w-full max-w-3xl max-h-[80vh] overflow-y-auto"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Preview Header */}
            <div className="p-6 border-b border-gray-800">
              <h3 className="text-xl font-bold text-white mb-2">
                {previewTemplate.display_name}
              </h3>
              <p className="text-gray-400 text-sm">
                {previewTemplate.description}
              </p>
            </div>

            {/* Preview Content */}
            <div className="p-6 space-y-6">
              {/* Template Metadata */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <div className="text-sm text-gray-500 mb-1">Report Type</div>
                  <div className="text-white capitalize">
                    {previewTemplate.report_type}
                  </div>
                </div>
                <div>
                  <div className="text-sm text-gray-500 mb-1">Supported Formats</div>
                  <div className="flex gap-2">
                    {previewTemplate.supported_formats?.map((format) => (
                      <span
                        key={format}
                        className="px-2 py-1 bg-gray-800 text-gray-400 text-xs rounded uppercase"
                      >
                        {format}
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              {/* Default Sections */}
              {previewTemplate.default_sections && (
                <div>
                  <div className="text-sm text-gray-500 mb-2">Default Sections</div>
                  <div className="space-y-2">
                    {previewTemplate.default_sections.map((section, index) => (
                      <div
                        key={section}
                        className="flex items-center gap-3 p-3 bg-[#0f0f0f] rounded-lg"
                      >
                        <span className="flex items-center justify-center w-6 h-6 bg-blue-500/20 text-blue-500 text-xs rounded">
                          {index + 1}
                        </span>
                        <span className="text-white capitalize">
                          {section.replace(/_/g, ' ')}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Customizable Sections */}
              {previewTemplate.customizable_sections && previewTemplate.customizable_sections.length > 0 && (
                <div>
                  <div className="text-sm text-gray-500 mb-2">Customizable Sections</div>
                  <div className="flex flex-wrap gap-2">
                    {previewTemplate.customizable_sections.map((section) => (
                      <span
                        key={section}
                        className="px-3 py-1.5 bg-blue-500/10 text-blue-500 text-sm rounded capitalize"
                      >
                        {section.replace(/_/g, ' ')}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Template Options */}
              {previewTemplate.template_options && Object.keys(previewTemplate.template_options).length > 0 && (
                <div>
                  <div className="text-sm text-gray-500 mb-2">Template Options</div>
                  <div className="space-y-2">
                    {Object.entries(previewTemplate.template_options).map(([key, value]) => (
                      <div
                        key={key}
                        className="flex items-center justify-between p-3 bg-[#0f0f0f] rounded-lg"
                      >
                        <span className="text-white capitalize">
                          {key.replace(/_/g, ' ')}
                        </span>
                        <span className="text-gray-400 text-sm">
                          {typeof value === 'object' ? value.type : String(value)}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Preview Footer */}
            <div className="p-6 border-t border-gray-800 flex justify-end gap-3">
              <button
                onClick={() => setPreviewTemplate(null)}
                className="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-white rounded-lg transition-colors"
              >
                Close
              </button>
              <button
                onClick={() => {
                  onSelect(previewTemplate.template_name);
                  setPreviewTemplate(null);
                }}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
              >
                Use This Template
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
