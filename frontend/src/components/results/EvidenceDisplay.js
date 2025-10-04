'use client';

import { useState } from 'react';
import { Image as ImageIcon, Code, FileText, ExternalLink, Download, ChevronDown } from 'lucide-react';

export function EvidenceDisplay({ evidence }) {
  const [expandedItems, setExpandedItems] = useState(new Set());

  const toggleExpanded = (index) => {
    const newExpanded = new Set(expandedItems);
    if (newExpanded.has(index)) {
      newExpanded.delete(index);
    } else {
      newExpanded.add(index);
    }
    setExpandedItems(newExpanded);
  };

  const getEvidenceIcon = (type) => {
    switch (type) {
      case 'screenshot':
      case 'image':
        return ImageIcon;
      case 'request':
      case 'response':
      case 'code':
        return Code;
      default:
        return FileText;
    }
  };

  const getEvidenceTypeLabel = (type) => {
    const labels = {
      screenshot: 'Screenshot',
      request: 'HTTP Request',
      response: 'HTTP Response',
      code: 'Code Snippet',
      image: 'Image',
      text: 'Text',
      log: 'Log Output',
    };
    return labels[type] || 'Evidence';
  };

  const renderEvidenceContent = (item, index) => {
    const isExpanded = expandedItems.has(index);

    switch (item.type) {
      case 'screenshot':
      case 'image':
        return (
          <div className="bg-[#0f0f0f] border border-gray-800 rounded-lg p-3">
            <img
              src={item.url || item.data}
              alt={item.description || 'Evidence screenshot'}
              className="max-w-full rounded border border-gray-700"
            />
            {item.description && (
              <p className="text-sm text-gray-400 mt-2">{item.description}</p>
            )}
          </div>
        );

      case 'request':
      case 'response':
      case 'code':
        return (
          <div className="bg-[#0f0f0f] border border-gray-800 rounded-lg overflow-hidden">
            <div
              className="flex items-center justify-between px-4 py-2 bg-gray-900/50 cursor-pointer"
              onClick={() => toggleExpanded(index)}
            >
              <span className="text-xs text-gray-400 uppercase tracking-wide font-medium">
                {getEvidenceTypeLabel(item.type)}
              </span>
              <ChevronDown
                className={`w-4 h-4 text-gray-400 transition-transform ${
                  isExpanded ? 'rotate-180' : ''
                }`}
              />
            </div>
            {isExpanded && (
              <div className="p-3 max-h-96 overflow-auto">
                <pre className="text-xs text-gray-300 font-mono whitespace-pre-wrap">
                  {item.content || item.data}
                </pre>
              </div>
            )}
          </div>
        );

      case 'text':
      case 'log':
        return (
          <div className="bg-[#0f0f0f] border border-gray-800 rounded-lg p-4">
            <pre className="text-sm text-gray-300 whitespace-pre-wrap font-mono">
              {item.content || item.data}
            </pre>
          </div>
        );

      case 'url':
        return (
          <div className="bg-[#0f0f0f] border border-gray-800 rounded-lg p-4">
            <a
              href={item.url}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-2 text-blue-400 hover:text-blue-300 transition-colors"
            >
              <ExternalLink className="w-4 h-4" />
              <span className="font-mono text-sm break-all">{item.url}</span>
            </a>
            {item.description && (
              <p className="text-sm text-gray-400 mt-2">{item.description}</p>
            )}
          </div>
        );

      default:
        return (
          <div className="bg-[#0f0f0f] border border-gray-800 rounded-lg p-4">
            <p className="text-sm text-gray-300">{item.content || item.data || 'No content available'}</p>
          </div>
        );
    }
  };

  if (!evidence || evidence.length === 0) {
    return (
      <div className="bg-[#1a1a1a] border border-gray-800 rounded-lg p-6 text-center">
        <FileText className="w-8 h-8 text-gray-600 mx-auto mb-2" />
        <p className="text-gray-500 text-sm">No evidence available</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {evidence.map((item, index) => {
        const Icon = getEvidenceIcon(item.type);

        return (
          <div key={index} className="bg-[#1a1a1a] border border-gray-800 rounded-lg p-4">
            {/* Evidence Header */}
            <div className="flex items-center gap-3 mb-3">
              <div className="p-2 bg-blue-900/20 rounded">
                <Icon className="w-4 h-4 text-blue-400" />
              </div>
              <div className="flex-1">
                <h5 className="text-sm font-medium text-white">
                  {item.title || getEvidenceTypeLabel(item.type)}
                </h5>
                {item.timestamp && (
                  <p className="text-xs text-gray-500 mt-0.5">
                    {new Date(item.timestamp).toLocaleString()}
                  </p>
                )}
              </div>
              {item.file_url && (
                <a
                  href={item.file_url}
                  download
                  className="p-2 bg-gray-800 hover:bg-gray-700 rounded transition-colors"
                  title="Download evidence"
                >
                  <Download className="w-4 h-4 text-gray-400" />
                </a>
              )}
            </div>

            {/* Evidence Content */}
            {renderEvidenceContent(item, index)}
          </div>
        );
      })}
    </div>
  );
}
