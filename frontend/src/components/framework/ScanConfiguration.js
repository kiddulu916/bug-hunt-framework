'use client';

import { useState } from 'react';
import { Settings, Activity, Zap, Shield, ChevronDown, ChevronUp, Info } from 'lucide-react';
import { cn } from '@/lib/utils';

export function ScanConfiguration() {
  const [expandedSection, setExpandedSection] = useState('tools');
  const [config, setConfig] = useState({
    // Tool Selection
    tools: {
      nuclei: true,
      custom_web: true,
      custom_api: true,
      custom_infra: true,
    },
    // Phase Configuration
    phases: {
      reconnaissance: {
        enabled: true,
        passive_only: false,
        max_subdomains: 1000,
        max_endpoints: 5000,
        port_scan_top_ports: 1000,
        enable_service_detection: true,
        enable_technology_detection: true,
        enable_certificate_transparency: true,
        enable_search_engines: true,
        enable_web_crawling: true,
        crawl_depth: 3,
        wordlist_size: 'medium',
        timeout_seconds: 30,
      },
      exploitation: {
        enabled: true,
        auto_exploit: false,
        max_concurrent_exploits: 3,
        exploit_timeout: 60,
        safe_mode: true,
      },
    },
    // Rate Limiting & Concurrency
    performance: {
      max_concurrent_scans: 5,
      requests_per_second: 10,
      max_threads: 10,
      enable_rate_limiting: true,
      respect_robots_txt: true,
      user_agent: 'BugHuntFramework/1.0',
    },
  });

  const toggleSection = (section) => {
    setExpandedSection(expandedSection === section ? null : section);
  };

  const updateConfig = (section, key, value) => {
    setConfig((prev) => ({
      ...prev,
      [section]: {
        ...prev[section],
        [key]: value,
      },
    }));
  };

  const updatePhaseConfig = (phase, key, value) => {
    setConfig((prev) => ({
      ...prev,
      phases: {
        ...prev.phases,
        [phase]: {
          ...prev.phases[phase],
          [key]: value,
        },
      },
    }));
  };

  const ConfigSection = ({ id, title, icon: Icon, children }) => {
    const isExpanded = expandedSection === id;

    return (
      <div className="bg-[#1a1a1a] rounded-lg border border-gray-800 overflow-hidden">
        <button
          onClick={() => toggleSection(id)}
          className="w-full flex items-center justify-between p-4 hover:bg-gray-800/50 transition-colors"
        >
          <div className="flex items-center gap-3">
            <Icon className="w-5 h-5 text-red-500" />
            <h3 className="text-white font-medium">{title}</h3>
          </div>
          {isExpanded ? (
            <ChevronUp className="w-5 h-5 text-gray-400" />
          ) : (
            <ChevronDown className="w-5 h-5 text-gray-400" />
          )}
        </button>

        {isExpanded && (
          <div className="p-4 pt-0 border-t border-gray-800/50">{children}</div>
        )}
      </div>
    );
  };

  const Toggle = ({ enabled, onChange, label, description }) => (
    <div className="flex items-start justify-between py-3">
      <div className="flex-1">
        <label className="text-white text-sm font-medium">{label}</label>
        {description && <p className="text-gray-500 text-xs mt-1">{description}</p>}
      </div>
      <button
        onClick={() => onChange(!enabled)}
        className={cn(
          'relative inline-flex h-6 w-11 items-center rounded-full transition-colors',
          enabled ? 'bg-red-600' : 'bg-gray-700'
        )}
      >
        <span
          className={cn(
            'inline-block h-4 w-4 transform rounded-full bg-white transition-transform',
            enabled ? 'translate-x-6' : 'translate-x-1'
          )}
        />
      </button>
    </div>
  );

  const NumberInput = ({ label, value, onChange, min, max, step = 1, unit = '' }) => (
    <div className="py-3">
      <label className="text-white text-sm font-medium block mb-2">{label}</label>
      <div className="flex items-center gap-2">
        <input
          type="number"
          value={value}
          onChange={(e) => onChange(parseInt(e.target.value) || 0)}
          min={min}
          max={max}
          step={step}
          className="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-white text-sm w-32 focus:outline-none focus:border-red-500"
        />
        {unit && <span className="text-gray-400 text-sm">{unit}</span>}
      </div>
    </div>
  );

  const Select = ({ label, value, onChange, options }) => (
    <div className="py-3">
      <label className="text-white text-sm font-medium block mb-2">{label}</label>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-white text-sm w-full focus:outline-none focus:border-red-500"
      >
        {options.map((opt) => (
          <option key={opt.value} value={opt.value}>
            {opt.label}
          </option>
        ))}
      </select>
    </div>
  );

  return (
    <div className="space-y-4">
      {/* Tool Selection */}
      <ConfigSection id="tools" title="Scanner Tools" icon={Shield}>
        <div className="space-y-1">
          <Toggle
            enabled={config.tools.nuclei}
            onChange={(val) => updateConfig('tools', 'nuclei', val)}
            label="Nuclei Engine"
            description="Template-based vulnerability scanner with 1000+ built-in checks"
          />
          <Toggle
            enabled={config.tools.custom_web}
            onChange={(val) => updateConfig('tools', 'custom_web', val)}
            label="Custom Web Scanner"
            description="Advanced web application security testing"
          />
          <Toggle
            enabled={config.tools.custom_api}
            onChange={(val) => updateConfig('tools', 'custom_api', val)}
            label="Custom API Scanner"
            description="REST API and GraphQL security testing"
          />
          <Toggle
            enabled={config.tools.custom_infra}
            onChange={(val) => updateConfig('tools', 'custom_infra', val)}
            label="Custom Infrastructure Scanner"
            description="Network and infrastructure vulnerability assessment"
          />
        </div>
      </ConfigSection>

      {/* Reconnaissance Phase */}
      <ConfigSection id="recon" title="Reconnaissance Phase" icon={Activity}>
        <div className="space-y-1">
          <Toggle
            enabled={config.phases.reconnaissance.enabled}
            onChange={(val) => updatePhaseConfig('reconnaissance', 'enabled', val)}
            label="Enable Reconnaissance"
            description="Discover attack surface before exploitation"
          />

          {config.phases.reconnaissance.enabled && (
            <>
              <div className="border-t border-gray-800 my-3" />
              <Toggle
                enabled={config.phases.reconnaissance.passive_only}
                onChange={(val) => updatePhaseConfig('reconnaissance', 'passive_only', val)}
                label="Passive Only Mode"
                description="Only perform passive reconnaissance (no active scanning)"
              />

              <NumberInput
                label="Max Subdomains"
                value={config.phases.reconnaissance.max_subdomains}
                onChange={(val) => updatePhaseConfig('reconnaissance', 'max_subdomains', val)}
                min={1}
                max={10000}
              />

              <NumberInput
                label="Max Endpoints"
                value={config.phases.reconnaissance.max_endpoints}
                onChange={(val) => updatePhaseConfig('reconnaissance', 'max_endpoints', val)}
                min={1}
                max={50000}
              />

              <NumberInput
                label="Port Scan Top Ports"
                value={config.phases.reconnaissance.port_scan_top_ports}
                onChange={(val) => updatePhaseConfig('reconnaissance', 'port_scan_top_ports', val)}
                min={1}
                max={65535}
              />

              <Select
                label="Wordlist Size"
                value={config.phases.reconnaissance.wordlist_size}
                onChange={(val) => updatePhaseConfig('reconnaissance', 'wordlist_size', val)}
                options={[
                  { value: 'small', label: 'Small (Fast)' },
                  { value: 'medium', label: 'Medium (Balanced)' },
                  { value: 'large', label: 'Large (Thorough)' },
                ]}
              />

              <NumberInput
                label="Crawl Depth"
                value={config.phases.reconnaissance.crawl_depth}
                onChange={(val) => updatePhaseConfig('reconnaissance', 'crawl_depth', val)}
                min={1}
                max={10}
              />

              <NumberInput
                label="Timeout"
                value={config.phases.reconnaissance.timeout_seconds}
                onChange={(val) => updatePhaseConfig('reconnaissance', 'timeout_seconds', val)}
                min={5}
                max={300}
                unit="seconds"
              />

              <div className="border-t border-gray-800 my-3" />

              <Toggle
                enabled={config.phases.reconnaissance.enable_service_detection}
                onChange={(val) => updatePhaseConfig('reconnaissance', 'enable_service_detection', val)}
                label="Service Detection"
              />

              <Toggle
                enabled={config.phases.reconnaissance.enable_technology_detection}
                onChange={(val) => updatePhaseConfig('reconnaissance', 'enable_technology_detection', val)}
                label="Technology Detection"
              />

              <Toggle
                enabled={config.phases.reconnaissance.enable_certificate_transparency}
                onChange={(val) => updatePhaseConfig('reconnaissance', 'enable_certificate_transparency', val)}
                label="Certificate Transparency"
              />

              <Toggle
                enabled={config.phases.reconnaissance.enable_search_engines}
                onChange={(val) => updatePhaseConfig('reconnaissance', 'enable_search_engines', val)}
                label="Search Engine Dorking"
              />

              <Toggle
                enabled={config.phases.reconnaissance.enable_web_crawling}
                onChange={(val) => updatePhaseConfig('reconnaissance', 'enable_web_crawling', val)}
                label="Web Crawling"
              />
            </>
          )}
        </div>
      </ConfigSection>

      {/* Exploitation Phase */}
      <ConfigSection id="exploit" title="Exploitation Phase" icon={Zap}>
        <div className="space-y-1">
          <Toggle
            enabled={config.phases.exploitation.enabled}
            onChange={(val) => updatePhaseConfig('exploitation', 'enabled', val)}
            label="Enable Exploitation"
            description="Automatically exploit discovered vulnerabilities"
          />

          {config.phases.exploitation.enabled && (
            <>
              <div className="border-t border-gray-800 my-3" />
              <Toggle
                enabled={config.phases.exploitation.auto_exploit}
                onChange={(val) => updatePhaseConfig('exploitation', 'auto_exploit', val)}
                label="Auto-Exploit Vulnerabilities"
                description="Automatically attempt exploitation of findings"
              />

              <Toggle
                enabled={config.phases.exploitation.safe_mode}
                onChange={(val) => updatePhaseConfig('exploitation', 'safe_mode', val)}
                label="Safe Mode"
                description="Prevent destructive exploitation attempts"
              />

              <NumberInput
                label="Max Concurrent Exploits"
                value={config.phases.exploitation.max_concurrent_exploits}
                onChange={(val) => updatePhaseConfig('exploitation', 'max_concurrent_exploits', val)}
                min={1}
                max={10}
              />

              <NumberInput
                label="Exploit Timeout"
                value={config.phases.exploitation.exploit_timeout}
                onChange={(val) => updatePhaseConfig('exploitation', 'exploit_timeout', val)}
                min={10}
                max={300}
                unit="seconds"
              />
            </>
          )}
        </div>
      </ConfigSection>

      {/* Performance & Rate Limiting */}
      <ConfigSection id="performance" title="Performance & Rate Limiting" icon={Settings}>
        <div className="space-y-1">
          <NumberInput
            label="Max Concurrent Scans"
            value={config.performance.max_concurrent_scans}
            onChange={(val) => updateConfig('performance', 'max_concurrent_scans', val)}
            min={1}
            max={20}
          />

          <NumberInput
            label="Requests Per Second"
            value={config.performance.requests_per_second}
            onChange={(val) => updateConfig('performance', 'requests_per_second', val)}
            min={1}
            max={100}
          />

          <NumberInput
            label="Max Threads"
            value={config.performance.max_threads}
            onChange={(val) => updateConfig('performance', 'max_threads', val)}
            min={1}
            max={50}
          />

          <div className="border-t border-gray-800 my-3" />

          <Toggle
            enabled={config.performance.enable_rate_limiting}
            onChange={(val) => updateConfig('performance', 'enable_rate_limiting', val)}
            label="Enable Rate Limiting"
            description="Prevent overwhelming target servers"
          />

          <Toggle
            enabled={config.performance.respect_robots_txt}
            onChange={(val) => updateConfig('performance', 'respect_robots_txt', val)}
            label="Respect robots.txt"
            description="Follow robots.txt directives"
          />

          <div className="py-3">
            <label className="text-white text-sm font-medium block mb-2">User Agent</label>
            <input
              type="text"
              value={config.performance.user_agent}
              onChange={(e) => updateConfig('performance', 'user_agent', e.target.value)}
              className="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-white text-sm w-full focus:outline-none focus:border-red-500"
            />
          </div>
        </div>
      </ConfigSection>

      {/* Save Configuration */}
      <div className="flex items-center justify-between bg-[#1a1a1a] rounded-lg border border-gray-800 p-4">
        <div className="flex items-center gap-2 text-blue-400">
          <Info className="w-4 h-4" />
          <span className="text-sm">Configuration will be saved per scan session</span>
        </div>
        <button
          onClick={() => console.log('Save config:', config)}
          className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors font-medium text-sm"
        >
          Save as Default
        </button>
      </div>
    </div>
  );
}
