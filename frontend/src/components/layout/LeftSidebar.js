'use client';

import { motion } from 'framer-motion';
import {
  LayoutDashboard,
  Target,
  Settings2,
  BarChart3,
  FileText,
  ChevronLeft,
  ChevronRight,
  Bug
} from 'lucide-react';
import { useLayoutStore } from '@/store/layout';
import { cn } from '@/lib/utils';

const navigationItems = [
  {
    id: 'dashboard',
    label: 'Dashboard',
    icon: LayoutDashboard,
    description: 'Overview & Metrics'
  },
  {
    id: 'targets',
    label: 'Targets',
    icon: Target,
    description: 'Target Profiles'
  },
  {
    id: 'framework',
    label: 'Framework',
    icon: Settings2,
    description: 'Automation & Tools'
  },
  {
    id: 'results',
    label: 'Results',
    icon: BarChart3,
    description: 'Scan Results & Vulnerabilities'
  },
  {
    id: 'reports',
    label: 'Reports',
    icon: FileText,
    description: 'Security Reports & Export'
  }
];

export function LeftSidebar() {
  const {
    leftSidebarCollapsed,
    activeSection,
    toggleLeftSidebar,
    setActiveSection
  } = useLayoutStore();

  return (
    <motion.div
      initial={false}
      animate={{
        width: leftSidebarCollapsed ? '1.5rem' : '8rem'
      }}
      transition={{ duration: 0.3, ease: 'easeInOut' }}
      className="relative h-full bg-gray-900 border-r border-gray-800 flex flex-col"
    >
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-gray-800">
        <motion.div
          initial={false}
          animate={{
            opacity: leftSidebarCollapsed ? 0 : 1,
            scale: leftSidebarCollapsed ? 0.8 : 1
          }}
          transition={{ duration: 0.2 }}
          className="flex items-center space-x-2"
        >
          {!leftSidebarCollapsed && (
            <>
              <Bug className="w-6 h-6 pl-2 text-red-500" />
              <span className="font-bold text-white text-lg">B.H.F</span>
            </>
          )}
        </motion.div>

        <button
          onClick={toggleLeftSidebar}
          className="p-1 rounded-md hover:bg-gray-800 text-gray-400 hover:text-white transition-colors"
        >
          {leftSidebarCollapsed ? (
            <ChevronRight className="w-4 h-4" />
          ) : (
            <ChevronLeft className="w-4 h-4" />
          )}
        </button>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-2 ml-2 space-y-1">
        {navigationItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeSection === item.id;

          return (
            <button
              key={item.id}
              onClick={() => setActiveSection(item.id)}
              className={cn(
                'w-full flex items-center px-3 mt-2 py-2 rounded-lg text-left transition-colors relative group',
                isActive
                  ? 'bg-red-600 text-white'
                  : 'text-gray-300 hover:bg-gray-800 hover:text-white'
              )}
            >
              <Icon className="w-5 h-5 ml-2 flex-shrink-0" />

              <motion.span
                initial={false}
                animate={{
                  opacity: leftSidebarCollapsed ? 0 : 1,
                  x: leftSidebarCollapsed ? -10 : 0
                }}
                transition={{ duration: 0.2 }}
                className="ml-3 font-medium whitespace-nowrap overflow-hidden"
              >
                {item.label}
              </motion.span>

              {/* Tooltip for collapsed state */}
              {leftSidebarCollapsed && (
                <div className="absolute left-full ml-2 px-2 py-1 bg-gray-800 text-white text-sm rounded-md opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap z-50 pointer-events-none">
                  <div className="font-medium">{item.label}</div>
                  <div className="text-xs text-gray-400">{item.description}</div>
                </div>
              )}
            </button>
          );
        })}
      </nav>

      {/* Footer */}
      <motion.div
        initial={false}
        animate={{
          opacity: leftSidebarCollapsed ? 0 : 1
        }}
        transition={{ duration: 0.2 }}
        className="p-4 border-t border-gray-800"
      >
        {!leftSidebarCollapsed && (
          <div className="text-xs text-gray-500 text-center">
            Bug Hunt Framework v1.0
          </div>
        )}
      </motion.div>
    </motion.div>
  );
}