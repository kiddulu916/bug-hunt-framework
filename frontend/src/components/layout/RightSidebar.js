'use client';

import { motion } from 'framer-motion';
import {
  Bell,
  Activity,
  Clock,
  AlertTriangle,
  CheckCircle,
  XCircle,
  ChevronLeft,
  ChevronRight,
  X
} from 'lucide-react';
import { useLayoutStore } from '@/store/layout';
import { cn } from '@/lib/utils';

// Mock notifications data
const notifications = [
  {
    id: 1,
    type: 'critical',
    title: 'SQL Injection Found',
    description: 'example.com login form',
    time: '2 min ago',
    icon: XCircle,
    color: 'text-red-500'
  },
  {
    id: 2,
    type: 'success',
    title: 'Scan Completed',
    description: 'testsite.org scan finished: 5 vulnerabilities',
    time: '7/10/2024',
    icon: CheckCircle,
    color: 'text-green-500'
  },
  {
    id: 3,
    type: 'info',
    title: 'New Target Added',
    description: 'webapp.net has been added to the target list',
    time: '7/10/2024',
    icon: Activity,
    color: 'text-blue-500'
  }
];

const activityItems = [
  {
    id: 1,
    action: 'Target testsite.org scan finished',
    detail: '5 vulnerabilities found',
    time: '7/10/2024'
  },
  {
    id: 2,
    action: 'Framework configuration updated',
    detail: 'Added custom headers for authentication',
    time: '7/10/2024'
  }
];

export function RightSidebar() {
  const { rightSidebarCollapsed, toggleRightSidebar } = useLayoutStore();

  return (
    <motion.div
      initial={false}
      animate={{
        width: rightSidebarCollapsed ? '1.5rem' : '16rem'
      }}
      transition={{ duration: 0.3, ease: 'easeInOut' }}
      className="relative h-full bg-gray-900 border-l mt-2 border-gray-800 flex flex-col"
    >
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-gray-800">
        <button
          onClick={toggleRightSidebar}
          className="p-1 rounded-md hover:bg-gray-800 text-gray-400 hover:text-white transition-colors"
        >
          {rightSidebarCollapsed ? (
            <ChevronLeft className="w-4 h-4" />
          ) : (
            <ChevronRight className="w-4 h-4" />
          )}
        </button>

        <motion.div
          initial={false}
          animate={{
            opacity: rightSidebarCollapsed ? 0 : 1,
            scale: rightSidebarCollapsed ? 0.8 : 1
          }}
          transition={{ duration: 0.2 }}
          className="flex items-center space-x-2"
        >
          {!rightSidebarCollapsed && (
            <>
              <Bell className="w-5 h-5 text-yellow-500" />
              <span className="font-semibold text-white">Notifications</span>
              <span className="bg-red-600 text-white text-xs px-2 py-1 rounded-full">
                {notifications.length}
              </span>
            </>
          )}
        </motion.div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-hidden">
        <motion.div
          initial={false}
          animate={{
            opacity: rightSidebarCollapsed ? 0 : 1,
            x: rightSidebarCollapsed ? 20 : 0
          }}
          transition={{ duration: 0.2 }}
          className="h-full overflow-y-auto"
        >
          {!rightSidebarCollapsed && (
            <div className="p-4 space-y-6">
              {/* Notifications Section */}
              <div className="m-2">
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wide">
                    Recent Alerts
                  </h3>
                  <button className="text-xs text-gray-500 hover:text-gray-300">
                    Clear All
                  </button>
                </div>

                <div className="space-y-3">
                  {notifications.map((notification) => {
                    const Icon = notification.icon;
                    return (
                      <div
                        key={notification.id}
                        className="bg-gray-800 rounded-lg p-3 m-2 hover:bg-gray-750 transition-colors group"
                      >
                        <div className="flex items-start space-y-2 space-x-3">
                          <Icon className={cn('w-5 h-5 mt-0.5', notification.color)} />
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center justify-between">
                              <p className="text-sm font-medium text-white truncate">
                                {notification.title}
                              </p>
                              <button className="opacity-0 group-hover:opacity-100 text-gray-500 hover:text-gray-300">
                                <X className="w-4 h-4" />
                              </button>
                            </div>
                            <p className="text-xs text-gray-400 mt-1">
                              {notification.description}
                            </p>
                            <div className="flex items-center text-xs text-gray-500">
                              <Clock className="w-3 h-3 mr-1" />
                              {notification.time}
                            </div>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Activity Section */}
              <div className="m-2">
                <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wide mb-3">
                  Recent Activity
                </h3>

                <div className="space-y-3">
                  {activityItems.map((item) => (
                    <div
                      key={item.id}
                      className="bg-gray-800 space-y-2 rounded-lg p-3"
                    >
                      <p className="text-sm text-white">{item.action}</p>
                      <p className="text-xs text-gray-400 mt-1">{item.detail}</p>
                      <div className="flex items-center mt-2 text-xs text-gray-500">
                        <Clock className="w-3 h-3 mr-1" />
                        {item.time}
                      </div>
                    </div>
                  ))}
                </div>

                <button className="w-full mt-3 text-sm text-gray-400 hover:text-white text-center py-2 hover:bg-gray-800 rounded-lg transition-colors">
                  Show All (4)
                </button>
              </div>
            </div>
          )}
        </motion.div>

        {/* Collapsed state icon */}
        {rightSidebarCollapsed && (
          <div className="flex flex-col items-center pt-4 space-y-4">
            <div className="relative">
              <Bell className="w-6 h-6 text-yellow-500" />
              <span className="absolute -top-1 -right-1 bg-red-600 text-white text-xs w-4 h-4 rounded-full flex items-center justify-center">
                {notifications.length}
              </span>
            </div>
            <Activity className="w-6 h-6 text-gray-400" />
          </div>
        )}
      </div>
    </motion.div>
  );
}