'use client';

import { motion } from 'framer-motion';
import {
  Maximize2,
  Minimize2,
  Search,
  User,
  Settings,
  LogOut
} from 'lucide-react';
import { useLayoutStore } from '@/store/layout';
import { cn } from '@/lib/utils';
import { NotificationButton } from '@/components/notifications';
import { useWebSocket } from '@/hooks/useWebSocket';
import { useAuth } from '@/contexts/AuthContext';
import { useLogout } from '@/hooks/api/useAuth';
import { toast } from 'sonner';

export function TopBar() {
  const {
    leftSidebarCollapsed,
    rightSidebarCollapsed,
    activeSection,
    collapseAll,
    expandAll
  } = useLayoutStore();

  const { isConnected } = useWebSocket();
  const { user } = useAuth();
  const logoutMutation = useLogout();
  const allCollapsed = leftSidebarCollapsed && rightSidebarCollapsed;

  const handleLogout = async () => {
    try {
      await logoutMutation.mutateAsync();
      toast.success('Logged out successfully');
    } catch (error) {
      toast.error('Logout failed');
    }
  };

  const getSectionTitle = () => {
    switch (activeSection) {
      case 'dashboard':
        return 'Dashboard';
      case 'targets':
        return 'Target Management';
      case 'framework':
        return 'Automation Framework';
      case 'results':
        return 'Scan Results';
      case 'reports':
        return 'Security Reports';
      default:
        return 'Bug Hunt Framework';
    }
  };

  return (
    <div className="relative h-20 bg-gray-900 rounded-xl flex items-center justify-between px-4 my-4">
      {/* Left section */}
      <div className="flex flex-row justify-center pl-8">
        <h1 className="text-4xl font-bold text-white pl-10 pr-6">
          {getSectionTitle()}
        </h1>
      </div>

      {/* Center section - Search */}
      <div className="flex-1 max-w-md pl-80">
        <div className="relative">
          <input
            type="text"
            placeholder="Search targets, vulnerabilities, reports..."
            className="w-full pl-10 pr-10 py-2 bg-gray-600 rounded-lg text-white placeholder-gray-775 focus:outline-none focus:ring-1 focus:ring-red-500 shadow-md"
          />
          <Search className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-775 w-4 h-4" />
        </div>
      </div>

      {/* Right section */}
      <div className="flex items-center space-x-3 pr-12">

      {/* Connection status - positioned at bottom */}
      <div className="absolute bottom-1 left-52 text-xs bg-gray-600 p-4 rounded flex items-center gap-2">
        <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-green-500 animate-pulse' : 'bg-gray-500'}`} />
        <span className={isConnected ? 'text-green-400' : 'text-gray-400'}>
          {isConnected ? 'Live Updates Active' : 'Connecting...'}
        </span>
      </div>

        {/* Notifications */}
        <NotificationButton />

        {/* Sidebar toggle */}
        <button
          onClick={allCollapsed ? expandAll : collapseAll}
          className="p-3 text-gray-500 hover:text-white hover:bg-gray-800 rounded-lg transition-colors"
          title={allCollapsed ? 'Expand sidebars' : 'Collapse sidebars'}
        >
          {allCollapsed ? (
            <Maximize2 className="w-6 h-6" />
          ) : (
            <Minimize2 className="w-6 h-6" />
          )}
        </button>

        {/* User menu */}
        <div className="flex justify-center space-x-2">
          <div className="text-center p-2">
            <div className="text-lg text-white font-medium">
              {user ? `${user.first_name || ''} ${user.last_name || ''}`.trim() || user.email : 'Researcher'}
            </div>
            <div className="text-xs text-gray-400">
              {user?.role ? user.role.charAt(0).toUpperCase() + user.role.slice(1) : 'Active Session'}
            </div>
          </div>

          <div className="relative group">
            <button className="mr-10 p-2 text-gray-400 hover:text-white hover:bg-gray-800 rounded-lg transition-colors">
              <User className="w-8 h-8 pt-2" />
            </button>

            {/* Dropdown menu */}
            <div className="absolute right-1 mt-2 w-40 bg-gray-600 border border-gray-700 rounded-lg shadow-lg opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 z-50">
              <div className="py-1">
                <a
                  href="/profile"
                  className="flex items-center px-4 py-2 text-sm text-gray-300 opacity-50 hover:opacity-90 hover:bg-gray-500 hover:text-white"
                >
                  <User className="w-4 h-4 mr-2" />
                  Profile
                </a>
                <a
                  href="/settings"
                  className="flex items-center px-4 py-2 text-sm text-gray-300 opacity-50 hover:opacity-90 hover:bg-gray-500 hover:text-white"
                >
                  <Settings className="w-4 h-4 mr-2" />
                  Settings
                </a>
                <button
                  onClick={handleLogout}
                  disabled={logoutMutation.isPending}
                  className="w-full flex items-center px-4 py-2 text-sm text-gray-300 opacity-50 hover:opacity-90 hover:bg-gray-500 hover:text-white disabled:opacity-25"
                >
                  <LogOut className="w-4 h-4 mr-2" />
                  {logoutMutation.isPending ? 'Signing out...' : 'Sign Out'}
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}