'use client';

import { LeftSidebar } from './LeftSidebar';
import { RightSidebar } from './RightSidebar';
import { TopBar } from './TopBar';
import { useLayoutStore } from '@/store/layout';
import { NotificationCenter } from '@/components/notifications';

export function MainLayout({ children }) {
  const { leftSidebarCollapsed, rightSidebarCollapsed } = useLayoutStore();

  return (
    <div className="h-screen bg-gray-900 flex flex-col overflow-hidden">
      {/* Top Bar - Responsive */}
      <TopBar className="mb-2 md:mb-3 mt-2 md:mt-3" />

      {/* Main Content Area - Responsive Layout */}
      <div className="flex-1 flex overflow-hidden gap-2 md:gap-3 px-2 md:px-3 pb-2 md:pb-3 bg-gray-800">
        {/* Left Sidebar - Hidden on mobile unless expanded */}
        <LeftSidebar className="hidden md:block" />

        {/* Main Content - Full width on mobile */}
        <main className="flex-1 overflow-auto bg-gray-800">
          <div className="h-full p-3 md:p-4 lg:p-6">
            {children}
          </div>
        </main>

        {/* Right Sidebar - Hidden on mobile and tablet */}
        <RightSidebar className="hidden lg:block" />
      </div>

      {/* Notification Center Overlay */}
      <NotificationCenter />
    </div>
  );
}