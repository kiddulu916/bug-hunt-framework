'use client';

import { LeftSidebar } from './LeftSidebar';
import { RightSidebar } from './RightSidebar';
import { TopBar } from './TopBar';
import { useLayoutStore } from '@/store/layout';

export function MainLayout({ children }) {
  const { leftSidebarCollapsed, rightSidebarCollapsed } = useLayoutStore();

  return (
    <div className="h-screen bg-gray-900 flex flex-col overflow-hidden">
      {/* Top Bar */}
      <TopBar className="mb-3 mt-3" />

      {/* Main Content Area */}
      <div className="flex-1 flex overflow-hidden gap-3 px-3 pb-3 bg-gray-800">
        {/* Left Sidebar */}
        <LeftSidebar />

        {/* Main Content */}
        <main className="flex-1 overflow-auto bg-gray-800">
          <div className="h-full p-6">
            {children}
          </div>
        </main>

        {/* Right Sidebar */}
        <RightSidebar />
      </div>
    </div>
  );
}