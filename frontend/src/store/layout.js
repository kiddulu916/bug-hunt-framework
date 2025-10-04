import { create } from 'zustand';
import { persist, createJSONStorage } from 'zustand/middleware';

export const useLayoutStore = create(
  persist(
    (set) => ({
      leftSidebarCollapsed: false,
      rightSidebarCollapsed: false,
      activeSection: 'dashboard',

      toggleLeftSidebar: () => set((state) => ({
        leftSidebarCollapsed: !state.leftSidebarCollapsed
      })),

      toggleRightSidebar: () => set((state) => ({
        rightSidebarCollapsed: !state.rightSidebarCollapsed
      })),

      setActiveSection: (section) => set({ activeSection: section }),

      collapseAll: () => set({
        leftSidebarCollapsed: true,
        rightSidebarCollapsed: true
      }),

      expandAll: () => set({
        leftSidebarCollapsed: false,
        rightSidebarCollapsed: false
      })
    }),
    {
      name: 'layout-storage',
      storage: createJSONStorage(() => localStorage),
    }
  )
);