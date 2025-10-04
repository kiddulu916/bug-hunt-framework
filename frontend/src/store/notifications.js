import { create } from 'zustand';

const useNotificationStore = create((set, get) => ({
  notifications: [],
  unreadCount: 0,
  isOpen: false,

  // Add a new notification
  addNotification: (notification) => {
    const newNotification = {
      id: notification.id || Date.now(),
      type: notification.type || 'info', // info, success, warning, error
      title: notification.title,
      message: notification.message,
      timestamp: notification.timestamp || new Date().toISOString(),
      read: false,
      data: notification.data || null,
    };

    set((state) => ({
      notifications: [newNotification, ...state.notifications],
      unreadCount: state.unreadCount + 1,
    }));

    return newNotification.id;
  },

  // Mark notification as read
  markAsRead: (id) => {
    set((state) => {
      const notification = state.notifications.find(n => n.id === id);
      if (notification && !notification.read) {
        return {
          notifications: state.notifications.map(n =>
            n.id === id ? { ...n, read: true } : n
          ),
          unreadCount: Math.max(0, state.unreadCount - 1),
        };
      }
      return state;
    });
  },

  // Mark all as read
  markAllAsRead: () => {
    set((state) => ({
      notifications: state.notifications.map(n => ({ ...n, read: true })),
      unreadCount: 0,
    }));
  },

  // Remove notification
  removeNotification: (id) => {
    set((state) => {
      const notification = state.notifications.find(n => n.id === id);
      const wasUnread = notification && !notification.read;

      return {
        notifications: state.notifications.filter(n => n.id !== id),
        unreadCount: wasUnread ? Math.max(0, state.unreadCount - 1) : state.unreadCount,
      };
    });
  },

  // Clear all notifications
  clearAll: () => {
    set({
      notifications: [],
      unreadCount: 0,
    });
  },

  // Toggle notification panel
  togglePanel: () => {
    set((state) => ({ isOpen: !state.isOpen }));
  },

  setIsOpen: (isOpen) => {
    set({ isOpen });
  },

  // Get unread notifications
  getUnreadNotifications: () => {
    return get().notifications.filter(n => !n.read);
  },

  // Get notifications by type
  getNotificationsByType: (type) => {
    return get().notifications.filter(n => n.type === type);
  },
}));

export default useNotificationStore;
