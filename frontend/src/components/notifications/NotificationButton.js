'use client';

import { Bell } from 'lucide-react';
import useNotificationStore from '@/store/notifications';
import { motion, AnimatePresence } from 'framer-motion';

export function NotificationButton() {
  const { unreadCount, togglePanel } = useNotificationStore();

  return (
    <button
      onClick={togglePanel}
      className="relative p-2 text-gray-400 hover:text-white transition-colors rounded-lg hover:bg-gray-800"
    >
      <Bell className="w-5 h-5" />
      <AnimatePresence>
        {unreadCount > 0 && (
          <motion.span
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            exit={{ scale: 0 }}
            className="absolute -top-1 -right-1 w-5 h-5 bg-red-500 text-white text-xs rounded-full flex items-center justify-center font-semibold"
          >
            {unreadCount > 9 ? '9+' : unreadCount}
          </motion.span>
        )}
      </AnimatePresence>
    </button>
  );
}
