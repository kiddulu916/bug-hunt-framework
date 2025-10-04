'use client';

import { motion } from 'framer-motion';
import { AlertTriangle, X, Trash2 } from 'lucide-react';

export function TargetDeleteConfirmation({ target, onClose, onConfirm, isDeleting }) {
  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        exit={{ opacity: 0, scale: 0.95 }}
        className="bg-gray-900 rounded-lg border border-gray-800 max-w-md w-full overflow-hidden"
      >
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-gray-800">
          <div className="flex items-center">
            <div className="w-10 h-10 bg-red-600 bg-opacity-20 rounded-full flex items-center justify-center mr-3">
              <AlertTriangle className="w-5 h-5 text-red-500" />
            </div>
            <h2 className="text-xl font-bold text-white">Delete Target</h2>
          </div>
          <button
            onClick={onClose}
            className="p-2 text-gray-400 hover:text-white transition-colors"
            disabled={isDeleting}
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6">
          <p className="text-gray-300 mb-4">
            Are you sure you want to delete <span className="font-semibold text-white">{target.target_name}</span>?
          </p>

          <div className="bg-red-900 bg-opacity-20 border border-red-700 rounded-lg p-4 mb-4">
            <p className="text-red-300 text-sm">
              <strong>Warning:</strong> This action cannot be undone. All associated scan sessions and data will be lost.
            </p>
          </div>

          <div className="bg-gray-800 rounded-lg p-4 space-y-2">
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Target:</span>
              <span className="text-white font-medium">{target.target_name}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">URL:</span>
              <span className="text-white font-medium truncate ml-2">{target.main_url}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Platform:</span>
              <span className="text-white font-medium capitalize">{target.platform}</span>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end space-x-3 p-6 border-t border-gray-800">
          <button
            onClick={onClose}
            disabled={isDeleting}
            className="px-4 py-2 text-gray-400 hover:text-white transition-colors disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            disabled={isDeleting}
            className="flex items-center px-6 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isDeleting ? (
              <>
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2" />
                Deleting...
              </>
            ) : (
              <>
                <Trash2 className="w-4 h-4 mr-2" />
                Delete Target
              </>
            )}
          </button>
        </div>
      </motion.div>
    </div>
  );
}
