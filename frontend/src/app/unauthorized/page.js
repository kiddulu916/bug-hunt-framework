'use client';

import { ShieldAlert } from 'lucide-react';
import { useRouter } from 'next/navigation';

export default function UnauthorizedPage() {
  const router = useRouter();

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900">
      <div className="text-center space-y-6 p-8">
        <div className="flex justify-center">
          <div className="p-4 bg-red-500/10 rounded-full">
            <ShieldAlert className="w-24 h-24 text-red-400" />
          </div>
        </div>
        <div className="space-y-2">
          <h1 className="text-4xl font-bold text-white">Access Denied</h1>
          <p className="text-gray-400 text-lg max-w-md">
            You don't have permission to access this resource. Please contact your administrator if you believe this is a mistake.
          </p>
        </div>
        <div className="flex gap-4 justify-center pt-4">
          <button
            onClick={() => router.back()}
            className="px-6 py-3 bg-gray-600 hover:bg-gray-700 text-white rounded-lg transition-colors"
          >
            Go Back
          </button>
          <button
            onClick={() => router.push('/dashboard')}
            className="px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
          >
            Go to Dashboard
          </button>
        </div>
      </div>
    </div>
  );
}
