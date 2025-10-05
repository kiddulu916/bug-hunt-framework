'use client';

import { Component } from 'react';
import { AlertTriangle, RefreshCw, Home } from 'lucide-react';

class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null
    };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    this.setState({
      error,
      errorInfo
    });

    // Log error to monitoring service
    console.error('ErrorBoundary caught an error:', error, errorInfo);

    // You can also log to an external service like Sentry here
    if (typeof window !== 'undefined' && window.errorLogger) {
      window.errorLogger.log(error, errorInfo);
    }
  }

  handleReset = () => {
    this.setState({
      hasError: false,
      error: null,
      errorInfo: null
    });
  };

  render() {
    if (this.state.hasError) {
      const { fallback, minimal } = this.props;

      // Custom fallback component
      if (fallback) {
        return fallback(this.state.error, this.handleReset);
      }

      // Minimal error UI
      if (minimal) {
        return (
          <div className="flex items-center gap-2 p-4 bg-red-500/10 border border-red-500/20 rounded-lg">
            <AlertTriangle className="w-5 h-5 text-red-500" />
            <p className="text-sm text-red-400">Something went wrong</p>
            <button
              onClick={this.handleReset}
              className="ml-auto px-3 py-1 text-xs bg-red-500/20 hover:bg-red-500/30 rounded transition-colors"
            >
              Retry
            </button>
          </div>
        );
      }

      // Full error page
      return (
        <div className="min-h-screen flex items-center justify-center p-4 bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900">
          <div className="max-w-2xl w-full">
            <div className="bg-gray-800/50 backdrop-blur-sm border border-gray-700 rounded-2xl p-8 shadow-2xl">
              <div className="flex items-center gap-4 mb-6">
                <div className="p-3 bg-red-500/20 rounded-full">
                  <AlertTriangle className="w-8 h-8 text-red-500" />
                </div>
                <div>
                  <h1 className="text-2xl font-bold text-white">Something went wrong</h1>
                  <p className="text-gray-400 mt-1">
                    We're sorry for the inconvenience. The application encountered an unexpected error.
                  </p>
                </div>
              </div>

              {process.env.NODE_ENV === 'development' && this.state.error && (
                <div className="mb-6 p-4 bg-gray-900/50 border border-gray-700 rounded-lg">
                  <p className="text-sm font-mono text-red-400 mb-2">
                    {this.state.error.toString()}
                  </p>
                  {this.state.errorInfo && (
                    <pre className="text-xs text-gray-500 overflow-auto max-h-48">
                      {this.state.errorInfo.componentStack}
                    </pre>
                  )}
                </div>
              )}

              <div className="flex flex-wrap gap-3">
                <button
                  onClick={this.handleReset}
                  className="flex items-center gap-2 px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
                >
                  <RefreshCw className="w-4 h-4" />
                  Try Again
                </button>
                <button
                  onClick={() => window.location.href = '/'}
                  className="flex items-center gap-2 px-6 py-3 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors"
                >
                  <Home className="w-4 h-4" />
                  Go Home
                </button>
              </div>

              <div className="mt-6 pt-6 border-t border-gray-700">
                <p className="text-sm text-gray-500">
                  If this problem persists, please contact support with the error details above.
                </p>
              </div>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
