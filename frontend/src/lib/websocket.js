import { io } from 'socket.io-client';

class WebSocketService {
  constructor() {
    this.socket = null;
    this.listeners = new Map();
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 5;
    this.isConnecting = false;
  }

  connect(url = 'http://localhost:8000') {
    if (this.socket?.connected || this.isConnecting) {
      return this.socket;
    }

    this.isConnecting = true;

    this.socket = io(url, {
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
      reconnectionAttempts: this.maxReconnectAttempts,
      timeout: 20000,
    });

    this.socket.on('connect', () => {
      console.log('✅ WebSocket connected');
      this.reconnectAttempts = 0;
      this.isConnecting = false;
      this.emit('connection_status', { connected: true });
    });

    this.socket.on('disconnect', (reason) => {
      console.log('❌ WebSocket disconnected:', reason);
      this.isConnecting = false;
      this.emit('connection_status', { connected: false, reason });
    });

    this.socket.on('connect_error', (error) => {
      console.error('WebSocket connection error:', error);
      this.reconnectAttempts++;
      this.isConnecting = false;

      if (this.reconnectAttempts >= this.maxReconnectAttempts) {
        console.error('Max reconnection attempts reached');
        this.emit('connection_error', {
          error: 'Failed to connect after multiple attempts',
          attempts: this.reconnectAttempts
        });
      }
    });

    // Scan-related events
    this.socket.on('scan_started', (data) => {
      this.emit('scan_started', data);
    });

    this.socket.on('scan_progress', (data) => {
      this.emit('scan_progress', data);
    });

    this.socket.on('scan_completed', (data) => {
      this.emit('scan_completed', data);
    });

    this.socket.on('scan_failed', (data) => {
      this.emit('scan_failed', data);
    });

    // Vulnerability events
    this.socket.on('vulnerability_found', (data) => {
      this.emit('vulnerability_found', data);
    });

    // Dashboard metrics events
    this.socket.on('metrics_update', (data) => {
      this.emit('metrics_update', data);
    });

    // Notification events
    this.socket.on('notification', (data) => {
      this.emit('notification', data);
    });

    return this.socket;
  }

  disconnect() {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
      this.listeners.clear();
      this.isConnecting = false;
      this.reconnectAttempts = 0;
    }
  }

  // Subscribe to events
  on(event, callback) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, []);
    }
    this.listeners.get(event).push(callback);

    // Return unsubscribe function
    return () => {
      const callbacks = this.listeners.get(event);
      if (callbacks) {
        const index = callbacks.indexOf(callback);
        if (index > -1) {
          callbacks.splice(index, 1);
        }
      }
    };
  }

  // Emit events to listeners
  emit(event, data) {
    const callbacks = this.listeners.get(event);
    if (callbacks) {
      callbacks.forEach(callback => callback(data));
    }
  }

  // Send data to server
  send(event, data) {
    if (this.socket?.connected) {
      this.socket.emit(event, data);
    } else {
      console.warn(`Cannot send ${event}: WebSocket not connected`);
    }
  }

  isConnected() {
    return this.socket?.connected || false;
  }

  // Join a room (for scan-specific updates)
  joinRoom(room) {
    this.send('join_room', { room });
  }

  // Leave a room
  leaveRoom(room) {
    this.send('leave_room', { room });
  }
}

// Singleton instance
const websocketService = new WebSocketService();

export default websocketService;
