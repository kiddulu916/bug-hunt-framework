'use client';

import { useEffect, useState, useCallback } from 'react';
import websocketService from '@/lib/websocket';

export function useWebSocket() {
  const [isConnected, setIsConnected] = useState(false);

  useEffect(() => {
    websocketService.connect();

    const unsubscribeConnection = websocketService.on('connection_status', ({ connected }) => {
      setIsConnected(connected);
    });

    return () => {
      unsubscribeConnection();
    };
  }, []);

  const subscribe = useCallback((event, callback) => {
    return websocketService.on(event, callback);
  }, []);

  const send = useCallback((event, data) => {
    websocketService.send(event, data);
  }, []);

  const joinRoom = useCallback((room) => {
    websocketService.joinRoom(room);
  }, []);

  const leaveRoom = useCallback((room) => {
    websocketService.leaveRoom(room);
  }, []);

  return {
    isConnected,
    subscribe,
    send,
    joinRoom,
    leaveRoom,
  };
}
