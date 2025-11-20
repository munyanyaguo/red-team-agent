/**
 * WebSocket Context
 * Provides real-time updates via Socket.IO
 */
import { createContext, useContext, useEffect, useState, useRef } from 'react';
import { io } from 'socket.io-client';
import { useAuth } from './AuthContext';

const WebSocketContext = createContext(null);

const WS_URL = import.meta.env.VITE_WS_URL || 'http://localhost:5000';

export const WebSocketProvider = ({ children }) => {
  const [socket, setSocket] = useState(null);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState(null);
  const { isAuthenticated, user } = useAuth();
  const eventListeners = useRef({});

  // Initialize WebSocket connection when user is authenticated
  useEffect(() => {
    // WebSocket disabled - backend doesn't have Socket.IO configured yet
    console.log('[WebSocket] Connection disabled');
    setConnected(false);
    setSocket(null);
    setError(null);

    // Cleanup on unmount
    return () => {
      if (socket) {
        socket.disconnect();
      }
    };
  }, [isAuthenticated, user]);

  /**
   * Subscribe to an event
   */
  const on = (event, callback) => {
    if (!socket) return;

    // Store listener reference for cleanup
    if (!eventListeners.current[event]) {
      eventListeners.current[event] = [];
    }
    eventListeners.current[event].push(callback);

    socket.on(event, callback);

    // Return unsubscribe function
    return () => {
      socket.off(event, callback);
      const listeners = eventListeners.current[event];
      if (listeners) {
        const index = listeners.indexOf(callback);
        if (index > -1) {
          listeners.splice(index, 1);
        }
      }
    };
  };

  /**
   * Unsubscribe from an event
   */
  const off = (event, callback) => {
    if (!socket) return;
    socket.off(event, callback);

    // Remove from listeners reference
    const listeners = eventListeners.current[event];
    if (listeners) {
      const index = listeners.indexOf(callback);
      if (index > -1) {
        listeners.splice(index, 1);
      }
    }
  };

  /**
   * Emit an event to the server
   */
  const emit = (event, data) => {
    if (!socket || !connected) {
      console.warn('[WebSocket] Cannot emit, not connected');
      return;
    }
    socket.emit(event, data);
  };

  /**
   * Subscribe to scan updates for a specific scan ID
   */
  const subscribeScan = (scanId, callback) => {
    return on(`scan:${scanId}:update`, callback);
  };

  /**
   * Subscribe to finding updates
   */
  const subscribeFinding = (callback) => {
    return on('finding:new', callback);
  };

  /**
   * Subscribe to engagement updates
   */
  const subscribeEngagement = (engagementId, callback) => {
    return on(`engagement:${engagementId}:update`, callback);
  };

  /**
   * Subscribe to system notifications
   */
  const subscribeNotifications = (callback) => {
    return on('notification', callback);
  };

  const value = {
    socket,
    connected,
    error,
    on,
    off,
    emit,
    subscribeScan,
    subscribeFinding,
    subscribeEngagement,
    subscribeNotifications,
  };

  return (
    <WebSocketContext.Provider value={value}>
      {children}
    </WebSocketContext.Provider>
  );
};

// Custom hook to use WebSocket context
export const useWebSocket = () => {
  const context = useContext(WebSocketContext);
  if (!context) {
    throw new Error('useWebSocket must be used within a WebSocketProvider');
  }
  return context;
};

export default WebSocketContext;
