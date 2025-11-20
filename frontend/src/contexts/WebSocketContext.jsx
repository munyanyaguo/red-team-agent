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
    if (!isAuthenticated || !user) {
      // Disconnect if not authenticated
      if (socket) {
        socket.disconnect();
        setSocket(null);
        setConnected(false);
      }
      return;
    }

    // Create Socket.IO connection with auth token
    const token = localStorage.getItem('access_token');
    const newSocket = io(WS_URL, {
      auth: {
        token: token,
      },
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionAttempts: 5,
    });

    // Connection event handlers
    newSocket.on('connect', () => {
      console.log('[WebSocket] Connected');
      setConnected(true);
      setError(null);
    });

    newSocket.on('disconnect', (reason) => {
      console.log('[WebSocket] Disconnected:', reason);
      setConnected(false);
    });

    newSocket.on('connect_error', (err) => {
      console.error('[WebSocket] Connection error:', err);
      setError(err.message);
      setConnected(false);
    });

    newSocket.on('error', (err) => {
      console.error('[WebSocket] Error:', err);
      setError(err.message || 'WebSocket error');
    });

    setSocket(newSocket);

    // Cleanup on unmount
    return () => {
      if (newSocket) {
        newSocket.disconnect();
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
