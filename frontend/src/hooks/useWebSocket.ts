'use client';

import { useEffect, useRef, useCallback, useState } from 'react';
import type { ScanStatus } from '@/lib/api';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:4000';

/** Derive WebSocket URL from the API URL (http→ws, https→wss). */
function getWsUrl(scanId: string): string {
  const url = new URL(API_URL);
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
  url.pathname = '/ws';
  url.searchParams.set('scanId', scanId);
  return url.toString();
}

export interface WsMessage {
  type: 'connected' | 'progress' | 'status' | 'hosts_discovered' | 'error';
  scanId?: string;
  status?: string;
  currentPhase?: string;
  currentTool?: string;
  currentHost?: string;
  hostsCompleted?: number;
  hostsTotal?: number;
  hosts?: Array<{ ip: string; fqdns: string[] }>;
  error?: string;
  updatedAt?: string;
}

interface UseWebSocketOptions {
  /** Called on every WebSocket message */
  onMessage: (msg: WsMessage) => void;
  /** Called when WebSocket connects/disconnects (for fallback polling) */
  onConnectionChange?: (connected: boolean) => void;
}

/**
 * Hook that connects to the VectiScan WebSocket endpoint for a scan.
 *
 * Returns `connected` state. When disconnected, the parent component
 * should fall back to HTTP polling.
 */
export function useWebSocket(
  scanId: string | null,
  { onMessage, onConnectionChange }: UseWebSocketOptions,
) {
  const wsRef = useRef<WebSocket | null>(null);
  const [connected, setConnected] = useState(false);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const reconnectAttempt = useRef(0);

  const cleanup = useCallback(() => {
    if (reconnectTimer.current) {
      clearTimeout(reconnectTimer.current);
      reconnectTimer.current = null;
    }
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    reconnectAttempt.current = 0;
  }, []);

  const connect = useCallback((id: string) => {
    cleanup();

    const ws = new WebSocket(getWsUrl(id));
    wsRef.current = ws;

    ws.onopen = () => {
      reconnectAttempt.current = 0;
      setConnected(true);
      onConnectionChange?.(true);
    };

    ws.onmessage = (event) => {
      try {
        const msg: WsMessage = JSON.parse(event.data);
        onMessage(msg);
      } catch {
        // Ignore malformed messages
      }
    };

    ws.onclose = () => {
      setConnected(false);
      onConnectionChange?.(false);

      // Reconnect with exponential backoff (max 10s)
      if (reconnectAttempt.current < 5) {
        const delay = Math.min(1000 * 2 ** reconnectAttempt.current, 10000);
        reconnectAttempt.current += 1;
        reconnectTimer.current = setTimeout(() => connect(id), delay);
      }
    };

    ws.onerror = () => {
      // onclose will fire after onerror — reconnect happens there
    };
  }, [cleanup, onMessage, onConnectionChange]);

  useEffect(() => {
    if (scanId) {
      connect(scanId);
    }
    return cleanup;
  }, [scanId, connect, cleanup]);

  return { connected, close: cleanup };
}
