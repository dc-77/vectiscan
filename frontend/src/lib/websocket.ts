'use client';

import { useEffect, useRef, useState, useCallback } from 'react';
import { getToken } from './auth';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:4000';
const WS_URL_OVERRIDE = process.env.NEXT_PUBLIC_WS_URL;

export type WsEventType =
  | 'connected'
  | 'status'
  | 'progress'
  | 'hosts_discovered'
  | 'ai_strategy'
  | 'ai_config'
  | 'tool_output'
  | 'tool_starting'
  | 'precheck_progress'
  | 'precheck_target_complete'
  | 'precheck_complete'
  | 'target_approved'
  | 'target_rejected'
  | 'error';

export interface WsEvent {
  type: WsEventType | string;
  orderId?: string;
  targetId?: string;
  status?: string;
  phase?: string;
  message?: string;
  currentPhase?: string;
  currentTool?: string;
  currentHost?: string;
  hostsCompleted?: number;
  hostsTotal?: number;
  hosts?: Array<{ ip: string; fqdns: string[] }>;
  tool?: string;
  host?: string;
  summary?: string;
  ip?: string;
  config?: Record<string, unknown>;
  strategy?: Record<string, unknown>;
  result?: Record<string, unknown>;
  reason?: string;
  error?: string;
  updatedAt?: string;
  [key: string]: unknown;
}

export interface UseOrderProgressResult {
  events: WsEvent[];
  lastStatus: string | null;
  connected: boolean;
  error: string | null;
}

function buildWsUrl(orderId: string, token: string | null): string {
  const base = WS_URL_OVERRIDE || API_URL;
  const url = new URL(base);
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
  url.pathname = '/ws';
  url.searchParams.set('orderId', orderId);
  if (token) {
    url.searchParams.set('token', token);
  }
  return url.toString();
}

export function useOrderProgress(orderId: string | null): UseOrderProgressResult {
  const [events, setEvents] = useState<WsEvent[]>([]);
  const [lastStatus, setLastStatus] = useState<string | null>(null);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const reconnectAttempt = useRef(0);
  const stoppedRef = useRef(false);

  const handleMessage = useCallback((raw: string) => {
    let msg: WsEvent;
    try {
      msg = JSON.parse(raw) as WsEvent;
    } catch {
      return;
    }
    setEvents(prev => [...prev, msg]);
    if (msg.type === 'status' && typeof msg.status === 'string') {
      setLastStatus(msg.status);
    }
  }, []);

  const connect = useCallback((id: string) => {
    if (stoppedRef.current) return;

    try {
      const token = getToken();
      const ws = new WebSocket(buildWsUrl(id, token));
      wsRef.current = ws;

      ws.onopen = () => {
        reconnectAttempt.current = 0;
        setConnected(true);
        setError(null);
      };

      ws.onmessage = (ev) => handleMessage(ev.data as string);

      ws.onerror = () => {
        setError('WebSocket-Verbindungsfehler');
      };

      ws.onclose = () => {
        setConnected(false);
        wsRef.current = null;
        if (stoppedRef.current) return;
        const attempt = reconnectAttempt.current;
        const delay = Math.min(1000 * 2 ** attempt, 15000);
        reconnectAttempt.current = attempt + 1;
        reconnectTimer.current = setTimeout(() => connect(id), delay);
      };
    } catch {
      setError('WebSocket konnte nicht initialisiert werden');
      setConnected(false);
    }
  }, [handleMessage]);

  useEffect(() => {
    stoppedRef.current = false;
    setEvents([]);
    setLastStatus(null);
    setError(null);

    if (!orderId) {
      return;
    }

    connect(orderId);

    return () => {
      stoppedRef.current = true;
      if (reconnectTimer.current) {
        clearTimeout(reconnectTimer.current);
        reconnectTimer.current = null;
      }
      if (wsRef.current) {
        try { wsRef.current.close(); } catch { /* noop */ }
        wsRef.current = null;
      }
      reconnectAttempt.current = 0;
    };
  }, [orderId, connect]);

  return { events, lastStatus, connected, error };
}
