'use client';

import { useEffect, useRef, useCallback } from 'react';

// VectiScan character set — security symbols + hex
const CHARSET = '█▓▒░╔╗╚╝║═0123456789abcdefABCDEF<>{}[]/:;@#$%^&*~';
const COLS = 120;
const ROWS = 40;
const MUTATIONS_PER_TICK = 120;

// Colors
const DIM_COLOR = '#0E3B5C';
const BRIGHT_COLOR = '#38BDF8';
const BG_COLOR = '#070D1A';

interface NoiseMatrixProps {
  active?: boolean;
}

export default function NoiseMatrix({ active = true }: NoiseMatrixProps) {
  const preRef = useRef<HTMLPreElement>(null);
  const gridRef = useRef<string[][]>([]);
  const brightnessRef = useRef<number[][]>([]);
  const scanlineRef = useRef<number>(0);

  // Initialize grid
  useEffect(() => {
    const grid: string[][] = [];
    const brightness: number[][] = [];
    for (let r = 0; r < ROWS; r++) {
      grid[r] = [];
      brightness[r] = [];
      for (let c = 0; c < COLS; c++) {
        grid[r][c] = CHARSET[Math.floor(Math.random() * CHARSET.length)];
        brightness[r][c] = Math.random() * 0.3; // start dim
      }
    }
    gridRef.current = grid;
    brightnessRef.current = brightness;
  }, []);

  const render = useCallback(() => {
    if (!preRef.current || !active) return;
    const grid = gridRef.current;
    const brightness = brightnessRef.current;
    if (!grid.length) return;

    // Mutate random cells
    for (let i = 0; i < MUTATIONS_PER_TICK; i++) {
      const r = Math.floor(Math.random() * ROWS);
      const c = Math.floor(Math.random() * COLS);
      grid[r][c] = CHARSET[Math.floor(Math.random() * CHARSET.length)];
      brightness[r][c] = Math.random() * 0.4;
    }

    // Occasional data burst — one row flashes bright
    if (Math.random() < 0.03) {
      const burstRow = Math.floor(Math.random() * ROWS);
      for (let c = 0; c < COLS; c++) {
        brightness[burstRow][c] = 0.5 + Math.random() * 0.3;
      }
    }

    // Scanline position
    scanlineRef.current = (scanlineRef.current + 0.5) % ROWS;
    const scanY = scanlineRef.current;

    // Build output with inline color via spans
    let html = '';
    for (let r = 0; r < ROWS; r++) {
      // Scanline brightens nearby rows
      const scanDist = Math.abs(r - scanY);
      const scanBoost = scanDist < 3 ? (3 - scanDist) * 0.15 : 0;

      for (let c = 0; c < COLS; c++) {
        const b = Math.min(brightness[r][c] + scanBoost, 0.8);
        // Fade brightness over time
        brightness[r][c] *= 0.97;

        const opacity = b.toFixed(2);
        const color = b > 0.4 ? BRIGHT_COLOR : DIM_COLOR;
        html += `<span style="color:${color};opacity:${opacity}">${grid[r][c]}</span>`;
      }
      html += '\n';
    }

    preRef.current.innerHTML = html;
  }, [active]);

  useEffect(() => {
    if (!active) return;
    let animId: number;
    const loop = () => {
      render();
      animId = requestAnimationFrame(loop);
    };
    animId = requestAnimationFrame(loop);
    return () => cancelAnimationFrame(animId);
  }, [active, render]);

  return (
    <div
      className="fixed inset-0 overflow-hidden pointer-events-none"
      style={{ backgroundColor: BG_COLOR, zIndex: 0 }}
    >
      <pre
        ref={preRef}
        className="absolute inset-0 m-0 p-4 leading-tight select-none"
        style={{
          fontFamily: "'Fira Mono', 'Consolas', 'Liberation Mono', monospace",
          fontSize: '12px',
          lineHeight: '14px',
          letterSpacing: '1px',
        }}
      />
      {/* Radial mask — center clear, edges dark */}
      <div
        className="absolute inset-0"
        style={{
          background: `radial-gradient(ellipse at center, transparent 20%, ${BG_COLOR}80 50%, ${BG_COLOR} 80%)`,
        }}
      />
      {/* Scanline overlay */}
      <div
        className="absolute inset-0"
        style={{
          background: 'repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.08) 2px, rgba(0,0,0,0.08) 4px)',
          pointerEvents: 'none',
        }}
      />
    </div>
  );
}
