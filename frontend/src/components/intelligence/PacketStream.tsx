'use client';

import { useEffect, useRef, useState } from 'react';

interface Packet {
  id: number;
  color: string;
  speed: number; // seconds for full traverse
  delay: number; // start delay in seconds
  size: number;  // width in px
}

interface PacketStreamProps {
  isActive: boolean;
  hostColors: string[];
  burst?: boolean;
}

let packetCounter = 0;

export default function PacketStream({ isActive, hostColors, burst }: PacketStreamProps) {
  const [packets, setPackets] = useState<Packet[]>([]);
  const intervalRef = useRef<ReturnType<typeof setInterval>>(undefined);

  useEffect(() => {
    if (!isActive) {
      setPackets([]);
      return;
    }

    const colors = hostColors.length > 0 ? hostColors : ['#38BDF8'];

    const spawn = () => {
      const count = burst ? 4 : 1;
      const newPackets: Packet[] = [];
      for (let i = 0; i < count; i++) {
        newPackets.push({
          id: packetCounter++,
          color: colors[Math.floor(Math.random() * colors.length)],
          speed: burst ? 1.5 + Math.random() * 1 : 3 + Math.random() * 4,
          delay: Math.random() * 0.3,
          size: Math.random() > 0.7 ? 12 : 6,
        });
      }
      setPackets(prev => [...prev.slice(-30), ...newPackets]); // keep max 30
    };

    spawn();
    intervalRef.current = setInterval(spawn, burst ? 200 : 800);
    return () => clearInterval(intervalRef.current);
  }, [isActive, burst, hostColors]);

  return (
    <div className="relative h-[3px] w-full overflow-hidden" style={{ background: 'rgba(30,58,95,0.2)' }}>
      {/* Heartbeat shimmer */}
      <div className="absolute inset-0"
        style={{
          background: 'linear-gradient(90deg, transparent, rgba(59,130,246,0.15), transparent)',
          backgroundSize: '200% 100%',
          animation: isActive ? 'packetHeartbeat 2s linear infinite' : 'none',
        }}
      />
      {/* Packets */}
      {packets.map(p => (
        <div
          key={p.id}
          className="absolute top-0 rounded-full"
          style={{
            width: p.size,
            height: 3,
            backgroundColor: p.color,
            boxShadow: `0 0 4px ${p.color}`,
            animation: `packetFlow ${p.speed}s linear ${p.delay}s forwards`,
            left: 0,
          }}
        />
      ))}
    </div>
  );
}
