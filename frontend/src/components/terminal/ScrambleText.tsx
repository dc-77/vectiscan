'use client';

import { useEffect, useState, useRef } from 'react';

const SCRAMBLE_CHARS = '█▓▒░╔╗╚╝║═0123456789abcdef!@#$%^&*';

interface ScrambleTextProps {
  text: string;
  duration?: number;    // ms to resolve (default 300)
  delay?: number;       // ms before starting (default 0)
  reverse?: boolean;    // dissolve instead of resolve
  className?: string;
  onComplete?: () => void;
}

function scramble(text: string): string {
  return text.split('').map(c =>
    c === ' ' ? ' ' : SCRAMBLE_CHARS[Math.floor(Math.random() * SCRAMBLE_CHARS.length)]
  ).join('');
}

export default function ScrambleText({
  text,
  duration = 300,
  delay = 0,
  reverse = false,
  className = '',
  onComplete,
}: ScrambleTextProps) {
  const [display, setDisplay] = useState(reverse ? text : scramble(text));
  const startedRef = useRef(false);

  useEffect(() => {
    const timer = setTimeout(() => {
      startedRef.current = true;
      const startTime = Date.now();
      const chars = text.split('');
      const totalChars = chars.length;

      const interval = setInterval(() => {
        const elapsed = Date.now() - startTime;
        const progress = Math.min(elapsed / duration, 1);

        const result = chars.map((char, i) => {
          const charProgress = (progress * totalChars - i) / 3;
          if (reverse) {
            // Characters dissolve left to right
            if (charProgress > 0) {
              return SCRAMBLE_CHARS[Math.floor(Math.random() * SCRAMBLE_CHARS.length)];
            }
            return char;
          } else {
            // Characters resolve left to right
            if (charProgress >= 1) return char;
            return SCRAMBLE_CHARS[Math.floor(Math.random() * SCRAMBLE_CHARS.length)];
          }
        }).join('');

        setDisplay(result);

        if (progress >= 1) {
          clearInterval(interval);
          setDisplay(reverse ? scramble(text) : text);
          onComplete?.();
        }
      }, 30);

      return () => clearInterval(interval);
    }, delay);

    return () => clearTimeout(timer);
  }, [text, duration, delay, reverse, onComplete]);

  return <span className={className}>{display}</span>;
}
