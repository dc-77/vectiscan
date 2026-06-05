import type { NextConfig } from 'next';
import { securityHeaders } from './src/lib/securityHeaders';

const nextConfig: NextConfig = {
  output: 'standalone',
  // VEC-166: kanonischer Content-Security-Policy-Header auf allen Routen.
  async headers() {
    return [
      {
        source: '/:path*',
        headers: securityHeaders(),
      },
    ];
  },
};

export default nextConfig;
