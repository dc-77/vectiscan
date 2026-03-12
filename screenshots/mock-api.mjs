/**
 * Mock API server for screenshots.
 * Simulates the VectiScan API responses for different scan states.
 */
import http from 'node:http';

const PORT = 4000;

// State machine: each GET advances the scan state
let pollCount = 0;

const STATES = [
  { status: 'created', phase: null, tool: null, host: null, hostsTotal: 0, hostsCompleted: 0, hosts: [] },
  { status: 'dns_recon', phase: 'phase0', tool: 'subfinder', host: null, hostsTotal: 0, hostsCompleted: 0, hosts: [] },
  {
    status: 'scan_phase1', phase: 'phase1', tool: 'nmap', host: '45.33.32.156', hostsTotal: 2, hostsCompleted: 0,
    hosts: [
      { ip: '45.33.32.156', fqdns: ['scanme.nmap.org'], status: 'scanning' },
      { ip: '45.33.49.119', fqdns: ['insecure.org'], status: 'pending' },
    ]
  },
  {
    status: 'scan_phase2', phase: 'phase2', tool: 'nikto', host: '45.33.32.156', hostsTotal: 2, hostsCompleted: 1,
    hosts: [
      { ip: '45.33.32.156', fqdns: ['scanme.nmap.org'], status: 'completed' },
      { ip: '45.33.49.119', fqdns: ['insecure.org'], status: 'scanning' },
    ]
  },
  {
    status: 'scan_phase2', phase: 'phase2', tool: 'nuclei', host: '45.33.49.119', hostsTotal: 2, hostsCompleted: 1,
    hosts: [
      { ip: '45.33.32.156', fqdns: ['scanme.nmap.org'], status: 'completed' },
      { ip: '45.33.49.119', fqdns: ['insecure.org'], status: 'scanning' },
    ]
  },
  {
    status: 'report_generating', phase: null, tool: null, host: null, hostsTotal: 2, hostsCompleted: 2,
    hosts: [
      { ip: '45.33.32.156', fqdns: ['scanme.nmap.org'], status: 'completed' },
      { ip: '45.33.49.119', fqdns: ['insecure.org'], status: 'completed' },
    ]
  },
  {
    status: 'report_complete', phase: null, tool: null, host: null, hostsTotal: 2, hostsCompleted: 2,
    hosts: [
      { ip: '45.33.32.156', fqdns: ['scanme.nmap.org'], status: 'completed' },
      { ip: '45.33.49.119', fqdns: ['insecure.org'], status: 'completed' },
    ]
  },
];

const SCAN_ID = '550e8400-e29b-41d4-a716-446655440000';

function jsonResponse(res, status, data) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  });
  res.end(JSON.stringify(data));
}

const server = http.createServer((req, res) => {
  // CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    });
    return res.end();
  }

  const url = new URL(req.url, `http://localhost:${PORT}`);

  // Health
  if (url.pathname === '/health') {
    return jsonResponse(res, 200, { status: 'ok', timestamp: new Date().toISOString() });
  }

  // POST /api/scans
  if (req.method === 'POST' && url.pathname === '/api/scans') {
    pollCount = 0;
    return jsonResponse(res, 201, {
      success: true,
      data: { id: SCAN_ID, domain: 'scanme.nmap.org', status: 'created', createdAt: new Date().toISOString() }
    });
  }

  // GET /api/scans/:id/report
  if (req.method === 'GET' && url.pathname.endsWith('/report')) {
    return jsonResponse(res, 200, {
      success: true,
      data: {
        downloadUrl: '#',
        fileName: 'vectiscan-scanme.nmap.org-2026-03-12.pdf',
        fileSize: 342016
      }
    });
  }

  // GET /api/scans/:id
  if (req.method === 'GET' && url.pathname.startsWith('/api/scans/')) {
    const state = STATES[Math.min(pollCount, STATES.length - 1)];
    pollCount++;

    const startedAt = new Date(Date.now() - 5 * 60 * 1000).toISOString();

    return jsonResponse(res, 200, {
      success: true,
      data: {
        id: SCAN_ID,
        domain: 'scanme.nmap.org',
        status: state.status,
        progress: {
          phase: state.phase,
          currentTool: state.tool,
          currentHost: state.host,
          hostsTotal: state.hostsTotal,
          hostsCompleted: state.hostsCompleted,
          discoveredHosts: state.hosts,
        },
        startedAt,
        finishedAt: state.status === 'report_complete' ? new Date().toISOString() : null,
        error: null,
        hasReport: state.status === 'report_complete',
      }
    });
  }

  // DELETE /api/scans/:id
  if (req.method === 'DELETE') {
    return jsonResponse(res, 200, { success: true, data: null });
  }

  jsonResponse(res, 404, { success: false, error: 'Not found' });
});

server.listen(PORT, () => {
  console.log(`Mock API running on http://localhost:${PORT}`);
});
