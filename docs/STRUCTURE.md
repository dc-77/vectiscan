vectiscan/
├── CLAUDE.md                          ← Projektkontext für Claude Code
├── docs/
│   ├── PROTOTYPE-SCOPE.md             ← Scope-Dokument (was rein, was raus)
│   ├── API-SPEC.md                    ← API-Endpoints mit Request/Response
│   ├── DB-SCHEMA.sql                  ← SQL-Schema (vereinfacht)
│   ├── SCAN-TOOLS.md                  ← Tool-Liste mit Argumenten und Output-Formaten
│   └── architecture.md                ← Kopie/Auszug der Architekturplanung
├── frontend/
│   ├── Dockerfile
│   ├── package.json
│   └── src/
├── api/
│   ├── Dockerfile
│   ├── package.json
│   └── src/
├── scan-worker/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── scanner/
├── report-worker/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── reporter/
│       ├── worker.py                  ← BullMQ Consumer, Orchestrierung
│       ├── parser.py                  ← Tool-Output-Parser (JSON/XML → Findings)
│       ├── claude_client.py           ← Claude API Aufruf + JSON-Parsing
│       ├── report_mapper.py           ← Claude-Output → report_data Dict
│       └── generate_report.py         ← PDF-Engine aus pentest-report-generator Skill
├── references/
│   └── report_structure.md            ← Layout-Referenz aus dem Skill
├── docker-compose.yml                 ← Gesamtes Projekt (Produktion)
├── docker-compose.dev.yml             ← Lokale Entwicklung (ohne Registry-Images)
├── .env.template
└── .gitlab-ci.yml