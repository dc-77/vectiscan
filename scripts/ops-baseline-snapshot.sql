-- ops-baseline-snapshot.sql
-- ============================================================================
-- Liefert KPI-Snapshot fuer Vor-/Nachher-Vergleich nach Audit-Deployment.
-- Lauft via GitLab-Job `ops-baseline-snapshot` (.gitlab-ci.yml).
-- Komplett read-only — kein DDL, keine Mutation.
-- ============================================================================

\pset format aligned
\pset border 1

\echo
\echo ============================================================================
\echo SCAN-OPTIMIERUNG BASELINE-SNAPSHOT
\echo ============================================================================
\echo
\echo Generated: now()
SELECT now() AT TIME ZONE 'UTC' AS snapshot_at_utc;

\echo
\echo === 1. ORDERS / REPORTS / SUBSCRIPTIONS Counts ===
SELECT
  (SELECT count(*) FROM orders) AS total_orders,
  (SELECT count(*) FROM reports) AS total_reports,
  (SELECT count(*) FROM subscriptions WHERE status = 'active') AS active_subs;

\echo
\echo === 2. POLICY_VERSION Verteilung ===
SELECT policy_version, count(*) AS reports
  FROM reports
  WHERE policy_version IS NOT NULL
  GROUP BY policy_version
  ORDER BY policy_version DESC NULLS LAST;

\echo
\echo === 3. SEVERITY-VERTEILUNG (letzte 30 Tage) ===
SELECT
  SUM((severity_counts->>'critical')::int) AS critical,
  SUM((severity_counts->>'high')::int)     AS high,
  SUM((severity_counts->>'medium')::int)   AS medium,
  SUM((severity_counts->>'low')::int)      AS low,
  SUM((severity_counts->>'info')::int)     AS info,
  count(*)                                  AS reports
FROM reports
WHERE severity_counts IS NOT NULL
  AND created_at > now() - interval '30 days';

\echo
\echo === 4. KI-CACHE-HIT-QUOTE pro NAMESPACE (letzte 7 Tage) ===
\echo (F-XS-001 + F-XS-002 sollten Hit-Rate fuer ki2/ki3 + reporter_v1 erhoehen)
SELECT
  ki_step,
  count(*) AS total_calls,
  SUM(CASE WHEN cache_hit THEN 1 ELSE 0 END) AS hits,
  ROUND(
    SUM(CASE WHEN cache_hit THEN 1 ELSE 0 END)::numeric / NULLIF(count(*), 0) * 100,
    1
  ) AS hit_rate_pct,
  ROUND(SUM(cost_usd)::numeric, 4) AS total_cost_usd
FROM ai_call_costs
WHERE created_at > now() - interval '7 days'
GROUP BY ki_step
ORDER BY total_calls DESC;

\echo
\echo === 5. KI-COST-MODELL-AGGREGAT (letzte 7 Tage) ===
SELECT
  model,
  count(*) AS calls,
  ROUND(SUM(cost_usd)::numeric, 2) AS total_usd,
  ROUND(AVG(cost_usd)::numeric, 4) AS avg_per_call,
  SUM(input_tokens) AS in_tok,
  SUM(output_tokens) AS out_tok
FROM ai_call_costs
WHERE created_at > now() - interval '7 days'
GROUP BY model
ORDER BY total_usd DESC NULLS LAST;

\echo
\echo === 6. DETERMINISMUS-KPI (alle Subscriptions) ===
\echo (F-XS-001 + F-XS-002 + F-RPT-002 + F-RPT-007 sollten Score nach 2 Re-Scans erhoehen)
SELECT
  subscription_id,
  determinism_score,
  jsonb_array_length(last_3_orders) AS orders_in_window,
  updated_at
FROM subscription_posture
WHERE determinism_score IS NOT NULL
ORDER BY determinism_score DESC NULLS LAST
LIMIT 20;

\echo
\echo === 7. POLICY_ID-VERTEILUNG Top 30 (letzte 30 Tage) ===
\echo (Drift-Indikator: welche policy_ids haeufig in Reports auftauchen)
SELECT
  policy_id,
  count(*) AS occurrences,
  count(DISTINCT order_id) AS in_orders
FROM consolidated_findings
WHERE policy_id IS NOT NULL
  AND created_at > now() - interval '30 days'
GROUP BY policy_id
ORDER BY count(*) DESC
LIMIT 30;

\echo
\echo === 8. CONSOLIDATED_FINDINGS PRO PAKET (letzte 30 Tage) ===
SELECT
  o.package,
  count(DISTINCT cf.order_id) AS orders,
  count(*)                    AS findings,
  ROUND(count(*)::numeric / NULLIF(count(DISTINCT cf.order_id), 0), 1) AS avg_per_order,
  SUM(CASE WHEN cf.severity = 'critical' THEN 1 ELSE 0 END) AS critical,
  SUM(CASE WHEN cf.severity = 'high' THEN 1 ELSE 0 END)     AS high
FROM consolidated_findings cf
JOIN orders o ON o.id = cf.order_id
WHERE cf.created_at > now() - interval '30 days'
GROUP BY o.package
ORDER BY findings DESC;

\echo
\echo === 9. SHODAN PRE-WARM STATUS (Migration 026) ===
\echo (sollte nach erstem Subscription-Re-Scan befuellt sein)
SELECT
  count(*) FILTER (WHERE pre_warm_requested = true) AS one_off_prewarm_requested,
  count(*) AS total_orders_last_30d
FROM orders
WHERE created_at > now() - interval '30 days';

SELECT
  count(*) AS subs_with_shodan_request
FROM subscriptions
WHERE shodan_scan_request IS NOT NULL;

\echo
\echo === 10. TOP-10 HAEUFIGSTE FINDING_TYPES (letzte 30 Tage) ===
\echo (zeigt Reporter-Coverage; Drift signalisiert finding_type_mapper-Luecken)
SELECT
  finding_type,
  count(*) AS occurrences,
  ROUND(AVG(business_impact_score)::numeric, 2) AS avg_business_impact
FROM consolidated_findings
WHERE finding_type IS NOT NULL
  AND created_at > now() - interval '30 days'
GROUP BY finding_type
ORDER BY count(*) DESC
LIMIT 10;

\echo
\echo === 11. TAKEOVER + URLHAUS-FINDINGS (P2 + P3 indicators) ===
SELECT
  finding_type,
  severity,
  count(*) AS findings
FROM consolidated_findings
WHERE finding_type IN ('subdomain_takeover', 'urlhaus_compromise_detected')
   OR policy_id IN ('SP-URLHAUS-001')
GROUP BY finding_type, severity
ORDER BY count(*) DESC;

\echo
\echo === 12. NEUE SP-DNS-* + SP-URLHAUS-* REGELN (P3) ===
SELECT
  policy_id,
  count(*) AS occurrences
FROM consolidated_findings
WHERE policy_id IN (
  'SP-DNS-011', 'SP-DNS-012', 'SP-DNS-013', 'SP-DNS-014',
  'SP-URLHAUS-001'
)
GROUP BY policy_id
ORDER BY policy_id;

\echo
\echo ============================================================================
\echo SNAPSHOT COMPLETE
\echo ============================================================================
