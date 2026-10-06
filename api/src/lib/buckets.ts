/**
 * Bucket-Namen an einer Stelle (Swarm-Umzug, 06.10.2026).
 *
 * Auf dem gemeinsamen MinIO des Datenknotens darf der Schluessel eines Feldes
 * nur Buckets mit seinem Praefix anfassen (vect-prod-, vect-test-; README von
 * vectigal/data-services, "Buckets und Schluessel"). MINIO_BUCKET_PREFIX traegt
 * dieses Praefix; auf docker02 bleibt es leer und jeder Name, wie er war.
 * scan-worker und report-worker lesen dieselbe Variable.
 *
 * Bewusst ein eigenes Modul und nicht lib/minio.ts: mehrere Tests ersetzen
 * lib/minio komplett durch eine Attrappe, die Namen waeren dort undefined.
 */
export const BUCKET_PREFIX = process.env.MINIO_BUCKET_PREFIX ?? '';

export const RAWDATA_BUCKET = `${BUCKET_PREFIX}scan-rawdata`;
export const REPORTS_BUCKET = `${BUCKET_PREFIX}scan-reports`;
export const AUTH_BUCKET = `${BUCKET_PREFIX}scan-authorizations`;
export const SCREENSHOTS_BUCKET = `${BUCKET_PREFIX}scan-screenshots`;
export const DEBUG_BUCKET = `${BUCKET_PREFIX}scan-debug`;
