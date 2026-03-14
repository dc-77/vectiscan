import fs from 'fs';
import path from 'path';

describe('MVP Schema Migration', () => {
  const migrationPath = path.join(__dirname, '..', 'migrations', '003_mvp_schema.sql');

  it('migration file should exist', () => {
    expect(fs.existsSync(migrationPath)).toBe(true);
  });

  it('should define all required tables', () => {
    const sql = fs.readFileSync(migrationPath, 'utf-8');

    expect(sql).toContain('CREATE TABLE customers');
    expect(sql).toContain('CREATE TABLE orders');
    expect(sql).toContain('CREATE TABLE scan_results');
    expect(sql).toContain('CREATE TABLE reports');
    expect(sql).toContain('CREATE TABLE audit_log');
  });

  it('should drop old prototype tables', () => {
    const sql = fs.readFileSync(migrationPath, 'utf-8');

    expect(sql).toContain('DROP TABLE IF EXISTS scan_results');
    expect(sql).toContain('DROP TABLE IF EXISTS reports');
    expect(sql).toContain('DROP TABLE IF EXISTS scans');
  });

  it('customers table should have required columns', () => {
    const sql = fs.readFileSync(migrationPath, 'utf-8');

    expect(sql).toContain('email');
    expect(sql).toContain('stripe_id');
    expect(sql).toContain('UNIQUE');
  });

  it('orders table should have required columns', () => {
    const sql = fs.readFileSync(migrationPath, 'utf-8');

    expect(sql).toContain('customer_id');
    expect(sql).toContain('target_url');
    expect(sql).toContain('target_ip');
    expect(sql).toContain('verification_method');
    expect(sql).toContain('verification_token');
    expect(sql).toContain('verified_at');
    expect(sql).toContain('stripe_payment_id');
    expect(sql).toContain('stripe_checkout_id');
    expect(sql).toContain('paid_at');
    expect(sql).toContain('amount_cents');
    expect(sql).toContain('currency');
    expect(sql).toContain('discovered_hosts');
    expect(sql).toContain('hosts_total');
    expect(sql).toContain('hosts_completed');
    expect(sql).toContain('current_phase');
    expect(sql).toContain('current_tool');
    expect(sql).toContain('current_host');
    expect(sql).toContain('error_message');
    expect(sql).toContain('scan_started_at');
    expect(sql).toContain('scan_finished_at');
  });

  it('orders table should have package CHECK constraint', () => {
    const sql = fs.readFileSync(migrationPath, 'utf-8');

    expect(sql).toContain("'basic'");
    expect(sql).toContain("'professional'");
    expect(sql).toContain("'nis2'");
    expect(sql).toContain('chk_orders_package');
  });

  it('orders table should have verification_method CHECK constraint', () => {
    const sql = fs.readFileSync(migrationPath, 'utf-8');

    expect(sql).toContain("'dns_txt'");
    expect(sql).toContain("'file'");
    expect(sql).toContain("'meta_tag'");
  });

  it('reports table should have download_token and expires_at', () => {
    const sql = fs.readFileSync(migrationPath, 'utf-8');

    expect(sql).toContain('download_token');
    expect(sql).toContain('download_count');
    expect(sql).toContain('expires_at');
  });

  it('reports table should reference orders (not scans)', () => {
    const sql = fs.readFileSync(migrationPath, 'utf-8');

    expect(sql).toContain('order_id');
    expect(sql).toContain('REFERENCES orders(id)');
  });

  it('scan_results should reference orders via order_id', () => {
    const sql = fs.readFileSync(migrationPath, 'utf-8');

    // Find scan_results table definition and check it uses order_id
    const scanResultsSection = sql.substring(
      sql.indexOf('CREATE TABLE scan_results'),
      sql.indexOf('CREATE TABLE reports')
    );
    expect(scanResultsSection).toContain('order_id');
    expect(scanResultsSection).toContain('REFERENCES orders(id)');
  });

  it('audit_log table should have required columns', () => {
    const sql = fs.readFileSync(migrationPath, 'utf-8');

    expect(sql).toContain('BIGSERIAL');
    expect(sql).toContain('action');
    expect(sql).toContain('ip_address');
    expect(sql).toContain('INET');
  });

  it('should create required indexes', () => {
    const sql = fs.readFileSync(migrationPath, 'utf-8');

    expect(sql).toContain('idx_orders_status');
    expect(sql).toContain('idx_orders_customer');
    expect(sql).toContain('idx_scan_results_order');
    expect(sql).toContain('idx_audit_log_order');
  });
});
