import crypto from 'crypto';
import { FastifyInstance } from 'fastify';
import { createClient } from 'redis';
import { query } from '../lib/db.js';
import { hashPassword, verifyPasswordHash, generateJwt, JwtPayload } from '../lib/auth.js';
import { requireAuth } from '../middleware/requireAuth.js';
import { requireAdmin } from '../middleware/requireAdmin.js';
import { sendPasswordResetEmail } from '../lib/email.js';
import { audit } from '../lib/audit.js';

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MIN_PASSWORD_LENGTH = 8;

interface RegisterBody {
  email: string;
  password: string;
  companyName?: string;
}

interface LoginBody {
  email: string;
  password: string;
}

interface ForgotPasswordBody {
  email: string;
}

interface ResetPasswordBody {
  token: string;
  password: string;
}

export async function authRoutes(server: FastifyInstance): Promise<void> {
  // POST /api/auth/register
  server.post<{ Body: RegisterBody }>('/api/auth/register', async (request, reply) => {
    const { email, password, companyName } = request.body || {};

    if (!email || !EMAIL_REGEX.test(email)) {
      return reply.status(400).send({ success: false, error: 'Ungültige E-Mail-Adresse.' });
    }

    if (!password || password.length < MIN_PASSWORD_LENGTH) {
      return reply.status(400).send({
        success: false,
        error: `Passwort muss mindestens ${MIN_PASSWORD_LENGTH} Zeichen haben.`,
      });
    }

    // Check if user already exists
    const existing = await query<{ id: string }>('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
    if (existing.rows.length > 0) {
      return reply.status(409).send({ success: false, error: 'Ein Konto mit dieser E-Mail existiert bereits.' });
    }

    // Find or create customer record (with optional company name)
    const customerResult = await query<{ id: string }>(
      `INSERT INTO customers (email, company_name) VALUES ($1, $2)
       ON CONFLICT (email) DO UPDATE SET company_name = COALESCE(EXCLUDED.company_name, customers.company_name)
       RETURNING id`,
      [email.toLowerCase(), companyName?.trim() || null],
    );
    const customerId = customerResult.rows[0].id;

    // Create user
    const passwordHash = await hashPassword(password);
    const userResult = await query<{ id: string; email: string; role: string }>(
      "INSERT INTO users (email, password_hash, role, customer_id) VALUES ($1, $2, 'customer', $3) RETURNING id, email, role",
      [email.toLowerCase(), passwordHash, customerId],
    );
    const user = userResult.rows[0];

    const payload: JwtPayload = {
      sub: user.id,
      role: user.role as 'customer' | 'admin',
      customerId,
      email: user.email,
    };

    audit({ action: 'user.registered', details: { userId: user.id, email: user.email }, ip: request.ip });

    return reply.status(201).send({
      success: true,
      data: {
        token: generateJwt(payload),
        user: { id: user.id, email: user.email, role: user.role },
      },
    });
  });

  // POST /api/auth/login
  server.post<{ Body: LoginBody }>('/api/auth/login', async (request, reply) => {
    const { email, password } = request.body || {};

    if (!email || !password) {
      return reply.status(400).send({ success: false, error: 'E-Mail und Passwort erforderlich.' });
    }

    const result = await query<{ id: string; email: string; role: string; password_hash: string; customer_id: string | null }>(
      'SELECT id, email, role, password_hash, customer_id FROM users WHERE email = $1',
      [email.toLowerCase()],
    );

    if (result.rows.length === 0) {
      return reply.status(401).send({ success: false, error: 'Ungültige Anmeldedaten.' });
    }

    const user = result.rows[0];
    const valid = await verifyPasswordHash(password, user.password_hash);
    if (!valid) {
      return reply.status(401).send({ success: false, error: 'Ungültige Anmeldedaten.' });
    }

    const payload: JwtPayload = {
      sub: user.id,
      role: user.role as 'customer' | 'admin',
      customerId: user.customer_id,
      email: user.email,
    };

    audit({ action: 'user.login', details: { userId: user.id, email: user.email }, ip: request.ip });

    return {
      success: true,
      data: {
        token: generateJwt(payload),
        user: { id: user.id, email: user.email, role: user.role },
      },
    };
  });

  // GET /api/auth/me
  server.get('/api/auth/me', { preHandler: [requireAuth] }, async (request) => {
    const user = request.user!;
    return {
      success: true,
      data: {
        id: user.sub,
        email: user.email,
        role: user.role,
        customerId: user.customerId,
      },
    };
  });

  // POST /api/auth/forgot-password
  server.post<{ Body: ForgotPasswordBody }>('/api/auth/forgot-password', async (request, reply) => {
    const { email } = request.body || {};

    // Always return 200 to prevent user enumeration
    const successResponse = {
      success: true,
      data: { message: 'Falls ein Konto mit dieser E-Mail existiert, wurde ein Reset-Link gesendet.' },
    };

    if (!email || !EMAIL_REGEX.test(email)) {
      return reply.status(400).send({ success: false, error: 'Ungültige E-Mail-Adresse.' });
    }

    const result = await query<{ id: string }>(
      'SELECT id FROM users WHERE email = $1',
      [email.toLowerCase()],
    );

    if (result.rows.length === 0) {
      return successResponse;
    }

    const resetToken = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    await query(
      'UPDATE users SET reset_token = $1, reset_token_expires_at = $2, updated_at = NOW() WHERE email = $3',
      [resetToken, expiresAt.toISOString(), email.toLowerCase()],
    );

    // Fire-and-forget — don't block the response
    sendPasswordResetEmail(email.toLowerCase(), resetToken).catch(() => {});

    return successResponse;
  });

  // POST /api/auth/reset-password
  server.post<{ Body: ResetPasswordBody }>('/api/auth/reset-password', async (request, reply) => {
    const { token, password } = request.body || {};

    if (!token) {
      return reply.status(400).send({ success: false, error: 'Token erforderlich.' });
    }

    if (!password || password.length < MIN_PASSWORD_LENGTH) {
      return reply.status(400).send({
        success: false,
        error: `Passwort muss mindestens ${MIN_PASSWORD_LENGTH} Zeichen haben.`,
      });
    }

    const result = await query<{ id: string; email: string; role: string; customer_id: string | null; reset_token_expires_at: Date }>(
      'SELECT id, email, role, customer_id, reset_token_expires_at FROM users WHERE reset_token = $1',
      [token],
    );

    if (result.rows.length === 0) {
      return reply.status(400).send({ success: false, error: 'Ungültiger oder abgelaufener Token.' });
    }

    const user = result.rows[0];

    if (new Date() > new Date(user.reset_token_expires_at)) {
      // Clean up expired token
      await query('UPDATE users SET reset_token = NULL, reset_token_expires_at = NULL WHERE id = $1', [user.id]);
      return reply.status(400).send({ success: false, error: 'Ungültiger oder abgelaufener Token.' });
    }

    // Update password and clear token
    const passwordHash = await hashPassword(password);
    await query(
      'UPDATE users SET password_hash = $1, reset_token = NULL, reset_token_expires_at = NULL, updated_at = NOW() WHERE id = $2',
      [passwordHash, user.id],
    );

    // Return JWT so user is logged in immediately
    const payload: JwtPayload = {
      sub: user.id,
      role: user.role as 'customer' | 'admin',
      customerId: user.customer_id,
      email: user.email,
    };

    audit({ action: 'user.password_reset', details: { userId: user.id, email: user.email }, ip: request.ip });

    return {
      success: true,
      data: {
        token: generateJwt(payload),
        user: { id: user.id, email: user.email, role: user.role },
      },
    };
  });

  // PUT /api/auth/password — change own password (authenticated)
  server.put<{ Body: { currentPassword: string; newPassword: string } }>('/api/auth/password', { preHandler: [requireAuth] }, async (request, reply) => {
    const user = request.user!;
    const { currentPassword, newPassword } = request.body || {};

    if (!currentPassword || !newPassword) {
      return reply.status(400).send({ success: false, error: 'Aktuelles und neues Passwort erforderlich.' });
    }

    if (newPassword.length < MIN_PASSWORD_LENGTH) {
      return reply.status(400).send({ success: false, error: `Neues Passwort muss mindestens ${MIN_PASSWORD_LENGTH} Zeichen haben.` });
    }

    const result = await query<{ password_hash: string }>('SELECT password_hash FROM users WHERE id = $1', [user.sub]);
    if (result.rows.length === 0) {
      return reply.status(404).send({ success: false, error: 'Benutzer nicht gefunden.' });
    }

    const valid = await verifyPasswordHash(currentPassword, result.rows[0].password_hash);
    if (!valid) {
      return reply.status(401).send({ success: false, error: 'Aktuelles Passwort ist falsch.' });
    }

    const newHash = await hashPassword(newPassword);
    await query('UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2', [newHash, user.sub]);

    return { success: true, data: { message: 'Passwort geändert.' } };
  });

  // GET /api/auth/verified-domains — list verified domains for current user
  server.get('/api/auth/verified-domains', { preHandler: [requireAuth] }, async (request) => {
    const user = request.user!;

    // Resolve customer_id: JWT may have null for admins, look up via email
    let customerId = user.customerId;
    if (!customerId) {
      const custResult = await query<{ id: string }>(
        'SELECT id FROM customers WHERE email = $1',
        [user.email],
      );
      if (custResult.rows.length === 0) {
        return { success: true, data: { domains: [] } };
      }
      customerId = custResult.rows[0].id;
    }

    const result = await query<{
      domain: string;
      verification_method: string;
      verified_at: string;
      expires_at: string;
    }>(
      `SELECT domain, verification_method, verified_at, expires_at
       FROM verified_domains
       WHERE customer_id = $1 AND expires_at > NOW()
       ORDER BY domain ASC`,
      [customerId],
    );

    return { success: true, data: { domains: result.rows } };
  });

  // ── Admin endpoints ──

  // GET /api/admin/users — list all users
  server.get('/api/admin/users', { preHandler: [requireAuth, requireAdmin] }, async () => {
    const result = await query(
      `SELECT u.id, u.email, u.role, u.created_at, u.updated_at,
              u.customer_id,
              COUNT(o.id)::int AS order_count
       FROM users u
       LEFT JOIN orders o ON o.customer_id = u.customer_id
       GROUP BY u.id
       ORDER BY u.created_at DESC`,
    );

    const users = result.rows.map((row: Record<string, unknown>) => ({
      id: row.id,
      email: row.email,
      role: row.role,
      customerId: row.customer_id,
      orderCount: row.order_count ?? 0,
      createdAt: (row.created_at as Date).toISOString(),
    }));

    return { success: true, data: { users } };
  });

  // PUT /api/admin/users/:id/role — change user role
  server.put<{ Params: { id: string }; Body: { role: string } }>('/api/admin/users/:id/role', { preHandler: [requireAuth, requireAdmin] }, async (request, reply) => {
    const { id } = request.params;
    const { role } = request.body || {};
    const admin = request.user!;

    if (!role || !['customer', 'admin'].includes(role)) {
      return reply.status(400).send({ success: false, error: 'Rolle muss "customer" oder "admin" sein.' });
    }

    if (id === admin.sub) {
      return reply.status(400).send({ success: false, error: 'Eigene Rolle kann nicht geändert werden.' });
    }

    const result = await query('UPDATE users SET role = $1, updated_at = NOW() WHERE id = $2 RETURNING id, email, role', [role, id]);
    if (result.rows.length === 0) {
      return reply.status(404).send({ success: false, error: 'Benutzer nicht gefunden.' });
    }

    const updated = result.rows[0] as Record<string, unknown>;
    audit({ action: 'user.role_changed', details: { targetUserId: id, newRole: role, admin: admin.email }, ip: request.ip });

    return { success: true, data: { id: updated.id, email: updated.email, role: updated.role } };
  });

  // DELETE /api/admin/users/:id — delete user
  server.delete<{ Params: { id: string } }>('/api/admin/users/:id', { preHandler: [requireAuth, requireAdmin] }, async (request, reply) => {
    const { id } = request.params;
    const admin = request.user!;

    if (id === admin.sub) {
      return reply.status(400).send({ success: false, error: 'Eigenen Account kann man nicht löschen.' });
    }

    const check = await query<{ email: string }>('SELECT email FROM users WHERE id = $1', [id]);
    if (check.rows.length === 0) {
      return reply.status(404).send({ success: false, error: 'Benutzer nicht gefunden.' });
    }

    await query('DELETE FROM users WHERE id = $1', [id]);
    audit({ action: 'user.deleted', details: { deletedUserId: id, email: check.rows[0].email, admin: admin.email }, ip: request.ip });

    return { success: true, data: null };
  });

  // GET /api/admin/stats — system statistics
  server.get('/api/admin/stats', { preHandler: [requireAuth, requireAdmin] }, async () => {
    const [usersResult, ordersResult, statusResult, recentResult] = await Promise.all([
      query('SELECT COUNT(*)::int AS total, COUNT(*) FILTER (WHERE role = \'admin\')::int AS admins FROM users'),
      query('SELECT COUNT(*)::int AS total FROM orders'),
      query(`SELECT status, COUNT(*)::int AS count FROM orders GROUP BY status`),
      query(`SELECT COUNT(*)::int AS today FROM orders WHERE created_at >= CURRENT_DATE`),
    ]);

    const users = usersResult.rows[0] as Record<string, unknown>;
    const orders = ordersResult.rows[0] as Record<string, unknown>;
    const recent = recentResult.rows[0] as Record<string, unknown>;

    const statusBreakdown: Record<string, number> = {};
    for (const row of statusResult.rows) {
      const r = row as Record<string, unknown>;
      statusBreakdown[r.status as string] = r.count as number;
    }

    return {
      success: true,
      data: {
        users: { total: users.total, admins: users.admins },
        orders: { total: orders.total, today: recent.today, byStatus: statusBreakdown },
      },
    };
  });

  // GET /api/admin/ai-costs — AI cost analytics
  server.get('/api/admin/ai-costs', { preHandler: [requireAuth, requireAdmin] }, async () => {
    // Get all cost data from scan_results
    const costResult = await query(
      `SELECT sr.order_id, sr.tool_name, sr.raw_output, sr.created_at, o.target_url, o.package
       FROM scan_results sr
       JOIN orders o ON sr.order_id = o.id
       WHERE sr.tool_name = 'report_cost'
       ORDER BY sr.created_at DESC
       LIMIT 100`,
    );

    let totalCost = 0;
    const byModel: Record<string, {count: number; total_usd: number}> = {};
    const byPackage: Record<string, {count: number; total_usd: number}> = {};
    const recentReports: Array<{orderId: string; domain: string; package: string; cost_usd: number; model: string; createdAt: string}> = [];

    for (const row of costResult.rows as Array<Record<string, unknown>>) {
      try {
        const cost = JSON.parse(row.raw_output as string);
        if (!cost.total_cost_usd) continue;

        totalCost += cost.total_cost_usd;
        const model = cost.model || 'unknown';
        const pkg = (row.package as string) || 'unknown';

        if (!byModel[model]) byModel[model] = {count: 0, total_usd: 0};
        byModel[model].count++;
        byModel[model].total_usd += cost.total_cost_usd;

        if (!byPackage[pkg]) byPackage[pkg] = {count: 0, total_usd: 0};
        byPackage[pkg].count++;
        byPackage[pkg].total_usd += cost.total_cost_usd;

        if (recentReports.length < 20) {
          recentReports.push({
            orderId: (row.order_id as string) || '',
            domain: (row.target_url as string) || '',
            package: pkg,
            cost_usd: Math.round(cost.total_cost_usd * 10000) / 10000,
            model,
            createdAt: row.created_at ? (row.created_at as Date).toISOString() : '',
          });
        }
      } catch { /* skip unparseable */ }
    }

    // Round aggregates
    for (const m of Object.values(byModel)) m.total_usd = Math.round(m.total_usd * 100) / 100;
    for (const p of Object.values(byPackage)) {
      p.total_usd = Math.round(p.total_usd * 100) / 100;
    }

    return {
      success: true,
      data: {
        total_cost_usd: Math.round(totalCost * 100) / 100,
        cost_by_model: byModel,
        cost_by_package: byPackage,
        recent_reports: recentReports,
      },
    };
  });

  // POST /api/admin/diagnose — trigger scan-worker tool diagnostics
  server.post<{ Body: { probe?: string } }>('/api/admin/diagnose', { preHandler: [requireAuth, requireAdmin] }, async (request, reply) => {
    const probe = request.body?.probe || undefined;
    const requestId = crypto.randomUUID();

    // Push diagnose job to Redis queue
    const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';
    const redis = createClient({ url: redisUrl });
    await redis.connect();

    await redis.rPush('diagnose-pending', JSON.stringify({
      requestId,
      probe: probe || null,
    }));

    // Poll for result (max 30s)
    const maxWait = probe ? 60000 : 30000;
    const pollInterval = 500;
    const start = Date.now();

    while (Date.now() - start < maxWait) {
      const raw = await redis.get(`diagnose:result:${requestId}`);
      if (raw) {
        await redis.disconnect();
        const result = JSON.parse(raw);
        return { success: true, data: result };
      }
      await new Promise(r => setTimeout(r, pollInterval));
    }

    await redis.disconnect();
    return reply.status(504).send({
      success: false,
      error: 'Diagnose timeout — scan-worker did not respond within 30s. Is it running?',
    });
  });
}
