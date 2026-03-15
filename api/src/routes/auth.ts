import { FastifyInstance } from 'fastify';
import { query } from '../lib/db.js';
import { hashPassword, verifyPasswordHash, generateJwt, JwtPayload } from '../lib/auth.js';
import { requireAuth } from '../middleware/requireAuth.js';

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MIN_PASSWORD_LENGTH = 8;

interface RegisterBody {
  email: string;
  password: string;
}

interface LoginBody {
  email: string;
  password: string;
}

export async function authRoutes(server: FastifyInstance): Promise<void> {
  // POST /api/auth/register
  server.post<{ Body: RegisterBody }>('/api/auth/register', async (request, reply) => {
    const { email, password } = request.body || {};

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

    // Find or create customer record
    const customerResult = await query<{ id: string }>(
      'INSERT INTO customers (email) VALUES ($1) ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email RETURNING id',
      [email.toLowerCase()],
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
}
