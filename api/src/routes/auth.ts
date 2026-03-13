import { FastifyInstance } from 'fastify';

interface VerifyBody {
  password: string;
}

export async function authRoutes(server: FastifyInstance): Promise<void> {
  server.post<{ Body: VerifyBody }>('/api/auth/verify', async (request, reply) => {
    const accessPassword = process.env.VECTISCAN_ACCESS_PASSWORD;

    if (!accessPassword) {
      server.log.error('VECTISCAN_ACCESS_PASSWORD is not set');
      return reply.status(500).send({
        success: false,
        error: 'Server configuration error',
      });
    }

    const { password } = request.body || {};

    if (!password || typeof password !== 'string') {
      return reply.status(400).send({
        success: false,
        error: 'Password required',
      });
    }

    if (password === accessPassword) {
      return { success: true };
    }

    return reply.status(401).send({
      success: false,
      error: 'Falsches Passwort',
    });
  });
}
