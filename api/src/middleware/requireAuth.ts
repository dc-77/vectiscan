import { FastifyRequest, FastifyReply } from 'fastify';
import { verifyJwt, JwtPayload } from '../lib/auth.js';

declare module 'fastify' {
  interface FastifyRequest {
    user?: JwtPayload;
  }
}

export async function requireAuth(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  const header = request.headers.authorization;
  const queryToken = (request.query as Record<string, string>)?.token;

  const token = header?.startsWith('Bearer ') ? header.slice(7) : queryToken;

  if (!token) {
    return reply.status(401).send({ success: false, error: 'Authentication required' });
  }

  try {
    request.user = verifyJwt(token);
  } catch {
    return reply.status(401).send({ success: false, error: 'Invalid or expired token' });
  }
}
