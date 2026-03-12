import { buildServer } from '../server';

describe('VectiScan API', () => {
  it('should start and respond to health check', async () => {
    const server = buildServer();
    const response = await server.inject({
      method: 'GET',
      url: '/health',
    });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      success: true,
      data: { status: 'ok' },
    });
    await server.close();
  });
});
