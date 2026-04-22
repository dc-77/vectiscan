import { Client } from 'minio';

export const minioClient = new Client({
  endPoint: process.env.MINIO_ENDPOINT || 'localhost',
  port: Number(process.env.MINIO_PORT) || 9000,
  useSSL: process.env.MINIO_USE_SSL === 'true',
  accessKey: process.env.MINIO_ACCESS_KEY || 'minioadmin',
  secretKey: process.env.MINIO_SECRET_KEY || 'minioadmin',
});

const BUCKETS = ['scan-rawdata', 'scan-reports', 'scan-authorizations'];

export async function initBuckets(): Promise<void> {
  for (const bucket of BUCKETS) {
    const exists = await minioClient.bucketExists(bucket);
    if (!exists) {
      await minioClient.makeBucket(bucket);
    }
  }
}

export async function getPresignedUrl(
  bucket: string,
  objectName: string,
): Promise<string> {
  const sevenDays = 7 * 24 * 60 * 60;
  return minioClient.presignedGetObject(bucket, objectName, sevenDays);
}
