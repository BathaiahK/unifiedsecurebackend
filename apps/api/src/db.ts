import { PrismaClient } from '@prisma/client';
import { MongoClient } from 'mongodb';

const globalForPrisma = globalThis as unknown as { prisma: PrismaClient; mongoClient?: MongoClient };

export const prisma =
  globalForPrisma.prisma ??
  new PrismaClient({
    log: process.env['NODE_ENV'] === 'development' ? ['query', 'error'] : ['error'],
  });

// Direct MongoDB client for operations that don't require transaction support
export const mongoClient =
  globalForPrisma.mongoClient ??
  new MongoClient(process.env.DATABASE_URL || 'mongodb://127.0.0.1:27017/uspservice?directConnection=true');

if (process.env['NODE_ENV'] !== 'production') {
  globalForPrisma.prisma = prisma;
  globalForPrisma.mongoClient = mongoClient;
}
