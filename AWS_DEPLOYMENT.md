# AWS Deployment Guide — Unified Secure Platform Backend

**ECS Fargate Deployment for Fastify API**

---

## Quick Start (5 minutes)

```bash
# 1. Build Docker image
docker build -f apps/api/Dockerfile -t uspservice-api:latest .

# 2. Tag for AWS ECR
docker tag uspservice-api:latest ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/uspservice-api:latest

# 3. Push to ECR
aws ecr get-login-password | docker login --username AWS --password-stdin ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com
docker push ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/uspservice-api:latest

# 4. Update ECS service
aws ecs update-service \
  --cluster uspservice-prod \
  --service uspservice-api-service \
  --force-new-deployment \
  --region us-east-1

# 5. Monitor deployment
aws ecs describe-services \
  --cluster uspservice-prod \
  --services uspservice-api-service \
  --region us-east-1
```

---

## Docker Image Details

### Current Dockerfile (Multi-stage Build)

- **Builder Stage**: Installs deps, builds TypeScript, generates Prisma client
- **Runtime Stage**: Alpine Linux (small, secure)
- **Health Check**: Pings `/health` endpoint every 30s
- **Entrypoint**: Runs `node apps/api/dist/index.js`

### Optimization Notes

- Alpine base (4.8MB) vs Node full (900MB) = **95% smaller**
- Multi-stage build = no build tools in production image
- Health check = ECS auto-restarts failed tasks

---

## Environment Variables

### In ECS Task Definition (Stored in Secrets Manager)

| Variable | Source | Description |
|----------|--------|-------------|
| `DATABASE_URL` | Secrets Manager | MongoDB Atlas connection |
| `CORS_ORIGIN` | Secrets Manager | Frontend domain (security) |
| `NODE_ENV` | Environment | Set to `production` |
| `PORT` | Environment | Set to `4000` |
| `LOG_LEVEL` | Environment | `warn` (production), `debug` (dev) |
| `NVD_API_URL` | Environment | External NVD API |
| `OSV_API_URL` | Environment | External OSV API |

### Scanner Credentials (Optional)

If using paid scanners, store in Secrets Manager:

```bash
aws secretsmanager create-secret \
  --name uspservice/prod/scanner-creds \
  --secret-string '{
    "SONATYPE_USERNAME": "...",
    "SONATYPE_PASSWORD": "..."
  }'
```

Then reference in task definition:

```json
{
  "name": "SONATYPE_USERNAME",
  "valueFrom": "arn:aws:secretsmanager:us-east-1:ACCOUNT_ID:secret:uspservice/prod/scanner-creds:SONATYPE_USERNAME::"
}
```

---

## Deployment Checklist

### Pre-Deployment

- [ ] All environment variables in Secrets Manager
- [ ] Docker image builds without errors
- [ ] Health check endpoint responds with 200 status
- [ ] Logs are structured (JSON format for CloudWatch)
- [ ] No hardcoded credentials in code/Dockerfile

### Deployment

- [ ] Image pushed to ECR
- [ ] Task definition registered with latest image
- [ ] ECS service updated
- [ ] Desired task count matches actual running tasks

### Post-Deployment

- [ ] Tasks are in `RUNNING` state
- [ ] Health checks passing
- [ ] ALB target group showing `healthy`
- [ ] Logs appearing in CloudWatch
- [ ] API responding to `/health` endpoint

---

## Monitoring

### View Service Status

```bash
aws ecs describe-services \
  --cluster uspservice-prod \
  --services uspservice-api-service \
  --region us-east-1 \
  --query 'services[0].[runningCount,desiredCount,status]'
```

### View Task Logs

```bash
# Stream logs in real-time
aws logs tail /ecs/uspservice-api-prod --follow

# View last 100 lines
aws logs tail /ecs/uspservice-api-prod --max-items 100

# Search for errors
aws logs filter-log-events \
  --log-group-name /ecs/uspservice-api-prod \
  --filter-pattern "ERROR"
```

### View Task Details

```bash
# List running tasks
aws ecs list-tasks --cluster uspservice-prod

# Describe a specific task
aws ecs describe-tasks \
  --cluster uspservice-prod \
  --tasks arn:aws:ecs:us-east-1:ACCOUNT_ID:task/uspservice-prod/task-id
```

---

## Scaling

### Auto Scaling Policy

Configured to:
- **Min tasks**: 2 (high availability)
- **Max tasks**: 10 (cost control)
- **Target CPU**: 70% average
- **Scale out cooldown**: 60 seconds
- **Scale in cooldown**: 300 seconds

### Manual Scaling

```bash
# Scale to 5 tasks
aws ecs update-service \
  --cluster uspservice-prod \
  --service uspservice-api-service \
  --desired-count 5

# Scale down to 2 tasks
aws ecs update-service \
  --cluster uspservice-prod \
  --service uspservice-api-service \
  --desired-count 2
```

---

## Troubleshooting

### Task Stuck in `PROVISIONING`

```bash
# Check task details
aws ecs describe-tasks --cluster uspservice-prod --tasks <task-arn>

# Common issues:
# - Task role missing permissions
# - Secrets Manager secrets don't exist
# - ECR image doesn't exist or permissions denied

# Solution: Update task definition and redeploy
aws ecs update-service \
  --cluster uspservice-prod \
  --service uspservice-api-service \
  --force-new-deployment
```

### Target Group Showing `Unhealthy`

```bash
# Check health check configuration
aws elbv2 describe-target-groups \
  --names uspservice-api-tg \
  --query 'TargetGroups[0].[HealthCheckPath,HealthCheckIntervalSeconds,HealthCheckTimeoutSeconds]'

# Verify health endpoint responds
curl http://ALB_IP:4000/health

# Check task security group allows port 4000 from ALB SG
aws ec2 describe-security-groups --group-ids <task-sg-id>
```

### High Memory/CPU Usage

```bash
# Check CloudWatch metrics
aws cloudwatch get-metric-statistics \
  --namespace AWS/ECS \
  --metric-name MemoryUtilization \
  --dimensions Name=ServiceName,Value=uspservice-api-service Name=ClusterName,Value=uspservice-prod \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Average

# View logs for memory issues
aws logs filter-log-events \
  --log-group-name /ecs/uspservice-api-prod \
  --filter-pattern "heap"
```

---

## Rolling Back to Previous Version

```bash
# List recent task definitions
aws ecs describe-task-definition \
  --task-definition uspservice-api-prod \
  --query 'taskDefinition.revision'

# Get previous revision number
PREV_REVISION=$(($(aws ecs describe-task-definition --task-definition uspservice-api-prod --query 'taskDefinition.revision' --output text) - 1))

# Update service to use previous task definition
aws ecs update-service \
  --cluster uspservice-prod \
  --service uspservice-api-service \
  --task-definition uspservice-api-prod:$PREV_REVISION \
  --force-new-deployment
```

---

## Production Best Practices

### 1. Always Use Image Tags, Never `latest`

```bash
# ❌ Don't do this
docker tag uspservice-api:latest ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/uspservice-api:latest

# ✅ Do this
docker tag uspservice-api:v1.2.3 ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/uspservice-api:v1.2.3
docker tag uspservice-api:v1.2.3 ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/uspservice-api:prod-$(date +%s)
```

### 2. Implement Graceful Shutdown

In Fastify app:

```typescript
process.on('SIGTERM', async () => {
  app.log.info('SIGTERM received, shutting down gracefully...');
  await app.close();
  process.exit(0);
});
```

### 3. Use Structured Logging

```typescript
app.log.info({ endpoint: '/api/findings', duration_ms: 245 });
// Easier to parse in CloudWatch Logs Insights
```

### 4. Set Proper Resource Limits

- **CPU**: 256 CPU units (0.25 vCPU) = $0.04/hour
- **Memory**: 512 MB
- Max concurrent connections: ~500 per task

Increase if:
- CPU consistently > 70%
- Memory consistently > 80%
- Requests timing out

### 5. Monitor Database Connection Pool

```typescript
// In Prisma config
const prisma = new PrismaClient({
  datasources: {
    db: {
      url: env.DATABASE_URL,
    },
  },
});

// Connection pool size (adjust based on load)
// Default: min_pool_size=2, max_pool_size=10
```

---

## Cost Optimization

### Current Configuration

- **2 tasks × 0.25 vCPU × 730 hours/month** = $15-20
- **ALB** = ~$16/month
- **Data transfer** = ~$2-5/month
- **Total** = ~$35-40/month

### To Reduce Costs

1. **Use on-demand only** (currently is)
2. **Set min capacity to 1** (during low traffic)
3. **Use smaller memory** (256MB instead of 512MB)
4. **Consolidate environments** (STG/QAT on same ALB)

---

## Deployment via GitHub Actions

Create `.github/workflows/deploy-api.yml`:

```yaml
name: Deploy Backend to AWS ECS

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v2
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1
      
      - name: Login to Amazon ECR
        run: |
          aws ecr get-login-password | docker login --username AWS --password-stdin ${{ secrets.AWS_ACCOUNT_ID }}.dkr.ecr.us-east-1.amazonaws.com
      
      - name: Build and push Docker image
        run: |
          docker build -f apps/api/Dockerfile -t uspservice-api:latest .
          docker tag uspservice-api:latest ${{ secrets.AWS_ACCOUNT_ID }}.dkr.ecr.us-east-1.amazonaws.com/uspservice-api:${{ github.sha }}
          docker push ${{ secrets.AWS_ACCOUNT_ID }}.dkr.ecr.us-east-1.amazonaws.com/uspservice-api:${{ github.sha }}
      
      - name: Update ECS service
        run: |
          aws ecs update-service \
            --cluster uspservice-prod \
            --service uspservice-api-service \
            --force-new-deployment \
            --region us-east-1
      
      - name: Wait for deployment
        run: |
          aws ecs wait services-stable \
            --cluster uspservice-prod \
            --services uspservice-api-service \
            --region us-east-1
```

Add GitHub secrets:
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_ACCOUNT_ID`

---

## Network Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Internet (HTTPS)                          │
└──────────────────────┬──────────────────────────────────────┘
                       │ api.hakward.com
                       ▼
         ┌─────────────────────────────┐
         │   AWS Route 53 (DNS)        │
         │   ├─ api.hakward.com → ALB │
         │   └─ hakward.com → CloudFront
         └────────────┬────────────────┘
                      │
      ┌───────────────┴───────────────┐
      │   Application Load Balancer   │
      │   - HTTPS (443)               │
      │   - HTTP redirect → HTTPS     │
      │   - Health check: /health     │
      └───────────────┬───────────────┘
                      │
      ┌───────────────┴───────────────┐
      │   Target Group (4000)         │
      │   - 2 Fargate Tasks (running) │
      │   - Auto-scaling 2-10 tasks   │
      └───────────────┬───────────────┘
                      │
          ┌───────────┼───────────┐
          ▼           ▼           ▼
      ┌─────────┐ ┌─────────┐ ┌─────────┐
      │ Task 1  │ │ Task 2  │ │ Task N  │
      │ (4000)  │ │ (4000)  │ │ (4000)  │
      └────┬────┘ └────┬────┘ └────┬────┘
           │           │           │
           └───────────┼───────────┘
                       │
                       ▼
        ┌──────────────────────────────┐
        │    MongoDB Atlas (External)  │
        │    (No AWS service)          │
        └──────────────────────────────┘
```

---

## Additional Resources

- **Fargate Pricing**: https://aws.amazon.com/fargate/pricing/
- **ECS Best Practices**: https://docs.aws.amazon.com/AmazonECS/latest/bestpracticesguide/
- **Troubleshooting ECS**: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/troubleshooting.html

