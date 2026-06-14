#!/bin/bash

################################################################################
# AWS Deployment Script for Unified Secure Platform Backend
#
# Usage: ./scripts/deploy-to-aws.sh [prod|stg|qat] [image-tag]
#
# Examples:
#   ./scripts/deploy-to-aws.sh prod v1.2.3
#   ./scripts/deploy-to-aws.sh stg latest
#
################################################################################

set -e

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Parse arguments
ENVIRONMENT="${1:-prod}"
IMAGE_TAG="${2:-latest}"

# Validate environment
if [[ ! "$ENVIRONMENT" =~ ^(prod|stg|qat)$ ]]; then
  echo -e "${RED}Error: Environment must be prod, stg, or qat${NC}"
  exit 1
fi

# Configuration based on environment
case "$ENVIRONMENT" in
  prod)
    AWS_REGION="us-east-1"
    CLUSTER_NAME="uspservice-prod"
    SERVICE_NAME="uspservice-api-service"
    TASK_FAMILY="uspservice-api-prod"
    LOG_GROUP="/ecs/uspservice-api-prod"
    ;;
  stg)
    AWS_REGION="us-east-1"
    CLUSTER_NAME="uspservice-stg"
    SERVICE_NAME="uspservice-api-service-stg"
    TASK_FAMILY="uspservice-api-stg"
    LOG_GROUP="/ecs/uspservice-api-stg"
    ;;
  qat)
    AWS_REGION="us-east-1"
    CLUSTER_NAME="uspservice-qat"
    SERVICE_NAME="uspservice-api-service-qat"
    TASK_FAMILY="uspservice-api-qat"
    LOG_GROUP="/ecs/uspservice-api-qat"
    ;;
esac

# Get AWS Account ID
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
ECR_REGISTRY="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
ECR_REPOSITORY="uspservice-api"
IMAGE_URI="${ECR_REGISTRY}/${ECR_REPOSITORY}:${IMAGE_TAG}"

echo -e "${YELLOW}=== AWS Deployment for USP Backend ===${NC}"
echo -e "Environment: ${GREEN}${ENVIRONMENT}${NC}"
echo -e "Region: ${GREEN}${AWS_REGION}${NC}"
echo -e "Image Tag: ${GREEN}${IMAGE_TAG}${NC}"
echo -e "Image URI: ${GREEN}${IMAGE_URI}${NC}"
echo ""

# Step 1: Verify AWS credentials
echo -e "${YELLOW}[1/6] Verifying AWS credentials...${NC}"
if ! aws sts get-caller-identity --region "$AWS_REGION" > /dev/null 2>&1; then
  echo -e "${RED}Error: AWS credentials not configured${NC}"
  echo "Run: aws configure"
  exit 1
fi
echo -e "${GREEN}✓ AWS credentials verified${NC}"

# Step 2: Verify ECR repository exists
echo -e "${YELLOW}[2/6] Verifying ECR repository...${NC}"
if ! aws ecr describe-repositories \
  --repository-names "$ECR_REPOSITORY" \
  --region "$AWS_REGION" > /dev/null 2>&1; then
  echo -e "${RED}Error: ECR repository not found: ${ECR_REPOSITORY}${NC}"
  echo "Create it with:"
  echo "  aws ecr create-repository --repository-name $ECR_REPOSITORY --region $AWS_REGION"
  exit 1
fi
echo -e "${GREEN}✓ ECR repository verified${NC}"

# Step 3: Check if image exists in ECR
echo -e "${YELLOW}[3/6] Checking if image exists in ECR...${NC}"
if ! aws ecr describe-images \
  --repository-name "$ECR_REPOSITORY" \
  --image-ids "imageTag=$IMAGE_TAG" \
  --region "$AWS_REGION" > /dev/null 2>&1; then
  echo -e "${YELLOW}⚠ Image not found in ECR. Did you build and push it?${NC}"
  echo ""
  echo "Build and push locally:"
  echo "  docker build -f apps/api/Dockerfile -t uspservice-api:${IMAGE_TAG} ."
  echo "  aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin ${ECR_REGISTRY}"
  echo "  docker tag uspservice-api:${IMAGE_TAG} ${IMAGE_URI}"
  echo "  docker push ${IMAGE_URI}"
  exit 1
fi
echo -e "${GREEN}✓ Image verified in ECR${NC}"

# Step 4: Register task definition
echo -e "${YELLOW}[4/6] Registering new task definition...${NC}"
TASK_DEF_JSON=$(cat <<EOF
{
  "family": "${TASK_FAMILY}",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "256",
  "memory": "512",
  "containerDefinitions": [
    {
      "name": "api",
      "image": "${IMAGE_URI}",
      "portMappings": [
        {
          "containerPort": 4000,
          "protocol": "tcp"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "${LOG_GROUP}",
          "awslogs-region": "${AWS_REGION}",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "secrets": [
        {
          "name": "DATABASE_URL",
          "valueFrom": "arn:aws:secretsmanager:${AWS_REGION}:${AWS_ACCOUNT_ID}:secret:uspservice/${ENVIRONMENT}/db-url"
        },
        {
          "name": "CORS_ORIGIN",
          "valueFrom": "arn:aws:secretsmanager:${AWS_REGION}:${AWS_ACCOUNT_ID}:secret:uspservice/${ENVIRONMENT}/cors-origin"
        }
      ],
      "environment": [
        {
          "name": "NODE_ENV",
          "value": "production"
        },
        {
          "name": "PORT",
          "value": "4000"
        },
        {
          "name": "HOST",
          "value": "0.0.0.0"
        },
        {
          "name": "LOG_LEVEL",
          "value": "warn"
        },
        {
          "name": "NVD_API_URL",
          "value": "https://services.nvd.nist.gov/rest/json/cves/2.0"
        },
        {
          "name": "OSV_API_URL",
          "value": "https://api.osv.dev/v1"
        }
      ]
    }
  ],
  "executionRoleArn": "arn:aws:iam::${AWS_ACCOUNT_ID}:role/uspservice-ecs-task-execution-role",
  "taskRoleArn": "arn:aws:iam::${AWS_ACCOUNT_ID}:role/uspservice-ecs-task-role"
}
EOF
)

TASK_DEF_ARN=$(aws ecs register-task-definition \
  --cli-input-json "$TASK_DEF_JSON" \
  --region "$AWS_REGION" \
  --query 'taskDefinition.taskDefinitionArn' \
  --output text)

echo -e "${GREEN}✓ Task definition registered: ${TASK_DEF_ARN}${NC}"

# Step 5: Update ECS service
echo -e "${YELLOW}[5/6] Updating ECS service...${NC}"
aws ecs update-service \
  --cluster "$CLUSTER_NAME" \
  --service "$SERVICE_NAME" \
  --task-definition "$TASK_DEF_ARN" \
  --force-new-deployment \
  --region "$AWS_REGION" > /dev/null

echo -e "${GREEN}✓ ECS service updated${NC}"

# Step 6: Wait for deployment to stabilize
echo -e "${YELLOW}[6/6] Waiting for deployment to stabilize (max 5 minutes)...${NC}"
if aws ecs wait services-stable \
  --cluster "$CLUSTER_NAME" \
  --services "$SERVICE_NAME" \
  --region "$AWS_REGION"; then
  echo -e "${GREEN}✓ Deployment successful!${NC}"
else
  echo -e "${RED}⚠ Deployment timeout. Check status:${NC}"
  echo "  aws ecs describe-services --cluster ${CLUSTER_NAME} --services ${SERVICE_NAME} --region ${AWS_REGION}"
  exit 1
fi

# Final status
echo ""
echo -e "${GREEN}=== Deployment Summary ===${NC}"
echo "Environment: ${ENVIRONMENT}"
echo "Image: ${IMAGE_URI}"
echo "Task Definition: ${TASK_DEF_ARN}"
echo ""
echo "View logs:"
echo "  aws logs tail ${LOG_GROUP} --follow --region ${AWS_REGION}"
echo ""
echo "Monitor service:"
echo "  aws ecs describe-services --cluster ${CLUSTER_NAME} --services ${SERVICE_NAME} --region ${AWS_REGION}"
echo ""
echo -e "${GREEN}✓ Done!${NC}"
