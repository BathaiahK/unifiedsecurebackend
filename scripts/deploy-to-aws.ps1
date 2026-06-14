#################################################################################
# AWS Deployment Script for Unified Secure Platform Backend (PowerShell)
#
# Usage: .\scripts\deploy-to-aws.ps1 -Environment [prod|stg|qat] -ImageTag [tag]
#
# Examples:
#   .\scripts\deploy-to-aws.ps1 -Environment prod -ImageTag v1.2.3
#   .\scripts\deploy-to-aws.ps1 -Environment stg -ImageTag latest
#
#################################################################################

param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('prod', 'stg', 'qat')]
  [string]$Environment,

  [Parameter(Mandatory = $true)]
  [string]$ImageTag = 'latest'
)

$ErrorActionPreference = 'Stop'

# Color output
$Green = @{ ForegroundColor = 'Green' }
$Yellow = @{ ForegroundColor = 'Yellow' }
$Red = @{ ForegroundColor = 'Red' }

# Configuration based on environment
$config = @{
  'prod' = @{
    AWSRegion     = 'us-east-1'
    ClusterName   = 'uspservice-prod'
    ServiceName   = 'uspservice-api-service'
    TaskFamily    = 'uspservice-api-prod'
    LogGroup      = '/ecs/uspservice-api-prod'
  }
  'stg'  = @{
    AWSRegion     = 'us-east-1'
    ClusterName   = 'uspservice-stg'
    ServiceName   = 'uspservice-api-service-stg'
    TaskFamily    = 'uspservice-api-stg'
    LogGroup      = '/ecs/uspservice-api-stg'
  }
  'qat'  = @{
    AWSRegion     = 'us-east-1'
    ClusterName   = 'uspservice-qat'
    ServiceName   = 'uspservice-api-service-qat'
    TaskFamily    = 'uspservice-api-qat'
    LogGroup      = '/ecs/uspservice-api-qat'
  }
}

$cfg = $config[$Environment]
$AWCRegion = $cfg.AWSRegion
$ClusterName = $cfg.ClusterName
$ServiceName = $cfg.ServiceName
$TaskFamily = $cfg.TaskFamily
$LogGroup = $cfg.LogGroup

# Get AWS Account ID
try {
  $AWSAccountID = aws sts get-caller-identity --query Account --output text
} catch {
  Write-Host @Red "Error: AWS credentials not configured"
  Write-Host "Run: aws configure"
  exit 1
}

$ECRRegistry = "$AWSAccountID.dkr.ecr.$AWCRegion.amazonaws.com"
$ECRRepository = 'uspservice-api'
$ImageURI = "$ECRRegistry/$ECRRepository`:$ImageTag"

Write-Host @Yellow "=== AWS Deployment for USP Backend ==="
Write-Host "Environment: $(Write-Host @Green $Environment -NoNewline; Write-Host '')"
Write-Host "Region: $(Write-Host @Green $AWCRegion -NoNewline; Write-Host '')"
Write-Host "Image Tag: $(Write-Host @Green $ImageTag -NoNewline; Write-Host '')"
Write-Host "Image URI: $(Write-Host @Green $ImageURI -NoNewline; Write-Host '')"
Write-Host ""

# Step 1: Verify AWS credentials
Write-Host @Yellow "[1/6] Verifying AWS credentials..."
try {
  aws sts get-caller-identity --region $AWCRegion | Out-Null
  Write-Host @Green "✓ AWS credentials verified"
} catch {
  Write-Host @Red "Error: AWS credentials not configured or invalid"
  exit 1
}

# Step 2: Verify ECR repository exists
Write-Host @Yellow "[2/6] Verifying ECR repository..."
try {
  aws ecr describe-repositories `
    --repository-names $ECRRepository `
    --region $AWCRegion | Out-Null
  Write-Host @Green "✓ ECR repository verified"
} catch {
  Write-Host @Red "Error: ECR repository not found: $ECRRepository"
  Write-Host "Create it with:"
  Write-Host "  aws ecr create-repository --repository-name $ECRRepository --region $AWCRegion"
  exit 1
}

# Step 3: Check if image exists in ECR
Write-Host @Yellow "[3/6] Checking if image exists in ECR..."
try {
  aws ecr describe-images `
    --repository-name $ECRRepository `
    --image-ids "imageTag=$ImageTag" `
    --region $AWCRegion | Out-Null
  Write-Host @Green "✓ Image verified in ECR"
} catch {
  Write-Host @Yellow "⚠ Image not found in ECR. Did you build and push it?"
  Write-Host ""
  Write-Host "Build and push locally:"
  Write-Host "  docker build -f apps/api/Dockerfile -t uspservice-api:$ImageTag ."
  Write-Host "  aws ecr get-login-password --region $AWCRegion | docker login --username AWS --password-stdin $ECRRegistry"
  Write-Host "  docker tag uspservice-api:$ImageTag $ImageURI"
  Write-Host "  docker push $ImageURI"
  exit 1
}

# Step 4: Register task definition
Write-Host @Yellow "[4/6] Registering new task definition..."
$taskDefJson = @"
{
  "family": "$TaskFamily",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "256",
  "memory": "512",
  "containerDefinitions": [
    {
      "name": "api",
      "image": "$ImageURI",
      "portMappings": [
        {
          "containerPort": 4000,
          "protocol": "tcp"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "$LogGroup",
          "awslogs-region": "$AWCRegion",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "secrets": [
        {
          "name": "DATABASE_URL",
          "valueFrom": "arn:aws:secretsmanager:$AWCRegion`:$AWSAccountID`:secret:uspservice/$Environment/db-url"
        },
        {
          "name": "CORS_ORIGIN",
          "valueFrom": "arn:aws:secretsmanager:$AWCRegion`:$AWSAccountID`:secret:uspservice/$Environment/cors-origin"
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
  "executionRoleArn": "arn:aws:iam::$AWSAccountID`:role/uspservice-ecs-task-execution-role",
  "taskRoleArn": "arn:aws:iam::$AWSAccountID`:role/uspservice-ecs-task-role"
}
"@

$taskDefTempFile = New-TemporaryFile
Set-Content -Path $taskDefTempFile -Value $taskDefJson

try {
  $taskDefARN = aws ecs register-task-definition `
    --cli-input-json "file://$($taskDefTempFile.FullName)" `
    --region $AWCRegion `
    --query 'taskDefinition.taskDefinitionArn' `
    --output text

  Write-Host @Green "✓ Task definition registered: $taskDefARN"
} finally {
  Remove-Item $taskDefTempFile -Force
}

# Step 5: Update ECS service
Write-Host @Yellow "[5/6] Updating ECS service..."
aws ecs update-service `
  --cluster $ClusterName `
  --service $ServiceName `
  --task-definition $taskDefARN `
  --force-new-deployment `
  --region $AWCRegion | Out-Null

Write-Host @Green "✓ ECS service updated"

# Step 6: Wait for deployment to stabilize
Write-Host @Yellow "[6/6] Waiting for deployment to stabilize (max 5 minutes)..."
try {
  aws ecs wait services-stable `
    --cluster $ClusterName `
    --services $ServiceName `
    --region $AWCRegion
  Write-Host @Green "✓ Deployment successful!"
} catch {
  Write-Host @Yellow "⚠ Deployment timeout. Check status with:"
  Write-Host "  aws ecs describe-services --cluster $ClusterName --services $ServiceName --region $AWCRegion"
  exit 1
}

# Final status
Write-Host ""
Write-Host @Green "=== Deployment Summary ==="
Write-Host "Environment: $Environment"
Write-Host "Image: $ImageURI"
Write-Host "Task Definition: $taskDefARN"
Write-Host ""
Write-Host "View logs:"
Write-Host "  aws logs tail $LogGroup --follow --region $AWCRegion"
Write-Host ""
Write-Host "Monitor service:"
Write-Host "  aws ecs describe-services --cluster $ClusterName --services $ServiceName --region $AWCRegion"
Write-Host ""
Write-Host @Green "✓ Done!"
