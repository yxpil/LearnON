# LearnON Cloud Deployment Guide

This guide covers deploying LearnON Gateway to various cloud platforms.

## Table of Contents
- [Docker](#docker)
- [Docker Compose](#docker-compose)
- [Kubernetes](#kubernetes)
- [AWS](#aws)
- [Azure](#azure)
- [Google Cloud](#google-cloud)

## Docker

### Build Image
```bash
docker build -t yxpil/learnon:latest .
```

### Run Container
```bash
docker run -d \
  --name learnon-gateway \
  -p 80:80 \
  -p 443:443 \
  -v $(pwd)/conf:/app/conf:ro \
  -v $(pwd)/certs:/app/certs:ro \
  yxpil/learnon:latest
```

## Docker Compose

### Quick Start
```bash
# Deploy
./deploy.sh deploy

# Or manually
docker-compose up -d

# View logs
docker-compose logs -f learnon

# Stop
docker-compose down
```

### Configuration
Edit `conf/learnon.conf` before deployment. See `conf/learnon.conf.example` for reference.

## Kubernetes

### Deploy
```bash
# Apply configuration
kubectl apply -f kubernetes/deployment.yaml

# Check status
kubectl get pods -l app=learnon
kubectl get svc learnon-gateway

# View logs
kubectl logs -f deployment/learnon-gateway
```

### Scale
```bash
kubectl scale deployment learnon-gateway --replicas=5
```

### Update
```bash
kubectl set image deployment/learnon-gateway learnon=yxpil/learnon:latest
kubectl rollout status deployment/learnon-gateway
```

### Rollback
```bash
kubectl rollout undo deployment/learnon-gateway
```

## AWS

### ECS (Elastic Container Service)

1. Push image to ECR:
```bash
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <account>.dkr.ecr.us-east-1.amazonaws.com
docker tag yxpil/learnon:latest <account>.dkr.ecr.us-east-1.amazonaws.com/learnon:latest
docker push <account>.dkr.ecr.us-east-1.amazonaws.com/learnon:latest
```

2. Create task definition and service using AWS Console or CLI

### EKS (Elastic Kubernetes Service)
Use the Kubernetes deployment files above with your EKS cluster.

## Azure

### AKS (Azure Kubernetes Service)

1. Login to Azure:
```bash
az login
az aks get-credentials --resource-group myResourceGroup --name myAKSCluster
```

2. Deploy:
```bash
kubectl apply -f kubernetes/deployment.yaml
```

### Azure Container Instances
```bash
az container create \
  --resource-group myResourceGroup \
  --name learnon-gateway \
  --image yxpil/learnon:latest \
  --dns-name-label learnon-gateway \
  --ports 80 443
```

## Google Cloud

### GKE (Google Kubernetes Engine)

1. Connect to cluster:
```bash
gcloud container clusters get-credentials learnon-cluster --zone us-central1-a
```

2. Deploy:
```bash
kubectl apply -f kubernetes/deployment.yaml
```

### Cloud Run
```bash
gcloud run deploy learnon-gateway \
  --image yxpil/learnon:latest \
  --platform managed \
  --port 80 \
  --allow-unauthenticated
```

## Monitoring

### Prometheus Metrics
LearnON exposes metrics at `/metrics` endpoint. Configure your monitoring solution to scrape this endpoint.

### Health Checks
- HTTP health check: `GET /health`
- Returns: `200 OK` when gateway is running

### Logging
All logs are written to `/app/logs/`:
- `access.log` - Request logs
- `error.log` - Error and warning logs

Configure log rotation in production environments.

## Security Best Practices

1. **TLS Certificates**: Mount certificates securely
   ```bash
   kubectl create secret tls learnon-certs --cert=cert.pem --key=key.pem
   ```

2. **Non-root User**: The container runs as non-root user by default

3. **Network Policies**: Restrict ingress/egress traffic in Kubernetes

4. **Secrets Management**: Use Kubernetes Secrets or cloud-specific secret managers for sensitive data

5. **Resource Limits**: Always set CPU and memory limits to prevent resource exhaustion

## Troubleshooting

### Container won't start
```bash
docker logs learnon-gateway
```

### Check configuration syntax
```bash
docker run --rm -v $(pwd)/conf:/app/conf:ro yxpil/learnon:latest -t
```

### Kubernetes pod issues
```bash
kubectl describe pod <pod-name>
kubectl logs <pod-name>
```

## Support

For issues and feature requests, please visit:
https://github.com/yxpil/LearnON/issues
