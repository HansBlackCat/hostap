#!/bin/bash
set -e

echo "Stopping all containers..."
docker-compose down -v

echo "Cleaning up Docker networks..."
docker network prune -f

echo "Removing any conflicting networks..."
docker network ls --format "{{.Name}}" | grep -E "wireless|external_net|isolated_net" | xargs -r docker network rm || true

echo "Cleaning system..."
docker system prune -f

echo "Checking for port/IP conflicts..."
ss -tulpn | grep -E "172\.(20|21|28|29)" || echo "No conflicts found"

echo "Starting fresh..."
docker-compose up -d

echo "Waiting for containers to start..."
sleep 5

echo "Container status:"
docker-compose ps

echo "Network status:"
docker network ls