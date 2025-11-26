#!/bin/bash
echo "Starting Database Security Scanner..."
docker-compose up -d
sleep 10
python src/security_scanner.py
