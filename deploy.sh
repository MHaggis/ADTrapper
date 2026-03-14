#!/bin/bash

# ADTrapper Production Deployment Script

echo "🚀 ADTrapper Production Deployment"
echo "=================================="

# Check for .env file
if [ ! -f .env ]; then
    echo "⚠️  No .env file found. Creating from env.example..."
    if [ -f env.example ]; then
        cp env.example .env
        echo "📝 Created .env from env.example"
        echo "   Please edit .env to set a secure POSTGRES_PASSWORD for production!"
    else
        echo "❌ env.example not found. Please create .env file manually."
        exit 1
    fi
fi

# Stop any existing containers
echo "📦 Stopping existing containers..."
docker compose down

# Build production containers
echo "🏗️  Building production containers..."
docker compose build --no-cache

# Start containers
echo "▶️  Starting production containers..."
docker compose up -d

# Wait for containers to be healthy
echo "⏳ Waiting for services to be ready..."
sleep 10

# Initialize database schema
echo "📊 Initializing database schema..."
docker compose exec -T database psql -U postgres < supabase/migrations/0001_simple_setup.sql

# Health check
echo "🏥 Health check..."
if curl -s http://localhost:3000/api/sessions > /dev/null; then
    echo "✅ ADTrapper is running successfully!"
    echo ""
    echo "🌐 Access your application at: http://localhost:3000"
    echo "📊 API endpoints available at: http://localhost:3000/api/*"
    echo ""
    echo "📋 Container Status:"
    docker compose ps
else
    echo "❌ Health check failed. Check logs:"
    docker compose logs app
fi
