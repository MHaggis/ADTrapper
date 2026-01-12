#!/bin/bash

# ADTrapper FRESH Deployment (removes all data)

echo "🧹 ADTrapper FRESH Deployment (WARNING: This will DELETE all data!)"
echo "================================================================="
echo ""

# Check for .env file
if [ ! -f .env ]; then
    echo "⚠️  No .env file found. Creating from env.example..."
    if [ -f env.example ]; then
        cp env.example .env
        echo "📝 Created .env from env.example"
    else
        echo "❌ env.example not found. Please create .env file manually."
        exit 1
    fi
fi

read -p "⚠️  This will DELETE all your sessions and data. Continue? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "❌ Deployment cancelled."
    exit 1
fi

echo "🗑️  Removing existing containers and volumes..."
docker-compose down -v  # -v removes volumes too

echo "🏗️  Building fresh containers..."
docker-compose build --no-cache

echo "▶️  Starting fresh containers..."
docker-compose up -d

echo "⏳ Waiting for services..."
sleep 15

echo "📊 Initializing database schema..."
docker-compose exec -T database psql -U postgres < supabase/migrations/0001_simple_setup.sql

echo "🏥 Health check..."
if curl -s http://localhost:3000/api/sessions > /dev/null; then
    echo "✅ ADTrapper fresh deployment successful!"
    echo ""
    echo "🌐 Access: http://localhost:3000"
    echo "📊 Fresh database - no existing data"
else
    echo "❌ Health check failed"
    docker-compose logs app
fi
