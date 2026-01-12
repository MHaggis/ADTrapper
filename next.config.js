/** @type {import('next').NextConfig} */
const nextConfig = {
  experimental: {
    serverComponentsExternalPackages: ['@supabase/supabase-js']
  },
  images: {
    domains: ['avatars.githubusercontent.com', 'lh3.googleusercontent.com']
  },
  // Enable standalone output for Docker
  output: 'standalone',
  // Disable SWC minification to avoid potential issues in Docker
  swcMinify: true,
  // Optimize for production
  poweredByHeader: false,
  generateEtags: false
}

module.exports = nextConfig
