// Configuration for ADTrapper - Supabase without auth
export const config = {
  supabase: {
    url: process.env.NEXT_PUBLIC_SUPABASE_URL || 'http://localhost:3001',
    // No anon key needed for open access
    anonKey: 'not-needed'
  },
  app: {
    name: 'ADTrapper',
    url: process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000',
    version: '1.0.0'
  }
}

// Simple validation
export const validateConfig = () => {
  if (!config.supabase.url) {
    throw new Error('Missing required configuration: NEXT_PUBLIC_SUPABASE_URL')
  }
  return true
}
