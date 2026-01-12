import { supabase } from './supabase'
import crypto from 'crypto'

export interface ApiKey {
  id: string
  user_id: string
  name: string
  description?: string
  expires_at?: string
  last_used_at?: string
  usage_count: number
  is_active: boolean
  created_at: string
}

export interface CreateApiKeyRequest {
  name: string
  description?: string
  expirationType: 'never' | '1time' | '30days' | '60days' | '90days'
}

export interface ApiKeyWithSecret extends ApiKey {
  secret: string
}

export class ApiKeyService {

  /**
   * Generate a secure API key
   */
  private static generateApiKey(): string {
    // Generate a cryptographically secure random string
    const randomBytes = new Uint8Array(32)
    crypto.getRandomValues(randomBytes)

    // Convert to base64url format (safe for URLs and filenames)
    const base64 = btoa(String.fromCharCode(...Array.from(randomBytes)))
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
  }

  /**
   * Hash an API key for storage
   */
  private static hashApiKey(apiKey: string): string {
    return crypto.createHash('sha256').update(apiKey).digest('hex')
  }

  /**
   * Calculate expiration date based on type
   */
  private static calculateExpiration(expirationType: string): string | null {
    const now = new Date()

    switch (expirationType) {
      case '1time':
        // Expire in 24 hours
        now.setHours(now.getHours() + 24)
        return now.toISOString()
      case '30days':
        now.setDate(now.getDate() + 30)
        return now.toISOString()
      case '60days':
        now.setDate(now.getDate() + 60)
        return now.toISOString()
      case '90days':
        now.setDate(now.getDate() + 90)
        return now.toISOString()
      case 'never':
      default:
        return null
    }
  }

  /**
   * Create a new API key (localStorage-based for anonymous mode)
   */
  static async createApiKey(request: CreateApiKeyRequest): Promise<ApiKeyWithSecret> {
    const secret = this.generateApiKey()
    const hashedKey = this.hashApiKey(secret)
    const expiresAt = this.calculateExpiration(request.expirationType)

    // In anonymous mode, store API keys in localStorage
    const apiKey: ApiKeyWithSecret = {
      id: crypto.randomUUID(),
      user_id: 'anonymous',
      name: request.name,
      description: request.description,
      expires_at: expiresAt || undefined,
      last_used_at: undefined,
      usage_count: 0,
      is_active: true,
      created_at: new Date().toISOString(),
      secret
    }

    // Store in localStorage
    const existingKeys = this.getStoredApiKeys()
    existingKeys.push(apiKey)
    localStorage.setItem('adt_api_keys', JSON.stringify(existingKeys))

    return apiKey
  }

  /**
   * Get stored API keys from localStorage
   */
  private static getStoredApiKeys(): ApiKeyWithSecret[] {
    try {
      const stored = localStorage.getItem('adt_api_keys')
      return stored ? JSON.parse(stored) : []
    } catch (error) {
      console.error('Failed to read API keys from localStorage:', error)
      return []
    }
  }

  /**
   * Get all user's API keys (without secrets)
   */
  static async getUserApiKeys(): Promise<ApiKey[]> {
    const storedKeys = this.getStoredApiKeys()

    // Return API keys without the secret field
    return storedKeys.map(({ secret, ...key }) => key)
  }

  /**
   * Validate an API key and get user info (localStorage-based)
   */
  static async validateApiKey(apiKey: string): Promise<{ userId: string; keyId: string } | null> {
    const hashedKey = this.hashApiKey(apiKey)
    const storedKeys = this.getStoredApiKeys()

    const key = storedKeys.find(k => {
      const keyHash = this.hashApiKey(k.secret)
      return keyHash === hashedKey && k.is_active
    })

    if (!key) {
      return null
    }

    // Check if key is expired
    if (key.expires_at) {
      const expiresAt = new Date(key.expires_at)
      if (expiresAt < new Date()) {
        return null
      }
    }

    // Update usage count and last used time
    key.last_used_at = new Date().toISOString()
    key.usage_count = (key.usage_count || 0) + 1

    // Save updated keys back to localStorage
    localStorage.setItem('adt_api_keys', JSON.stringify(storedKeys))

    return {
      userId: key.user_id,
      keyId: key.id
    }
  }

  /**
   * Deactivate an API key
   */
  static async deactivateApiKey(keyId: string): Promise<void> {
    const storedKeys = this.getStoredApiKeys()
    const keyIndex = storedKeys.findIndex(k => k.id === keyId)

    if (keyIndex === -1) {
      throw new Error('API key not found')
    }

    storedKeys[keyIndex].is_active = false
    localStorage.setItem('adt_api_keys', JSON.stringify(storedKeys))
  }

  /**
   * Delete an API key
   */
  static async deleteApiKey(keyId: string): Promise<void> {
    const storedKeys = this.getStoredApiKeys()
    const filteredKeys = storedKeys.filter(k => k.id !== keyId)

    if (filteredKeys.length === storedKeys.length) {
      throw new Error('API key not found')
    }

    localStorage.setItem('adt_api_keys', JSON.stringify(filteredKeys))
  }

  /**
   * Get API key statistics for user
   */
  static async getApiKeyStats(): Promise<{
    totalKeys: number
    activeKeys: number
    expiredKeys: number
    totalUsage: number
  }> {
    const storedKeys = this.getStoredApiKeys()

    const now = new Date()
    let activeKeys = 0
    let expiredKeys = 0
    let totalUsage = 0

    storedKeys.forEach(key => {
      totalUsage += key.usage_count || 0

      if (key.is_active) {
        if (key.expires_at) {
          const expiresAt = new Date(key.expires_at)
          if (expiresAt > now) {
            activeKeys++
          } else {
            expiredKeys++
          }
        } else {
          activeKeys++
        }
      }
    })

    return {
      totalKeys: storedKeys.length,
      activeKeys,
      expiredKeys,
      totalUsage
    }
  }
}
