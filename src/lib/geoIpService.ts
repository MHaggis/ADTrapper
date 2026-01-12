import { supabase } from './supabase'

export interface GeoIpData {
  ip: string
  country?: string
  region?: string
  city?: string
  isp?: string
  latitude?: number
  longitude?: number
  isTor: boolean
  isVpn: boolean
  isMalicious: boolean
  riskScore: number
  lastUpdated: Date
}

export class GeoIpService {
  private static instance: GeoIpService
  private cache = new Map<string, GeoIpData>()
  private readonly CACHE_DURATION = 24 * 60 * 60 * 1000 // 24 hours

  private constructor() {}

  static getInstance(): GeoIpService {
    if (!GeoIpService.instance) {
      GeoIpService.instance = new GeoIpService()
    }
    return GeoIpService.instance
  }

  /**
   * Get GeoIP data for an IP address, checking cache and database first
   */
  async getGeoIpData(ip: string, sessionId?: string): Promise<GeoIpData | null> {
    // Skip local/private IPs
    if (this.isPrivateIp(ip)) {
      return null
    }

    // Check memory cache first
    const cached = this.cache.get(ip)
    if (cached && this.isCacheValid(cached)) {
      return cached
    }

    // Check database cache
    const dbCached = await this.getFromDatabase(ip, sessionId)
    if (dbCached) {
      this.cache.set(ip, dbCached)
      return dbCached
    }

    // Fetch from external API
    const freshData = await this.fetchFromApi(ip)
    if (freshData) {
      // Store in database and cache
      await this.storeInDatabase(freshData, sessionId)
      this.cache.set(ip, freshData)
      return freshData
    }

    return null
  }

  /**
   * Batch get GeoIP data for multiple IPs
   */
  async getBatchGeoIpData(ips: string[], sessionId?: string): Promise<Map<string, GeoIpData>> {
    const results = new Map<string, GeoIpData>()

    // Filter out private IPs
    const publicIps = ips.filter(ip => !this.isPrivateIp(ip))

    if (publicIps.length === 0) {
      return results
    }

    // Check cache for all IPs
    const uncachedIps: string[] = []
    for (const ip of publicIps) {
      const cached = this.cache.get(ip)
      if (cached && this.isCacheValid(cached)) {
        results.set(ip, cached)
      } else {
        uncachedIps.push(ip)
      }
    }

    if (uncachedIps.length === 0) {
      return results
    }

    // Check database for uncached IPs
    const dbResults = await this.getBatchFromDatabase(uncachedIps, sessionId)
    for (const [ip, data] of Array.from(dbResults)) {
      results.set(ip, data)
      this.cache.set(ip, data)
    }

    // Remove IPs that are already in results from uncached list
    const stillUncachedIps = uncachedIps.filter(ip => !results.has(ip))

    if (stillUncachedIps.length === 0) {
      return results
    }

    // Fetch remaining IPs from API
    for (const ip of stillUncachedIps) {
      const data = await this.fetchFromApi(ip)
      if (data) {
        await this.storeInDatabase(data, sessionId)
        results.set(ip, data)
        this.cache.set(ip, data)
      }
    }

    return results
  }

  /**
   * Check if IP is private/local
   */
  private isPrivateIp(ip: string): boolean {
    // IPv4 private ranges
    const privateRanges = [
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
      /^192\.168\./,
      /^127\./,
      /^169\.254\./, // Link-local
      /^0\./        // Invalid
    ]

    // IPv6 private/link-local addresses
    const ipv6PrivateRanges = [
      /^::1$/,                    // IPv6 loopback
      /^fe80:/,                   // IPv6 link-local
      /^fc00:/,                   // IPv6 unique local
      /^fd00:/,                   // IPv6 unique local
      /^::ffff:10\./,             // IPv4 mapped in IPv6
      /^::ffff:172\.(1[6-9]|2[0-9]|3[0-1])\./,
      /^::ffff:192\.168\./,
      /^::ffff:127\./,
      /^::ffff:169\.254\./
    ]

    // Check if it's IPv4 private
    if (privateRanges.some(range => range.test(ip))) {
      return true
    }

    // Check if it's IPv6 private/link-local
    if (ipv6PrivateRanges.some(range => range.test(ip))) {
      return true
    }

    // Check if it's IPv6 link-local (fe80::/10)
    if (ip.startsWith('fe80:')) {
      return true
    }

    return false
  }

  /**
   * Check if cached data is still valid
   */
  private isCacheValid(data: GeoIpData): boolean {
    return Date.now() - data.lastUpdated.getTime() < this.CACHE_DURATION
  }

  /**
   * Get GeoIP data from database
   */
  private async getFromDatabase(ip: string, sessionId?: string): Promise<GeoIpData | null> {
    try {
      let query = supabase
        .from('ip_enrichment')
        .select('*')
        .eq('ip_address', ip)
        .order('created_at', { ascending: false })
        .limit(1)

      if (sessionId) {
        query = query.eq('session_id', sessionId)
      }

      const { data, error } = await query

      if (error) {
        console.warn('Error fetching GeoIP from database:', error)
        return null
      }

      if (!data || data.length === 0) {
        return null
      }

      const record = data[0]
      return {
        ip: record.ip_address,
        country: record.country,
        region: record.region,
        city: record.city,
        isp: record.isp,
        latitude: record.latitude,
        longitude: record.longitude,
        isTor: record.is_tor || false,
        isVpn: record.is_vpn || false,
        isMalicious: record.is_malicious || false,
        riskScore: record.risk_score || 0,
        lastUpdated: new Date(record.created_at)
      }
    } catch (error) {
      console.warn('Error in getFromDatabase:', error)
      return null
    }
  }

  /**
   * Get batch GeoIP data from database
   */
  private async getBatchFromDatabase(ips: string[], sessionId?: string): Promise<Map<string, GeoIpData>> {
    const results = new Map<string, GeoIpData>()

    try {
      let query = supabase
        .from('ip_enrichment')
        .select('*')
        .in('ip_address', ips)

      if (sessionId) {
        query = query.eq('session_id', sessionId)
      }

      const { data, error } = await query

      if (error) {
        console.warn('Error fetching batch GeoIP from database:', error)
        return results
      }

      if (!data) {
        return results
      }

      // Group by IP and take the most recent record for each
      const latestByIp = new Map<string, any>()
      data.forEach((record: any) => {
        const existing = latestByIp.get(record.ip_address)
        if (!existing || new Date(record.created_at) > new Date(existing.created_at)) {
          latestByIp.set(record.ip_address, record)
        }
      })

      for (const [ip, record] of Array.from(latestByIp)) {
        results.set(ip, {
          ip: record.ip_address,
          country: record.country,
          region: record.region,
          city: record.city,
          isp: record.isp,
          latitude: record.latitude,
          longitude: record.longitude,
          isTor: record.is_tor || false,
          isVpn: record.is_vpn || false,
          isMalicious: record.is_malicious || false,
          riskScore: record.risk_score || 0,
          lastUpdated: new Date(record.created_at)
        })
      }
    } catch (error) {
      console.warn('Error in getBatchFromDatabase:', error)
    }

    return results
  }

  /**
   * Fetch GeoIP data from external API
   */
  private async fetchFromApi(ip: string): Promise<GeoIpData | null> {
    try {
      // Using a free GeoIP API (ip-api.com)
      const response = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,regionName,city,isp,lat,lon,proxy,hosting,mobile,org`)

      if (!response.ok) {
        console.warn(`GeoIP API returned ${response.status} for IP ${ip}`)
        return null
      }

      const data = await response.json()

      if (data.status !== 'success') {
        console.warn(`GeoIP API failed for IP ${ip}: ${data.message || 'Unknown error'}`)
        return null
      }

      // Determine risk factors
      let riskScore = 0
      let isTor = false
      let isVpn = false
      let isMalicious = false

      // Check for TOR exit nodes (simplified check)
      if (data.isp?.toLowerCase().includes('tor') ||
          data.org?.toLowerCase().includes('tor') ||
          data.proxy) {
        isTor = true
        riskScore += 30
      }

      // Check for VPN providers
      const vpnProviders = ['mullvad', 'protonvpn', 'expressvpn', 'nordvpn', 'pia', 'surfshark', 'ipvanish']
      if (data.isp && vpnProviders.some(vpn => data.isp.toLowerCase().includes(vpn))) {
        isVpn = true
        riskScore += 20
      }

      // Check for hosting/datacenter IPs (often used for attacks)
      if (data.hosting) {
        riskScore += 15
      }

      // Check for mobile IPs (less likely to be attack source)
      if (data.mobile) {
        riskScore -= 10
      }

      return {
        ip,
        country: data.country,
        region: data.regionName,
        city: data.city,
        isp: data.isp,
        latitude: data.lat,
        longitude: data.lon,
        isTor,
        isVpn,
        isMalicious, // Would need a threat intelligence feed for this
        riskScore: Math.max(0, Math.min(100, riskScore)),
        lastUpdated: new Date()
      }
    } catch (error) {
      console.warn(`Error fetching GeoIP data for ${ip}:`, error)
      return null
    }
  }

  /**
   * Store GeoIP data in database
   */
  private async storeInDatabase(data: GeoIpData, sessionId?: string): Promise<void> {
    try {
      const record = {
        session_id: sessionId,
        ip_address: data.ip,
        country: data.country,
        region: data.region,
        city: data.city,
        isp: data.isp,
        latitude: data.latitude,
        longitude: data.longitude,
        is_tor: data.isTor,
        is_vpn: data.isVpn,
        is_malicious: data.isMalicious,
        risk_score: data.riskScore
      }

      const { error } = await supabase
        .from('ip_enrichment')
        .upsert(record, {
          onConflict: 'ip_address',
          ignoreDuplicates: false
        })

      if (error) {
        console.warn('Error storing GeoIP data:', error)
      }
    } catch (error) {
      console.warn('Error in storeInDatabase:', error)
    }
  }

  /**
   * Clear cache (useful for testing or memory management)
   */
  clearCache(): void {
    this.cache.clear()
  }

  /**
   * Get cache statistics
   */
  getCacheStats(): { size: number; entries: string[] } {
    return {
      size: this.cache.size,
      entries: Array.from(this.cache.keys())
    }
  }
}

// Export singleton instance
export const geoIpService = GeoIpService.getInstance()
