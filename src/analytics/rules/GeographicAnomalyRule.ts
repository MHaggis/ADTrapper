import { BaseRule } from '../BaseRule'
import { AuthEvent, Anomaly, AnalyticsContext } from '../types'
import { geoIpService } from '../../lib/geoIpService'

export class GeographicAnomalyRule extends BaseRule {
  constructor() {
    super({
      id: 'geographic_anomaly_detection',
      name: 'Geographic Anomaly Detection',
      description: 'Detects suspicious login patterns based on geographic locations',
      category: 'behavior',
      severity: 'medium',
      timeWindow: 120, // 2 hours
      thresholds: {
        maxCountries: 2,
        maxCitiesPerCountry: 3,
        impossibleTravelTimeHours: 1, // Flag if travel between locations would take less than 1 hour
        suspiciousCountries: 0 // Any login from predefined suspicious countries
      },
      version: '1.1.0',
      author: 'ADTrapper Security Team',
      detailedDescription: {
        overview: 'Detects suspicious login patterns based on geographic locations and impossible travel scenarios. Analyzes authentication events to identify users logging in from multiple countries, suspicious geographic locations, and physically impossible travel between login locations.',
        detectionLogic: 'Correlates authentication events with GeoIP data to analyze geographic patterns. Detects multiple country access within time windows, logins from high-risk countries or Tor/VPN exit nodes, and calculates travel feasibility between consecutive login locations. Uses statistical analysis to identify anomalous geographic behavior.',
        falsePositives: 'Legitimate business travel, VPN usage, shared workstations, remote work scenarios, system administration from multiple locations, or users with valid international access patterns. May also trigger during legitimate conference attendance or temporary international assignments.',
        mitigation: [
          'Implement location-based authentication policies',
          'Require additional verification for new geographic locations',
          'Monitor VPN and remote access usage patterns',
          'Set up geographic restrictions for high-risk accounts',
          'Implement risk-based authentication scoring',
          'Regular review of user access location patterns',
          'Configure alerts for access from suspicious countries',
          'Use conditional access policies based on location',
          'Implement session monitoring for geographic anomalies',
          'Regular audit of geographic access patterns for compliance'
        ],
        windowsEvents: ['4624 (Successful Logon)', '4625 (Failed Logon)', '4648 (Explicit Credential Logon)', '4778 (Session Reconnect)', '4779 (Session Disconnect)'],
        exampleQuery: `index=windows EventCode=4624 | iplocation IpAddress | stats values(Country) as countries by TargetUserName | where mvcount(countries) > 2`,
        recommendedThresholds: {
          maxCountries: 2,
          maxCitiesPerCountry: 3,
          impossibleTravelTimeHours: 1,
          suspiciousCountries: 0
        }
      }
    })
  }

  // List of countries that might be considered higher risk (configurable)
  private readonly suspiciousCountries = new Set([
    'TOR', // Tor exit nodes
    'CN',  // China
    'RU',  // Russia
    'KP',  // North Korea
    'IR',  // Iran
    'SY',  // Syria
  ])

  // Rough distance calculation for impossible travel detection
  private calculateDistance(coord1: [number, number], coord2: [number, number]): number {
    const [lat1, lon1] = coord1
    const [lat2, lon2] = coord2
    
    const R = 6371 // Earth's radius in kilometers
    const dLat = this.toRadians(lat2 - lat1)
    const dLon = this.toRadians(lon2 - lon1)
    
    const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
              Math.cos(this.toRadians(lat1)) * Math.cos(this.toRadians(lat2)) *
              Math.sin(dLon / 2) * Math.sin(dLon / 2)
    
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a))
    return R * c
  }

  private toRadians(degrees: number): number {
    return degrees * (Math.PI / 180)
  }

  async analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = []
    const recentEvents = this.filterByTimeWindow(events)
    const successfulLogins = recentEvents.filter(event => event.status === 'Success')

    // Group by user
    const loginsByUser = this.groupBy(successfulLogins, event =>
      `${event.userName}@${event.domainName || 'unknown'}`
    )

    // Get unique IPs from all events for batch GeoIP lookup
    const uniqueIps = new Set<string>()
    successfulLogins.forEach(event => {
      if (event.sourceIp) uniqueIps.add(event.sourceIp)
    })

    // Batch fetch GeoIP data for all IPs
    const geoIpData = await geoIpService.getBatchGeoIpData(Array.from(uniqueIps), context.sessionId)

    Object.entries(loginsByUser).forEach(([userKey, userLogins]) => {
      const userName = userLogins[0].userName
      if (!userName) return

      // Get IP intelligence for user's logins
      const loginsWithGeo = userLogins
        .map(login => {
          // Try context first, then GeoIP service
          let ipInfo = context.ipIntelligence?.find(ip => ip.ip === login.sourceIp)

          // If no context data, use GeoIP service data
          if (!ipInfo && login.sourceIp) {
            const serviceData = geoIpData.get(login.sourceIp)
            if (serviceData) {
              ipInfo = {
                ip: serviceData.ip,
                country: serviceData.country,
                region: serviceData.region,
                city: serviceData.city,
                latitude: serviceData.latitude,
                longitude: serviceData.longitude,
                isp: serviceData.isp,
                isVpn: serviceData.isVpn,
                isTor: serviceData.isTor,
                isMalicious: serviceData.isMalicious,
                riskScore: serviceData.riskScore
              }
            }
          }

          return { login, ipInfo }
        })
        .filter(item => item.ipInfo && item.ipInfo.country)

      if (loginsWithGeo.length < 2) return // Need at least 2 logins to detect anomalies

      // 1. Multiple Countries Anomaly
      const countries = new Set(loginsWithGeo.map(item => item.ipInfo!.country))
      if (countries.size > this.thresholds.maxCountries) {
        let confidence = 60 + (countries.size - this.thresholds.maxCountries) * 15

        const anomaly = this.createAnomaly(
          'Multi-Country Login Activity',
          `User ${userName} logged in from ${countries.size} different countries: ${Array.from(countries).join(', ')}`,
          {
            userName,
            domain: userLogins[0].domainName,
            countries: Array.from(countries),
            countryCount: countries.size,
            logins: loginsWithGeo.map(item => ({
              timestamp: item.login.timestamp,
              country: item.ipInfo!.country,
              city: item.ipInfo!.city,
              ip: item.login.sourceIp,
              computer: item.login.computerName
            })),
            timeSpanHours: (Math.max(...userLogins.map(l => l.timestamp instanceof Date
                             ? l.timestamp.getTime()
                             : new Date(l.timestamp).getTime())) -
                           Math.min(...userLogins.map(l => l.timestamp instanceof Date
                             ? l.timestamp.getTime()
                             : new Date(l.timestamp).getTime()))) / (1000 * 60 * 60)
          },
          confidence
        )

        anomalies.push(anomaly)
      }

      // 2. Suspicious Country Access
      const suspiciousLogins = loginsWithGeo.filter(item => 
        this.suspiciousCountries.has(item.ipInfo!.country!) ||
        item.ipInfo!.isTor ||
        item.ipInfo!.isVpn ||
        item.ipInfo!.isMalicious
      )

      if (suspiciousLogins.length > 0) {
        let confidence = 70
        if (suspiciousLogins.some(item => item.ipInfo!.isTor)) confidence += 20
        if (suspiciousLogins.some(item => item.ipInfo!.isMalicious)) confidence += 25

        const suspiciousCountriesFound = new Set(
          suspiciousLogins.map(item => item.ipInfo!.country).filter(Boolean)
        )

        const anomaly = this.createAnomaly(
          'Suspicious Geographic Access',
          `User ${userName} accessed from suspicious locations: ${Array.from(suspiciousCountriesFound).join(', ')}`,
          {
            userName,
            domain: userLogins[0].domainName,
            suspiciousCountries: Array.from(suspiciousCountriesFound),
            torAccess: suspiciousLogins.some(item => item.ipInfo!.isTor),
            vpnAccess: suspiciousLogins.some(item => item.ipInfo!.isVpn),
            maliciousIps: suspiciousLogins.some(item => item.ipInfo!.isMalicious),
            suspiciousLogins: suspiciousLogins.map(item => ({
              timestamp: item.login.timestamp,
              country: item.ipInfo!.country,
              city: item.ipInfo!.city,
              ip: item.login.sourceIp,
              isTor: item.ipInfo!.isTor,
              isVpn: item.ipInfo!.isVpn,
              isMalicious: item.ipInfo!.isMalicious,
              riskScore: item.ipInfo!.riskScore
            }))
          },
          confidence
        )

        anomalies.push(anomaly)
      }

      // 3. Impossible Travel Detection
      const sortedLogins = loginsWithGeo
        .filter(item => item.ipInfo!.latitude && item.ipInfo!.longitude)
        .sort((a, b) => a.login.timestamp.getTime() - b.login.timestamp.getTime())

      for (let i = 1; i < sortedLogins.length; i++) {
        const prev = sortedLogins[i - 1]
        const curr = sortedLogins[i]

        if (prev.ipInfo!.country === curr.ipInfo!.country) continue // Same country, skip

        const distance = this.calculateDistance(
          [prev.ipInfo!.latitude!, prev.ipInfo!.longitude!],
          [curr.ipInfo!.latitude!, curr.ipInfo!.longitude!]
        )

        const timeDiffHours = (curr.login.timestamp.getTime() - prev.login.timestamp.getTime()) / (1000 * 60 * 60)
        const maxPossibleSpeed = distance / timeDiffHours // km/h

        // Commercial aircraft average speed is about 900 km/h
        // Flag if travel would require speeds > 1200 km/h (impossible for commercial travel)
        if (maxPossibleSpeed > 1200) {
          const confidence = Math.min(95, 60 + Math.min(35, (maxPossibleSpeed - 1200) / 100))

          const anomaly = this.createAnomaly(
            'Impossible Travel Detected',
            `User ${userName} appeared to travel ${Math.round(distance)} km in ${Math.round(timeDiffHours * 10) / 10} hours (${Math.round(maxPossibleSpeed)} km/h required)`,
            {
              userName,
              domain: userLogins[0].domainName,
              distance: Math.round(distance),
              timeDiffHours: Math.round(timeDiffHours * 10) / 10,
              requiredSpeed: Math.round(maxPossibleSpeed),
              location1: {
                timestamp: prev.login.timestamp,
                country: prev.ipInfo!.country,
                city: prev.ipInfo!.city,
                ip: prev.login.sourceIp,
                coordinates: [prev.ipInfo!.latitude, prev.ipInfo!.longitude]
              },
              location2: {
                timestamp: curr.login.timestamp,
                country: curr.ipInfo!.country,
                city: curr.ipInfo!.city,
                ip: curr.login.sourceIp,
                coordinates: [curr.ipInfo!.latitude, curr.ipInfo!.longitude]
              }
            },
            confidence
          )

          anomalies.push(anomaly)
        }
      }
    })

    return anomalies
  }
}
