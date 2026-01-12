import { useState, useMemo } from 'react'

export interface Anomaly {
  id: string
  type: 'brute_force' | 'geographical' | 'privilege_escalation' | 'temporal' | 'anonymization'
  severity: 'low' | 'medium' | 'high' | 'critical'
  title: string
  description: string
  source?: string
  target?: string
  count?: number
  timestamp: Date
  confidence?: number
  countries?: string[]
  loginCount?: number
}

export interface LogData {
  nodes: any[]
  edges: any[]
}

export const useAnomalyDetection = () => {
  const [anomalies, setAnomalies] = useState<Anomaly[]>([])

  const detectAnomalies = (logData: LogData) => {
    const detectedAnomalies: Anomaly[] = []
    
    // 1. Brute Force Detection
    const bruteForceAnomalies = detectBruteForce(logData)
    detectedAnomalies.push(...bruteForceAnomalies)

    // 2. Geographical Anomaly Detection
    const geoAnomalies = detectGeographicalAnomalies(logData)
    detectedAnomalies.push(...geoAnomalies)

    // 3. Privilege Escalation Detection
    const privAnomalies = detectPrivilegeEscalation(logData)
    detectedAnomalies.push(...privAnomalies)

    // 4. Time-based Anomalies
    const timeAnomalies = detectTemporalAnomalies(logData)
    detectedAnomalies.push(...timeAnomalies)

    // 5. Tor/VPN Detection
    const torAnomalies = detectTorConnections(logData)
    detectedAnomalies.push(...torAnomalies)

    setAnomalies(detectedAnomalies)
    return detectedAnomalies
  }

  const detectBruteForce = (logData: LogData): Anomaly[] => {
    const anomalies: Anomaly[] = []
    const loginAttempts: any = {}
    
    logData.edges.forEach((edge: any) => {
      if (edge.type === 'login') {
        const key = `${edge.source}_${edge.target}`
        if (!loginAttempts[key]) loginAttempts[key] = { success: 0, failed: 0 }
        edge.status === 'Success' ? loginAttempts[key].success++ : loginAttempts[key].failed++
      }
    })

    Object.entries(loginAttempts).forEach(([key, attempts]: [string, any]) => {
      if (attempts.failed > 5 && attempts.success === 0) {
        anomalies.push({
          id: `brute_${Date.now()}_${Math.random()}`,
          type: 'brute_force',
          severity: 'high',
          title: 'Potential Brute Force Attack',
          description: `Multiple failed login attempts detected for ${key.split('_')[1]}`,
          source: key.split('_')[0],
          target: key.split('_')[1],
          count: attempts.failed,
          timestamp: new Date()
        })
      }
    })

    return anomalies
  }

  const detectGeographicalAnomalies = (logData: LogData): Anomaly[] => {
    const anomalies: Anomaly[] = []
    const userLocations: any = {}
    
    logData.edges.forEach((edge: any) => {
      if (edge.type === 'connection') {
        const ipNode = logData.nodes.find((n: any) => n.id === edge.source && n.type === 'ip')
        if (ipNode && ipNode.country) {
          if (!userLocations[edge.target]) userLocations[edge.target] = new Set()
          userLocations[edge.target].add(ipNode.country)
        }
      }
    })

    Object.entries(userLocations).forEach(([user, countries]: [string, any]) => {
      if (countries.size > 2) {
        anomalies.push({
          id: `geo_${Date.now()}_${Math.random()}`,
          type: 'geographical',
          severity: 'medium',
          title: 'Suspicious Geographic Activity',
          description: `User accessing from ${countries.size} different countries`,
          target: user,
          countries: Array.from(countries),
          timestamp: new Date()
        })
      }
    })

    return anomalies
  }

  const detectPrivilegeEscalation = (logData: LogData): Anomaly[] => {
    const anomalies: Anomaly[] = []
    const privilegedUsers = logData.nodes.filter((n: any) => n.type === 'user' && n.privileged)
    
    privilegedUsers.forEach((user: any) => {
      const recentLogins = logData.edges.filter((e: any) => 
        e.source === user.id && e.type === 'login' && e.status === 'Success'
      )
      
      if (recentLogins.length > 0) {
        anomalies.push({
          id: `priv_${Date.now()}_${Math.random()}`,
          type: 'privilege_escalation',
          severity: 'high',
          title: 'Privileged Account Activity',
          description: `High-privilege user ${user.label} active on multiple systems`,
          source: user.id,
          loginCount: recentLogins.length,
          timestamp: new Date()
        })
      }
    })

    return anomalies
  }

  const detectTemporalAnomalies = (logData: LogData): Anomaly[] => {
    const anomalies: Anomaly[] = []
    const suspiciousTimeLogins = logData.edges.filter((edge: any) => {
      const hour = new Date(edge.timestamp).getHours()
      return (hour < 6 || hour > 22) && edge.type === 'login' && edge.status === 'Success'
    })

    if (suspiciousTimeLogins.length > 0) {
      anomalies.push({
        id: `time_${Date.now()}_${Math.random()}`,
        type: 'temporal',
        severity: 'medium',
        title: 'Off-Hours Login Activity',
        description: `${suspiciousTimeLogins.length} logins detected outside business hours`,
        count: suspiciousTimeLogins.length,
        timestamp: new Date()
      })
    }

    return anomalies
  }

  const detectTorConnections = (logData: LogData): Anomaly[] => {
    const anomalies: Anomaly[] = []
    const torConnections = logData.nodes.filter((n: any) => n.type === 'ip' && n.tor)
    
    if (torConnections.length > 0) {
      anomalies.push({
        id: `tor_${Date.now()}_${Math.random()}`,
        type: 'anonymization',
        severity: 'critical',
        title: 'Tor Network Access Detected',
        description: `Connection from known Tor exit node: ${torConnections[0].label}`,
        source: torConnections[0].id,
        timestamp: new Date()
      })
    }

    return anomalies
  }

  const riskLevel = useMemo(() => {
    const level = anomalies.reduce((sum, anomaly) => {
      const multiplier = anomaly.severity === 'critical' ? 25 : 
                       anomaly.severity === 'high' ? 15 : 
                       anomaly.severity === 'medium' ? 10 : 5
      return sum + multiplier
    }, 0)
    return Math.min(level, 100)
  }, [anomalies])

  return {
    anomalies,
    detectAnomalies,
    riskLevel
  }
}
