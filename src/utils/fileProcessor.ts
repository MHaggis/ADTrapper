export interface ProcessedLogData {
  nodes: GraphNode[]
  edges: GraphEdge[]
  events: AuthEvent[]
  metadata: {
    eventCount: number
    timeRange: string
    riskScore: number
    anomalyCount: number
  }
}

export interface GraphNode {
  id: string
  label: string
  type: 'user' | 'computer' | 'ip'
  riskScore: number
  privileged?: boolean
  department?: string
  country?: string
  city?: string
  enabled?: boolean
  x?: number
  y?: number
  vx?: number
  vy?: number
  tor?: boolean
  os?: string
  lastSeen?: Date
}

export interface GraphEdge {
  source: string
  target: string
  type: 'login' | 'connection'
  status: 'Success' | 'Failed' | 'Logoff'
  timestamp: string
  anomaly: boolean
  logonType?: string
}

export interface AuthEvent {
  id: string
  timestamp: string
  eventId: string
  computerName?: string
  userName?: string
  domainName?: string
  sourceIp?: string
  logonType?: string
  status: 'Success' | 'Failed' | 'Logoff'
  failureReason?: string
}

export class LogProcessor {
  static async processFile(file: File): Promise<ProcessedLogData> {
    const text = await file.text()
    
    let data
    if (file.name.endsWith('.json')) {
      data = JSON.parse(text)
    } else if (file.name.endsWith('.csv')) {
      data = await this.parseCSV(text)
    } else {
      throw new Error('Unsupported file format')
    }

    return this.processLogData(data)
  }

  private static parseCSV(text: string): Promise<any> {
    return new Promise((resolve, reject) => {
      // Simple CSV parsing - in production, use a proper CSV parser like papaparse
      const lines = text.split('\n')
      const headers = lines[0].split(',')
      const data = lines.slice(1).map(line => {
        const values = line.split(',')
        const obj: any = {}
        headers.forEach((header, index) => {
          obj[header.trim()] = values[index]?.trim()
        })
        return obj
      }).filter(obj => Object.keys(obj).length > 1)
      
      resolve(data)
    })
  }

  private static processLogData(rawData: any): ProcessedLogData {
    const events = Array.isArray(rawData) ? rawData : rawData.events || []
    const nodes = new Map<string, GraphNode>()
    const edges: GraphEdge[] = []
    const processedEvents: AuthEvent[] = []

    // Process each event
    events.forEach((event: any, index: number) => {
      const processedEvent: AuthEvent = {
        id: `event_${index}`,
        timestamp: event.TimeStamp || event.timestamp || new Date().toISOString(),
        eventId: event.EventID || event.Id || '4624',
        computerName: event.Computer || event.computer_name,
        userName: event.TargetUser || event.user_name,
        domainName: event.TargetDomain || event.domain_name,
        sourceIp: event.SourceIP || event.source_ip,
        logonType: event.LogonType || event.logon_type,
        status: event.Status || 'Success',
        failureReason: event.FailureReason || event.failure_reason
      }

      processedEvents.push(processedEvent)

      // Create nodes
      if (processedEvent.userName) {
        const userKey = `user_${processedEvent.userName}`
        if (!nodes.has(userKey)) {
          nodes.set(userKey, {
            id: userKey,
            label: processedEvent.userName,
            type: 'user',
            riskScore: this.calculateUserRiskScore(processedEvent, events),
            privileged: event.IsPrivilegedUser || false,
            department: event.UserDepartment,
            enabled: event.UserEnabled !== false
          })
        }
      }

      if (processedEvent.computerName) {
        const computerKey = `computer_${processedEvent.computerName}`
        if (!nodes.has(computerKey)) {
          nodes.set(computerKey, {
            id: computerKey,
            label: processedEvent.computerName,
            type: 'computer',
            riskScore: this.calculateComputerRiskScore(processedEvent, events)
          })
        }
      }

      if (processedEvent.sourceIp) {
        const ipKey = `ip_${processedEvent.sourceIp}`
        if (!nodes.has(ipKey)) {
          nodes.set(ipKey, {
            id: ipKey,
            label: processedEvent.sourceIp,
            type: 'ip',
            riskScore: this.calculateIpRiskScore(processedEvent, events),
            country: event.SourceCountry,
            city: event.SourceCity
          })
        }
      }

      // Create edges
      if (processedEvent.userName && processedEvent.computerName) {
        const isAnomalous = this.isAnomalousLogin(processedEvent, events)
        edges.push({
          source: `user_${processedEvent.userName}`,
          target: `computer_${processedEvent.computerName}`,
          type: 'login',
          status: processedEvent.status,
          timestamp: processedEvent.timestamp,
          anomaly: isAnomalous
        })
      }

      if (processedEvent.sourceIp && processedEvent.computerName) {
        edges.push({
          source: `ip_${processedEvent.sourceIp}`,
          target: `computer_${processedEvent.computerName}`,
          type: 'connection',
          status: processedEvent.status,
          timestamp: processedEvent.timestamp,
          anomaly: processedEvent.status === 'Failed' || this.isSuspiciousIP(processedEvent.sourceIp!)
        })
      }
    })

    const anomalyCount = edges.filter(e => e.anomaly).length
    const failedLogins = processedEvents.filter(e => e.status === 'Failed').length
    const riskScore = Math.min((failedLogins * 2) + (anomalyCount * 5), 100)

    return {
      nodes: Array.from(nodes.values()),
      edges,
      events: processedEvents,
      metadata: {
        eventCount: processedEvents.length,
        timeRange: this.calculateTimeRange(processedEvents),
        riskScore,
        anomalyCount
      }
    }
  }

  private static calculateUserRiskScore(event: AuthEvent, allEvents: any[]): number {
    const userEvents = allEvents.filter(e => e.TargetUser === event.userName || e.user_name === event.userName)
    const failedLogins = userEvents.filter(e => e.Status === 'Failed' || e.status === 'Failed').length
    const privileged = userEvents.some(e => e.IsPrivilegedUser)
    
    let score = 0
    score += failedLogins * 10
    if (privileged) score += 30
    
    return Math.min(score, 100)
  }

  private static calculateComputerRiskScore(event: AuthEvent, allEvents: any[]): number {
    const computerEvents = allEvents.filter(e => e.Computer === event.computerName || e.computer_name === event.computerName)
    const failedConnections = computerEvents.filter(e => e.Status === 'Failed' || e.status === 'Failed').length
    
    return Math.min(failedConnections * 5, 100)
  }

  private static calculateIpRiskScore(event: AuthEvent, allEvents: any[]): number {
    const ipEvents = allEvents.filter(e => e.SourceIP === event.sourceIp || e.source_ip === event.sourceIp)
    const failedAttempts = ipEvents.filter(e => e.Status === 'Failed' || e.status === 'Failed').length
    const isExternal = this.isExternalIP(event.sourceIp!)
    
    let score = failedAttempts * 5
    if (isExternal) score += 25
    if (this.isSuspiciousIP(event.sourceIp!)) score += 50
    
    return Math.min(score, 100)
  }

  private static isAnomalousLogin(event: AuthEvent, allEvents: any[]): boolean {
    // Multiple failed attempts followed by success
    const userEvents = allEvents.filter(e => 
      (e.TargetUser === event.userName || e.user_name === event.userName) &&
      new Date(e.TimeStamp || e.timestamp).getTime() < new Date(event.timestamp).getTime()
    ).sort((a, b) => new Date(a.TimeStamp || a.timestamp).getTime() - new Date(b.TimeStamp || b.timestamp).getTime())

    const recentFailures = userEvents.slice(-5).filter(e => e.Status === 'Failed' || e.status === 'Failed').length
    return recentFailures >= 3 && event.status === 'Success'
  }

  private static isExternalIP(ip: string): boolean {
    // Simple check for private IP ranges
    const privateRanges = [
      /^10\./,
      /^192\.168\./,
      /^172\.(1[6-9]|2[0-9]|3[01])\./,
      /^127\./,
      /^169\.254\./
    ]
    
    return !privateRanges.some(range => range.test(ip))
  }

  private static isSuspiciousIP(ip: string): boolean {
    // In a real implementation, this would check against threat intelligence feeds
    // For demo purposes, we'll mark certain IP patterns as suspicious
    return ip.startsWith('185.') || ip.startsWith('203.') || ip.includes('tor-exit')
  }

  private static calculateTimeRange(events: AuthEvent[]): string {
    if (events.length === 0) return '0 hours'
    
    const timestamps = events.map(e => new Date(e.timestamp).getTime())
    const earliest = Math.min(...timestamps)
    const latest = Math.max(...timestamps)
    const diffHours = (latest - earliest) / (1000 * 60 * 60)
    
    if (diffHours < 1) return `${Math.round(diffHours * 60)} minutes`
    if (diffHours < 24) return `${Math.round(diffHours)} hours`
    return `${Math.round(diffHours / 24)} days`
  }
}
