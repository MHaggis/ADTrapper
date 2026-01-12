import { AnalyticsRule, AuthEvent, Anomaly, AnalyticsContext } from './types'

export abstract class BaseRule implements AnalyticsRule {
  public readonly id: string
  public readonly name: string
  public readonly description: string
  public readonly detailedDescription?: {
    overview: string
    detectionLogic: string
    falsePositives: string
    mitigation: string[]
    windowsEvents: string[]
    exampleQuery: string
    recommendedThresholds: Record<string, any>
  }
  public readonly category: 'authentication' | 'network' | 'behavior' | 'privilege' | 'temporal' | 'informational' | 'security' | 'behavioral' | 'correlation'
  public readonly severity: 'low' | 'medium' | 'high' | 'critical' | 'info'
  public readonly version: string
  public readonly author: string
  public readonly created: Date
  public readonly updated: Date
  
  public enabled: boolean = true
  public timeWindow: number = 60 // minutes
  public thresholds: Record<string, number> = {}

  constructor(config: Partial<AnalyticsRule>) {
    this.id = config.id || this.generateId()
    this.name = config.name || 'Unnamed Rule'
    this.description = config.description || 'No description provided'
    this.detailedDescription = config.detailedDescription as any
    this.category = config.category || 'behavior'
    this.severity = config.severity || 'medium'
    this.version = config.version || '1.0.0'
    this.author = config.author || 'ADTrapper'
    this.created = config.created || new Date()
    this.updated = config.updated || new Date()

    if (config.enabled !== undefined) this.enabled = config.enabled
    if (config.timeWindow !== undefined) this.timeWindow = config.timeWindow
    if (config.thresholds) this.thresholds = { ...config.thresholds }
  }

  // Abstract method that each rule must implement
  abstract analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]>

  // Validation method
  validate(): { valid: boolean; errors: string[] } {
    const errors: string[] = []
    
    if (!this.id) errors.push('Rule ID is required')
    if (!this.name) errors.push('Rule name is required')
    if (!this.description) errors.push('Rule description is required')
    if (!['authentication', 'network', 'behavior', 'privilege', 'temporal', 'informational', 'security', 'behavioral', 'correlation'].includes(this.category)) {
      errors.push('Invalid category')
    }
    if (!['low', 'medium', 'high', 'critical', 'info'].includes(this.severity)) {
      errors.push('Invalid severity')
    }
    
    return {
      valid: errors.length === 0,
      errors
    }
  }

  // Helper method to create anomalies
  protected createAnomaly(
    title: string,
    description: string,
    evidence: Record<string, any>,
    confidence: number = 80,
    metadata: Record<string, any> = {}
  ): Anomaly {
    return {
      id: this.generateId(),
      ruleId: this.id,
      ruleName: this.name,
      severity: this.severity,
      title,
      description,
      category: this.category,
      confidence: Math.min(100, Math.max(0, confidence)),
      evidence,
      affectedEntities: this.extractAffectedEntities(evidence),
      timeWindow: {
        start: new Date(Date.now() - this.timeWindow * 60 * 1000),
        end: new Date()
      },
      metadata,
      timestamp: new Date(),
      detectedAt: new Date()
    }
  }

  // Helper to filter events by time window
  protected filterByTimeWindow(events: AuthEvent[]): AuthEvent[] {
    const cutoff = new Date(Date.now() - this.timeWindow * 60 * 1000)
    return events.filter(event => event.timestamp >= cutoff)
  }

  // Helper to group events by a field
  protected groupBy<T>(array: T[], keyFn: (item: T) => string): Record<string, T[]> {
    return array.reduce((groups, item) => {
      const key = keyFn(item)
      groups[key] = groups[key] || []
      groups[key].push(item)
      return groups
    }, {} as Record<string, T[]>)
  }

  // Helper to safely get timestamp as milliseconds (handles both Date and string timestamps)
  protected getTimestampMs(timestamp: Date | string): number {
    return timestamp instanceof Date
      ? timestamp.getTime()
      : new Date(timestamp).getTime()
  }

  // Helper to count occurrences
  protected countBy<T>(array: T[], keyFn: (item: T) => string): Record<string, number> {
    return array.reduce((counts, item) => {
      const key = keyFn(item)
      counts[key] = (counts[key] || 0) + 1
      return counts
    }, {} as Record<string, number>)
  }

  // Helper to extract affected entities from evidence
  private extractAffectedEntities(evidence: Record<string, any>): Anomaly['affectedEntities'] {
    const entities: Array<{ type: 'user' | 'computer' | 'ip'; id: string; name: string }> = []

    // Extract users
    if (evidence.user || evidence.users || evidence.userName) {
      const users = Array.isArray(evidence.users) 
        ? evidence.users 
        : [evidence.user || evidence.userName].filter(Boolean)
      users.forEach((user: string) => {
        entities.push({ type: 'user', id: user, name: user })
      })
    }

    // Extract computers
    if (evidence.computer || evidence.computers || evidence.computerName) {
      const computers = Array.isArray(evidence.computers)
        ? evidence.computers
        : [evidence.computer || evidence.computerName].filter(Boolean)
      computers.forEach((computer: string) => {
        entities.push({ type: 'computer', id: computer, name: computer })
      })
    }

    // Extract IPs
    if (evidence.ip || evidence.ips || evidence.sourceIp) {
      const ips = Array.isArray(evidence.ips)
        ? evidence.ips
        : [evidence.ip || evidence.sourceIp].filter(Boolean)
      ips.forEach((ip: string) => {
        entities.push({ type: 'ip', id: ip, name: ip })
      })
    }

    return entities.length > 0 ? entities : undefined
  }

  // Generate unique ID
  private generateId(): string {
    return `rule_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  }

  // Get rule metadata
  public getMetadata() {
    return {
      id: this.id,
      name: this.name,
      description: this.description,
      detailedDescription: this.detailedDescription,
      category: this.category,
      severity: this.severity,
      enabled: this.enabled,
      timeWindow: this.timeWindow,
      thresholds: this.thresholds,
      version: this.version,
      author: this.author,
      created: this.created,
      updated: this.updated
    }
  }
}
