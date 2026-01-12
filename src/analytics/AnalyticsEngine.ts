import { AnalyticsRule, AuthEvent, AnalyticsContext, AnalyticsResult, Anomaly } from './types'

// Import all the rules
import { BruteForceDetectionRule } from './rules/BruteForceDetectionRule'
import { GeographicAnomalyRule } from './rules/GeographicAnomalyRule'
import { OffHoursAccessRule } from './rules/OffHoursAccessRule'
import { PrivilegedAccessRule } from './rules/PrivilegedAccessRule'
import { UserActivityRule } from './rules/UserActivityRule'
import { PasswordChangeRule } from './rules/PasswordChangeRule'
import { MultipleFailureRule } from './rules/MultipleFailureRule'
import { LogonPatternRule } from './rules/LogonPatternRule'
import { NTLMAuthenticationRule } from './rules/NTLMAuthenticationRule'
import { KerberosAuthenticationRule } from './rules/KerberosAuthenticationRule'
import { PasswordSprayRule } from './rules/PasswordSprayRule'
import { RDPActivityRule } from './rules/RDPActivityRule'
import { ExplicitCredentialsRule } from './rules/ExplicitCredentialsRule'
import { LocalAdminAttacksRule } from './rules/LocalAdminAttacksRule'
import { AnonymousAccountRule } from './rules/AnonymousAccountRule'
import { SMBEnumerationRule } from './rules/SMBEnumerationRule'

// Correlation Rules
import { HostUserAlertCorrelationRule } from './rules/HostUserAlertCorrelationRule'
import { IpAlertPatternRule } from './rules/IpAlertPatternRule'
import { TimeWindowCorrelationRule } from './rules/TimeWindowCorrelationRule'
import { PrivilegeEscalationCorrelationRule } from './rules/PrivilegeEscalationCorrelationRule'

// Service Account Rules
import { ServiceAccountAnomalyRule } from './rules/ServiceAccountAnomalyRule'
import { ServiceAccountLifecycleRule } from './rules/ServiceAccountLifecycleRule'
import { ServiceAccountCorrelationRule } from './rules/ServiceAccountCorrelationRule'

// Enhanced Password Spraying Detection
import { PasswordSprayPatternRule } from './rules/PasswordSprayPatternRule'

// ADCS (Active Directory Certificate Services) Rules
import { ESC1Rule } from './rules/ESC1Rule'
import { ESC2Rule } from './rules/ESC2Rule'
import { ESC3Rule } from './rules/ESC3Rule'
import { ESC4Rule } from './rules/ESC4Rule'
import { ESC6Rule } from './rules/ESC6Rule'
import { ESC7Rule } from './rules/ESC7Rule'
import { ESC8Rule } from './rules/ESC8Rule'
import { ESC9Rule } from './rules/ESC9Rule'
import { ESC11Rule } from './rules/ESC11Rule'
import { ESC13Rule } from './rules/ESC13Rule'
import { ESC15Rule } from './rules/ESC15Rule'
import { ESC16Rule } from './rules/ESC16Rule'
import { ADCSAuditingRule } from './rules/ADCSAuditingRule'
import { CertificateToolDetectionRule } from './rules/CertificateToolDetectionRule'
import { CertificateExportRule } from './rules/CertificateExportRule'
import { CABackupRule } from './rules/CABackupRule'
import { CertificateAuthenticationCorrelationRule } from './rules/CertificateAuthenticationCorrelationRule'
import { ADCSAttackChainCorrelationRule } from './rules/ADCSAttackChainCorrelationRule'

// SharpHound-specific rules
import { SharpHoundKerberosDelegationRule } from './rules/SharpHoundKerberosDelegationRule'
import { SharpHoundPrivilegedAccountsRule } from './rules/SharpHoundPrivilegedAccountsRule'
import { SharpHoundLAPSAnalysisRule } from './rules/SharpHoundLAPSAnalysisRule'
import { SharpHoundDomainTrustAnalysisRule } from './rules/SharpHoundDomainTrustAnalysisRule'
import { SharpHoundServiceAccountAnalysisRule } from './rules/SharpHoundServiceAccountAnalysisRule'
import { SharpHoundGroupMembershipAnalysisRule } from './rules/SharpHoundGroupMembershipAnalysisRule'
import { SharpHoundComputerAccountAnalysisRule } from './rules/SharpHoundComputerAccountAnalysisRule'
import { SharpHoundGPOSecurityAnalysisRule } from './rules/SharpHoundGPOSecurityAnalysisRule'
import { SharpHoundPasswordPolicyAnalysisRule } from './rules/SharpHoundPasswordPolicyAnalysisRule'
import { SharpHoundDomainControllerAnalysisRule } from './rules/SharpHoundDomainControllerAnalysisRule'
import { SharpHoundCertificateTemplateAnalysisRule } from './rules/SharpHoundCertificateTemplateAnalysisRule'
import { SharpHoundUserRightsAnalysisRule } from './rules/SharpHoundUserRightsAnalysisRule'
import { SharpHoundSIDHistoryAnalysisRule } from './rules/SharpHoundSIDHistoryAnalysisRule'

export class AnalyticsEngine {
  private rules: Map<string, AnalyticsRule> = new Map()
  private enabledRules: Set<string> = new Set()

  constructor() {
    this.initializeDefaultRules()
  }

  private initializeDefaultRules(): void {
    // Register core security detection rules
    this.registerRule(new BruteForceDetectionRule())
    this.registerRule(new GeographicAnomalyRule())
    this.registerRule(new OffHoursAccessRule())
    this.registerRule(new PrivilegedAccessRule())

    // Register advanced pattern detection rules
    this.registerRule(new MultipleFailureRule())
    this.registerRule(new LogonPatternRule())

    // Register Windows Event Log specific rules (from event_code_analytics.json)
    this.registerRule(new NTLMAuthenticationRule())
    this.registerRule(new KerberosAuthenticationRule())
    this.registerRule(new PasswordSprayRule())
    this.registerRule(new RDPActivityRule())
    this.registerRule(new ExplicitCredentialsRule())
    this.registerRule(new LocalAdminAttacksRule())
    this.registerRule(new AnonymousAccountRule())
    this.registerRule(new SMBEnumerationRule())

    // Register informational and activity tracking rules
    this.registerRule(new UserActivityRule())
    this.registerRule(new PasswordChangeRule())

    // Register correlation rules (advanced threat detection)
    this.registerRule(new HostUserAlertCorrelationRule())
    this.registerRule(new IpAlertPatternRule())
    this.registerRule(new TimeWindowCorrelationRule())
    this.registerRule(new PrivilegeEscalationCorrelationRule())

    // Register service account security rules (based on AD Service Accounts fundamentals)
    this.registerRule(new ServiceAccountAnomalyRule())
    this.registerRule(new ServiceAccountLifecycleRule())
    this.registerRule(new ServiceAccountCorrelationRule())

    // Register enhanced password spraying detection (based on AD Security article)
    this.registerRule(new PasswordSprayPatternRule())

    // Register ADCS (Active Directory Certificate Services) attack detection rules
    this.registerRule(new ESC1Rule())
    this.registerRule(new ESC2Rule())
    this.registerRule(new ESC3Rule())
    this.registerRule(new ESC4Rule())
    this.registerRule(new ESC6Rule())
    this.registerRule(new ESC7Rule())
    this.registerRule(new ESC8Rule())
    this.registerRule(new ESC9Rule())
    this.registerRule(new ESC11Rule())
    this.registerRule(new ESC13Rule())
    this.registerRule(new ESC15Rule())
    this.registerRule(new ESC16Rule())
    this.registerRule(new ADCSAuditingRule())
    this.registerRule(new CertificateToolDetectionRule())
    this.registerRule(new CertificateExportRule())
    this.registerRule(new CABackupRule())
    this.registerRule(new CertificateAuthenticationCorrelationRule())
    this.registerRule(new ADCSAttackChainCorrelationRule())

    // Register SharpHound-specific rules
    this.registerRule(new SharpHoundKerberosDelegationRule())
    this.registerRule(new SharpHoundPrivilegedAccountsRule())
    this.registerRule(new SharpHoundLAPSAnalysisRule())
    this.registerRule(new SharpHoundDomainTrustAnalysisRule())
    this.registerRule(new SharpHoundServiceAccountAnalysisRule())
    this.registerRule(new SharpHoundGroupMembershipAnalysisRule())
    this.registerRule(new SharpHoundComputerAccountAnalysisRule())
    this.registerRule(new SharpHoundGPOSecurityAnalysisRule())
    this.registerRule(new SharpHoundPasswordPolicyAnalysisRule())
    this.registerRule(new SharpHoundDomainControllerAnalysisRule())
    this.registerRule(new SharpHoundCertificateTemplateAnalysisRule())
    this.registerRule(new SharpHoundUserRightsAnalysisRule())
    this.registerRule(new SharpHoundSIDHistoryAnalysisRule())
  }

  /**
   * Register a new analytics rule
   */
  registerRule(rule: AnalyticsRule): void {
    const validation = rule.validate()
    if (!validation.valid) {
      throw new Error(`Invalid rule "${rule.name}": ${validation.errors.join(', ')}`)
    }

    this.rules.set(rule.id, rule)
    if (rule.enabled) {
      this.enabledRules.add(rule.id)
    }
  }

  /**
   * Unregister a rule
   */
  unregisterRule(ruleId: string): boolean {
    this.enabledRules.delete(ruleId)
    return this.rules.delete(ruleId)
  }

  /**
   * Enable a rule
   */
  enableRule(ruleId: string): boolean {
    const rule = this.rules.get(ruleId)
    if (rule) {
      rule.enabled = true
      this.enabledRules.add(ruleId)
      return true
    }
    return false
  }

  /**
   * Disable a rule
   */
  disableRule(ruleId: string): boolean {
    const rule = this.rules.get(ruleId)
    if (rule) {
      rule.enabled = false
      this.enabledRules.delete(ruleId)
      return true
    }
    return false
  }

  /**
   * Get all registered rules
   */
  getRules(): AnalyticsRule[] {
    return Array.from(this.rules.values())
  }

  /**
   * Get enabled rules
   */
  getEnabledRules(): AnalyticsRule[] {
    return Array.from(this.enabledRules).map(id => this.rules.get(id)!).filter(Boolean)
  }

  /**
   * Get a specific rule
   */
  getRule(ruleId: string): AnalyticsRule | undefined {
    return this.rules.get(ruleId)
  }

  /**
   * Update rule configuration
   */
  updateRuleConfig(ruleId: string, config: Partial<AnalyticsRule>): boolean {
    const rule = this.rules.get(ruleId)
    if (!rule) return false

    // Update configurable properties
    if (config.enabled !== undefined) {
      rule.enabled = config.enabled
      if (config.enabled) {
        this.enabledRules.add(ruleId)
      } else {
        this.enabledRules.delete(ruleId)
      }
    }
    if (config.timeWindow !== undefined) rule.timeWindow = config.timeWindow
    if (config.thresholds) rule.thresholds = { ...rule.thresholds, ...config.thresholds }

    return true
  }

  /**
   * Run analytics on events with optional user rule configurations
   */
  async analyze(events: AuthEvent[], context: AnalyticsContext, userRuleConfigs?: any[]): Promise<AnalyticsResult> {
    const startTime = Date.now()
    const ruleResults: AnalyticsResult['ruleResults'] = []
    const allAnomalies: Anomaly[] = []

    // Get rules with user configurations applied
    const rulesToExecute = userRuleConfigs || Array.from(this.enabledRules).map(id => this.rules.get(id)).filter(Boolean)

    // Debug logging removed - keeping clean for production

    // Run all enabled rules
    for (const rule of rulesToExecute) {
      if (!rule || !rule.enabled) {
        continue
      }

      const ruleStartTime = Date.now()
      let executed = false
      let anomaliesFound = 0
      let error: string | undefined

      try {
        const anomalies = await rule.analyze(events, context)
        allAnomalies.push(...anomalies)
        anomaliesFound = anomalies.length
        executed = true
      } catch (err) {
        error = err instanceof Error ? err.message : 'Unknown error'
        console.error(`Error executing rule ${rule.name}:`, err)
      }

      ruleResults.push({
        ruleId: rule.id,
        ruleName: rule.name,
        executed,
        executionTime: Date.now() - ruleStartTime,
        anomaliesFound,
        error
      })
    }

    // Calculate summary
    const executionTime = Date.now() - startTime
    const severityOrder: Record<string, number> = { low: 1, medium: 2, high: 3, critical: 4 }
    const highestSeverity = allAnomalies.reduce((highest, anomaly) => {
      if (!highest) return anomaly.severity
      return severityOrder[anomaly.severity] > severityOrder[highest] ? anomaly.severity : highest
    }, null as string | null) as AnalyticsResult['summary']['highestSeverity']

    return {
      sessionId: context.sessionId,
      ruleResults,
      anomalies: allAnomalies,
      summary: {
        totalRulesExecuted: ruleResults.filter(r => r.executed).length,
        totalAnomalies: allAnomalies.length,
        highestSeverity,
        executionTime
      },
      timestamp: new Date()
    }
  }

  /**
   * Get analytics for specific rule categories
   */
  async analyzeByCategory(
    events: AuthEvent[],
    context: AnalyticsContext,
    category: 'authentication' | 'network' | 'behavior' | 'privilege' | 'temporal' | 'correlation'
  ): Promise<AnalyticsResult> {
    const categoryRules = this.getEnabledRules().filter(rule => rule.category === category)
    const originalEnabledRules = new Set(this.enabledRules)

    try {
      // Temporarily enable only category rules
      this.enabledRules.clear()
      categoryRules.forEach(rule => this.enabledRules.add(rule.id))

      const result = await this.analyze(events, context)
      return result
    } finally {
      // Restore original enabled rules
      this.enabledRules = originalEnabledRules
    }
  }

  /**
   * Get rule statistics
   */
  getStatistics(): {
    totalRules: number
    enabledRules: number
    rulesByCategory: Record<string, number>
    rulesBySeverity: Record<string, number>
  } {
    const rules = this.getRules()
    
    const rulesByCategory = rules.reduce((acc, rule) => {
      acc[rule.category] = (acc[rule.category] || 0) + 1
      return acc
    }, {} as Record<string, number>)

    const rulesBySeverity = rules.reduce((acc, rule) => {
      acc[rule.severity] = (acc[rule.severity] || 0) + 1
      return acc
    }, {} as Record<string, number>)

    return {
      totalRules: rules.length,
      enabledRules: this.enabledRules.size,
      rulesByCategory,
      rulesBySeverity
    }
  }

  /**
   * Export rule configuration
   */
  exportConfiguration(): any {
    return {
      rules: this.getRules().map(rule => rule.getMetadata()),
      enabledRules: Array.from(this.enabledRules),
      exportedAt: new Date()
    }
  }

  /**
   * Test a single rule with events
   */
  async testRule(ruleId: string, events: AuthEvent[], context: AnalyticsContext): Promise<{
    rule: AnalyticsRule
    anomalies: Anomaly[]
    executionTime: number
    error?: string
  }> {
    const rule = this.rules.get(ruleId)
    if (!rule) {
      throw new Error(`Rule ${ruleId} not found`)
    }

    const startTime = Date.now()
    let anomalies: Anomaly[] = []
    let error: string | undefined

    try {
      anomalies = await rule.analyze(events, context)
    } catch (err) {
      error = err instanceof Error ? err.message : 'Unknown error'
    }

    return {
      rule,
      anomalies,
      executionTime: Date.now() - startTime,
      error
    }
  }
}
