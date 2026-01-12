import { AnalyticsRule, AuthEvent, AnalyticsContext, Anomaly } from '../types'

export class SharpHoundDomainTrustAnalysisRule implements AnalyticsRule {
  readonly id = 'sharpHound-domain-trust-analysis'
  readonly name = 'SharpHound Domain Trust Analysis'
  readonly description = 'Analyzes domain trust relationships for security risks and misconfigurations'
  readonly severity = 'high'
  readonly category = 'privilege'
  readonly enabled = true
  readonly timeWindow = 24 * 60 * 60 * 1000 // 24 hours
  readonly version = '1.0.0'
  readonly author = 'ADTrapper'
  readonly created = new Date('2025-01-01')
  readonly updated = new Date('2025-01-01')

  readonly thresholds = {
    maxTrustHops: 3,           // Maximum trust hops before flagging
    flagExternalTrusts: 1,     // Flag external trusts (1 = true, 0 = false)
    flagNonTransitive: 1,      // Flag non-transitive trusts (1 = true, 0 = false)
    flagSIDFilteringDisabled: 1 // Flag trusts with SID filtering disabled
  }

  readonly detailedDescription = {
    overview: 'Analyzes domain trust relationships for security risks and misconfigurations using SharpHound data. Identifies external trusts, non-transitive trusts, disabled SID filtering, and complex trust chains that could enable privilege escalation and lateral movement across domain boundaries.',
    detectionLogic: 'Analyzes SharpHound domain objects for Trusts arrays, examining TrustType, TrustDirection, IsTransitive, and SID filtering status. Identifies trust relationships that may pose security risks or enable attack paths across domain boundaries.',
    falsePositives: 'Approved external trusts with trusted partner organizations, non-transitive trusts designed for security isolation, trusts with SID filtering intentionally disabled for specific business requirements, and trust configurations that have been reviewed and approved by security teams.',
    mitigation: [
      'Regularly review and audit domain trust relationships',
      'Implement SID filtering on external trusts to prevent SID spoofing',
      'Limit external domain trusts to only necessary business partners',
      'Use non-transitive trusts when security isolation is required',
      'Monitor cross-domain authentication and privilege escalation attempts',
      'Implement trust relationship approval and documentation workflows',
      'Regularly validate trust configurations against security policies',
      'Enable detailed auditing for trust-related activities',
      'Conduct regular domain trust security assessments',
      'Implement cross-domain access control and monitoring'
    ],
    windowsEvents: ['4624 (Account Logon Success)', '4625 (Account Logon Failure)', '4672 (Special Privileges Assigned)', '4768 (Kerberos TGT Requested)', '4769 (Kerberos Service Ticket Operations)', '4771 (Kerberos Pre-auth Failed)', '4675 (SIDs Filtered)', '4904 (Security Event Source Registered)', '4905 (Security Event Source Unregistered)', '5136 (Directory Service Object Modified)', '5137 (Directory Service Object Created)', '5141 (Directory Service Object Deleted)'],
    exampleQuery: `index=windows EventCode=4675 | stats count by TargetUserName | where count > 5`,
    recommendedThresholds: {
      maxTrustHops: 3,
      flagExternalTrusts: 1,
      flagNonTransitive: 1,
      flagSIDFilteringDisabled: 1
    }
  }

  validate(): { valid: boolean; errors: string[] } {
    if (this.thresholds.maxTrustHops < 1) {
      return { valid: false, errors: ['maxTrustHops must be at least 1'] }
    }
    return { valid: true, errors: [] }
  }

  getMetadata() {
    return {
      id: this.id,
      name: this.name,
      description: this.description,
      severity: this.severity,
      category: this.category,
      enabled: this.enabled,
      timeWindow: this.timeWindow,
      thresholds: this.thresholds
    }
  }

  async analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = []

    if (!context.sharpHoundData) {
      return anomalies
    }

    const sharpHoundData = context.sharpHoundData

    // Analyze domain trust relationships
    if (sharpHoundData.domains) {
      sharpHoundData.domains.forEach((domain: any) => {
        // Check for dangerous trust configurations
        if (domain.Trusts) {
          domain.Trusts.forEach((trust: any) => {
            // Flag external domain trusts
            if (this.thresholds.flagExternalTrusts > 0 && trust.IsExternal === true) {
              anomalies.push({
                id: `${this.id}-external-trust-${domain.Properties.samaccountname}-${trust.TargetDomainName}-${Date.now()}`,
                ruleId: this.id,
                ruleName: this.name,
                severity: 'medium',
                category: 'privilege',
                title: 'External Domain Trust Detected',
                description: `Domain ${domain.Properties.samaccountname} has an external trust to ${trust.TargetDomainName}`,
                confidence: 75,
                evidence: {
                  sourceDomain: domain.Properties.samaccountname,
                  targetDomain: trust.TargetDomainName,
                  trustType: trust.TrustType,
                  trustDirection: trust.TrustDirection
                },
                recommendations: ['Review external trust necessity and security implications'],
                timestamp: new Date(),
                detectedAt: new Date(),
                timeWindow: {
                  start: new Date(Date.now() - this.timeWindow),
                  end: new Date()
                },
                metadata: {},
                affectedEntities: [{
                  type: 'user', // Using user type for domains since no domain type exists
                  id: domain.Properties.samaccountname,
                  name: domain.Properties.samaccountname
                }]
              })
            }

            // Flag non-transitive trusts (more dangerous)
            if (this.thresholds.flagNonTransitive > 0 && trust.IsTransitive === false) {
              anomalies.push({
                id: `${this.id}-non-transitive-trust-${domain.Properties.samaccountname}-${trust.TargetDomainName}-${Date.now()}`,
                ruleId: this.id,
                ruleName: this.name,
                severity: 'high',
                category: 'privilege',
                title: 'Non-Transitive Domain Trust',
                description: `Non-transitive trust found: ${domain.Properties.samaccountname} ↔ ${trust.TargetDomainName}`,
                confidence: 85,
                evidence: {
                  sourceDomain: domain.Properties.samaccountname,
                  targetDomain: trust.TargetDomainName,
                  trustType: trust.TrustType,
                  isTransitive: trust.IsTransitive
                },
                recommendations: ['Non-transitive trusts can limit attack paths but may indicate complex trust relationships'],
                timestamp: new Date(),
                detectedAt: new Date(),
                timeWindow: {
                  start: new Date(Date.now() - this.timeWindow),
                  end: new Date()
                },
                metadata: {},
                affectedEntities: [{
                  type: 'user',
                  id: domain.Properties.samaccountname,
                  name: domain.Properties.samaccountname
                }]
              })
            }

            // Flag trusts with SID filtering disabled
            if (this.thresholds.flagSIDFilteringDisabled > 0 && trust.SIDFilteringEnabled === false) {
              anomalies.push({
                id: `${this.id}-sid-filtering-disabled-${domain.Properties.samaccountname}-${trust.TargetDomainName}-${Date.now()}`,
                ruleId: this.id,
                ruleName: this.name,
                severity: 'critical',
                category: 'privilege',
                title: 'SID Filtering Disabled on Domain Trust',
                description: `SID filtering is disabled on trust: ${domain.Properties.samaccountname} ↔ ${trust.TargetDomainName}`,
                confidence: 95,
                evidence: {
                  sourceDomain: domain.Properties.samaccountname,
                  targetDomain: trust.TargetDomainName,
                  sidFilteringEnabled: trust.SIDFilteringEnabled
                },
                recommendations: ['Enable SID filtering to prevent SID spoofing attacks'],
                timestamp: new Date(),
                detectedAt: new Date(),
                timeWindow: {
                  start: new Date(Date.now() - this.timeWindow),
                  end: new Date()
                },
                metadata: {},
                affectedEntities: [{
                  type: 'user',
                  id: domain.Properties.samaccountname,
                  name: domain.Properties.samaccountname
                }]
              })
            }
          })
        }

        // Check domain functional level for security
        if (domain.Properties?.functionallevel) {
          const functionalLevel = parseInt(domain.Properties.functionallevel)
          if (functionalLevel < 7) { // Windows Server 2016 functional level
            anomalies.push({
              id: `${this.id}-old-functional-level-${domain.Properties.samaccountname}-${Date.now()}`,
              ruleId: this.id,
              ruleName: this.name,
              severity: 'low',
              category: 'security',
              title: 'Outdated Domain Functional Level',
              description: `Domain ${domain.Properties.samaccountname} is using functional level ${functionalLevel} (recommended: 7+)`,
              confidence: 60,
              evidence: {
                domain: domain.Properties.samaccountname,
                currentLevel: functionalLevel,
                recommendedLevel: 7
              },
              recommendations: ['Consider raising domain functional level for enhanced security features'],
              timestamp: new Date(),
              detectedAt: new Date(),
              timeWindow: {
                start: new Date(Date.now() - this.timeWindow),
                end: new Date()
              },
              metadata: {},
              affectedEntities: [{
                type: 'user',
                id: domain.Properties.samaccountname,
                name: domain.Properties.samaccountname
              }]
            })
          }
        }
      })
    }

    return anomalies
  }
}
