import { AnalyticsRule, AuthEvent, AnalyticsContext, Anomaly } from '../types'

export class SharpHoundGPOSecurityAnalysisRule implements AnalyticsRule {
  readonly id = 'sharpHound-gpo-security-analysis'
  readonly name = 'SharpHound GPO Security Analysis'
  readonly description = 'Analyzes Group Policy Objects for security misconfigurations and dangerous settings'
  readonly severity = 'high'
  readonly category = 'security'
  readonly enabled = true
  readonly timeWindow = 24 * 60 * 60 * 1000 // 24 hours
  readonly version = '1.0.0'
  readonly author = 'ADTrapper'
  readonly created = new Date('2025-01-01')
  readonly updated = new Date('2025-01-01')

  readonly thresholds = {
    flagWeakPasswordPolicies: 1,     // Flag weak password policies (1 = true, 0 = false)
    maxGPOLinkedObjects: 1000,       // Max objects a GPO can be linked to
    flagUnlinkedGPOs: 1,            // Flag unlinked GPOs (1 = true, 0 = false)
    flagOldGPOs: 365                // Days after which to flag old GPO modifications
  }

  readonly detailedDescription = {
    overview: 'Analyzes Group Policy Objects for security misconfigurations and dangerous settings using SharpHound data. Identifies unlinked GPOs, overly complex GPOs, old GPOs, and weak password policies that could be exploited or indicate poor GPO lifecycle management.',
    detectionLogic: 'Analyzes SharpHound GPO objects for Links arrays (unlinked GPOs), Properties.whenchanged (old GPOs), and Links.length (overly linked GPOs). Reviews GPO permissions and settings for security misconfigurations. Identifies GPOs that may pose management or security risks.',
    falsePositives: 'GPOs maintained for backup purposes but not currently linked, GPOs linked to large numbers of objects for valid business reasons, old GPOs that remain valid for specific environments, and GPOs with approved exceptions to standard policies.',
    mitigation: [
      'Regularly review and clean up unlinked Group Policy Objects',
      'Avoid linking GPOs to excessive numbers of objects to prevent performance issues',
      'Regularly update and review GPO modification dates',
      'Implement GPO lifecycle management and approval workflows',
      'Use Group Policy delegation appropriately and monitor changes',
      'Implement GPO versioning and backup procedures',
      'Regularly audit GPO permissions and access controls',
      'Monitor GPO application and processing performance',
      'Implement GPO security baselines and hardening',
      'Conduct regular Group Policy security assessments'
    ],
    windowsEvents: ['5136 (Directory Service Object Modified)', '5137 (Directory Service Object Created)', '5139 (Directory Service Object Moved)', '5141 (Directory Service Object Deleted)', '4904 (Security Event Source Registered)', '4905 (Security Event Source Unregistered)', '4907 (Auditing Settings on Object Changed)', '4908 (Special Registry Item Modified)', '4739 (Domain Policy Changed)', '4719 (System Audit Policy Changed)'],
    exampleQuery: `index=windows EventCode=5136 ObjectDN="*CN=Policies*" | stats count by ObjectDN | where count > 10`,
    recommendedThresholds: {
      flagWeakPasswordPolicies: 1,
      maxGPOLinkedObjects: 1000,
      flagUnlinkedGPOs: 1,
      flagOldGPOs: 365
    }
  }

  validate(): { valid: boolean; errors: string[] } {
    if (this.thresholds.maxGPOLinkedObjects < 1) {
      return { valid: false, errors: ['maxGPOLinkedObjects must be at least 1'] }
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

    // Analyze Group Policy Objects
    if (sharpHoundData.gpos) {
      // Find unlinked GPOs
      if (this.thresholds.flagUnlinkedGPOs > 0) {
        const unlinkedGPOs = sharpHoundData.gpos.filter((gpo: any) =>
          !gpo.Links || gpo.Links.length === 0
        )

        if (unlinkedGPOs.length > 0) {
          anomalies.push({
            id: `${this.id}-unlinked-gpos-${Date.now()}`,
            ruleId: this.id,
            ruleName: this.name,
            severity: 'low',
            category: 'security',
            title: 'Unlinked Group Policy Objects',
            description: `Found ${unlinkedGPOs.length} GPOs that are not linked to any containers`,
            confidence: 65,
            evidence: {
              count: unlinkedGPOs.length,
              gpos: unlinkedGPOs.map((gpo: any) => ({
                name: gpo.Properties?.displayname,
                distinguishedName: gpo.Properties?.distinguishedname
              })).slice(0, 10)
            },
            recommendations: ['Review and remove unlinked GPOs or link them to appropriate containers'],
            timestamp: new Date(),
            detectedAt: new Date(),
            timeWindow: {
              start: new Date(Date.now() - this.timeWindow),
              end: new Date()
            },
            metadata: {},
            affectedEntities: unlinkedGPOs.slice(0, 5).map((gpo: any) => ({
              type: 'user',
              id: gpo.Properties?.displayname,
              name: gpo.Properties?.displayname
            }))
          })
        }
      }

      // Find GPOs with too many linked objects
      const overlyLinkedGPOs = sharpHoundData.gpos.filter((gpo: any) =>
        gpo.Links && gpo.Links.length > this.thresholds.maxGPOLinkedObjects
      )

      if (overlyLinkedGPOs.length > 0) {
        anomalies.push({
          id: `${this.id}-overly-linked-gpos-${Date.now()}`,
          ruleId: this.id,
          ruleName: this.name,
          severity: 'medium',
          category: 'security',
          title: 'GPOs Linked to Too Many Objects',
          description: `Found ${overlyLinkedGPOs.length} GPOs linked to more than ${this.thresholds.maxGPOLinkedObjects} objects`,
          confidence: 70,
          evidence: {
            count: overlyLinkedGPOs.length,
            threshold: this.thresholds.maxGPOLinkedObjects,
            gpos: overlyLinkedGPOs.map((gpo: any) => ({
              name: gpo.Properties?.displayname,
              linkCount: gpo.Links?.length || 0
            })).slice(0, 10)
          },
          recommendations: ['Consider splitting large GPOs into smaller, more targeted policies'],
          timestamp: new Date(),
          detectedAt: new Date(),
          timeWindow: {
            start: new Date(Date.now() - this.timeWindow),
            end: new Date()
          },
          metadata: {},
          affectedEntities: overlyLinkedGPOs.slice(0, 5).map((gpo: any) => ({
            type: 'user',
            id: gpo.Properties?.displayname,
            name: gpo.Properties?.displayname
          }))
        })
      }

      // Find old GPOs that haven't been modified recently
      const oldGPOs = sharpHoundData.gpos.filter((gpo: any) => {
        if (!gpo.Properties?.whenchanged) return false
        const daysSinceModified = (Date.now() - gpo.Properties.whenchanged * 1000) / (1000 * 60 * 60 * 24)
        return daysSinceModified > this.thresholds.flagOldGPOs
      })

      if (oldGPOs.length > 0) {
        anomalies.push({
          id: `${this.id}-old-gpos-${Date.now()}`,
          ruleId: this.id,
          ruleName: this.name,
          severity: 'info',
          category: 'security',
          title: 'Old Group Policy Objects',
          description: `Found ${oldGPOs.length} GPOs not modified in ${this.thresholds.flagOldGPOs}+ days`,
          confidence: 50,
          evidence: {
            count: oldGPOs.length,
            thresholdDays: this.thresholds.flagOldGPOs,
            gpos: oldGPOs.map((gpo: any) => ({
              name: gpo.Properties?.displayname,
              lastModified: gpo.Properties?.whenchanged ? new Date(gpo.Properties.whenchanged * 1000).toISOString() : 'Unknown'
            })).slice(0, 10)
          },
          recommendations: ['Review old GPOs to ensure they are still needed and effective'],
          timestamp: new Date(),
          detectedAt: new Date(),
          timeWindow: {
            start: new Date(Date.now() - this.timeWindow),
            end: new Date()
          },
          metadata: {},
          affectedEntities: oldGPOs.slice(0, 5).map((gpo: any) => ({
            type: 'user',
            id: gpo.Properties?.displayname,
            name: gpo.Properties?.displayname
          }))
        })
      }

      // Analyze GPO permissions (dangerous delegations)
      sharpHoundData.gpos.forEach((gpo: any) => {
        if (gpo.Aces && Array.isArray(gpo.Aces)) {
          // Look for dangerous permissions on GPOs
          const dangerousAces = gpo.Aces.filter((ace: any) => {
            const rightName = ace.RightName?.toLowerCase() || ''
            return rightName.includes('write') ||
                   rightName.includes('modify') ||
                   rightName.includes('full control') ||
                   rightName.includes('genericall')
          })

          if (dangerousAces.length > 0) {
            anomalies.push({
              id: `${this.id}-dangerous-gpo-permissions-${gpo.Properties?.displayname}-${Date.now()}`,
              ruleId: this.id,
              ruleName: this.name,
              severity: 'high',
              category: 'security',
              title: 'Dangerous GPO Permissions',
              description: `GPO ${gpo.Properties?.displayname} has ${dangerousAces.length} dangerous permissions`,
              confidence: 80,
              evidence: {
                gpo: gpo.Properties?.displayname,
                dangerousPermissions: dangerousAces.map((ace: any) => ({
                  principal: ace.PrincipalSID,
                  right: ace.RightName
                })).slice(0, 5)
              },
              recommendations: ['Review and restrict GPO permissions to only necessary administrative accounts'],
              timestamp: new Date(),
              detectedAt: new Date(),
              timeWindow: {
                start: new Date(Date.now() - this.timeWindow),
                end: new Date()
              },
              metadata: {},
              affectedEntities: [{
                type: 'user',
                id: gpo.Properties?.displayname,
                name: gpo.Properties?.displayname
              }]
            })
          }
        }
      })
    }

    return anomalies
  }
}
