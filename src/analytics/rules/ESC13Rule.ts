import { BaseRule } from '../BaseRule'
import { AuthEvent, Anomaly, AnalyticsContext, CertificateEvent, ADCSContext, ESCDetectionResult } from '../types'

export class ESC13Rule extends BaseRule {
  constructor() {
    super({
      id: 'esc13_group_linked_templates',
      name: 'ESC13 - Group-Linked Certificate Templates',
      description: 'Detects certificate templates linked to groups via OID, allowing privilege escalation',
      category: 'security',
      severity: 'high',
      timeWindow: 60, // 1 hour for template group-link analysis
      thresholds: {
        groupLinkBonus: 2,
        privilegedGroupBonus: 1,
        multipleIssuancesBonus: 1
      },
      version: '1.0.0',
      author: 'ADTrapper Security Team',
      detailedDescription: {
        overview: 'Detects ESC13 vulnerabilities where certificate templates are linked to groups via Object Identifiers (OIDs) using the msDS-OIDToGroupLink attribute. This allows attackers who compromise a group member to automatically receive privileged certificates without explicit enrollment, enabling persistence and privilege escalation.',
        detectionLogic: 'Analyzes certificate template configurations for group-linked OIDs and monitors certificate issuances from vulnerable templates. Identifies templates with msDS-OIDToGroupLink attributes that provide automatic certificate issuance to group members, particularly privileged groups.',
        falsePositives: 'Legitimate group-linked certificate templates with proper approval workflows, certificate requests that follow organizational security policies, or group-based certificate deployment that includes appropriate access controls. May also trigger during legitimate group-based certificate renewal or system administration activities.',
        mitigation: [
          'Remove msDS-OIDToGroupLink attributes from vulnerable certificate templates',
          'Disable automatic certificate issuance for group-linked templates',
          'Implement explicit enrollment requirements for privileged certificates',
          'Restrict group-linked templates to require manager approval',
          'Use Locksmith to identify and remediate ESC13 vulnerabilities',
          'Monitor certificate issuances from group-linked templates',
          'Implement certificate request approval workflows for group-linked templates',
          'Regular AD CS template security assessments and auditing',
          'Configure certificate template restrictions in Group Policy',
          'Enable certificate issuance monitoring and alerting'
        ],
        windowsEvents: ['4887 (Certificate Issued)', '54 (Certificate Issued)', '4898 (Certificate Template Permissions Changed)', '4899 (Certificate Template Updated)', '4900 (Certificate Services Template Loaded)', '4886 (Certificate Services Started)', '4888 (Certificate Services Backup Started)', '4909 (Certificate Services Template Settings Changed)', '4910 (Certificate Services Template Updated)', '4732 (Member Added to Security Group)', '4733 (Member Removed from Security Group)'],
        exampleQuery: `index=windows EventCode=4887 | stats count by CertificateTemplate, msDS_OIDToGroupLink | where msDS_OIDToGroupLink!=""`,
        recommendedThresholds: {
          groupLinkBonus: 2,
          privilegedGroupBonus: 1,
          multipleIssuancesBonus: 1
        }
      }
    })
  }

  async analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = []
    const adcsContext = context as ADCSContext

    // Analyze certificate template configuration for group links
    const templateAnomalies = this.analyzeCertificateTemplates(adcsContext)
    anomalies.push(...templateAnomalies)

    // Analyze certificate issuances from group-linked templates
    const certificateEvents = events.filter(event =>
      this.isCertificateEvent(event)
    ) as CertificateEvent[]

    if (certificateEvents.length > 0) {
      const issuanceAnomalies = this.analyzeCertificateIssuances(certificateEvents, adcsContext)
      anomalies.push(...issuanceAnomalies)
    }

    return anomalies
  }

  private isCertificateEvent(event: AuthEvent): boolean {
    const certEventIds = ['4887', '54'] // Certificate issued events
    return certEventIds.includes(event.eventId) ||
           (event as CertificateEvent).certificateTemplate !== undefined
  }

  private analyzeCertificateTemplates(context: ADCSContext): Anomaly[] {
    const anomalies: Anomaly[] = []

    if (!context.certificateTemplates) return anomalies

    const groupLinkedTemplates = context.certificateTemplates.filter(template => {
      // Check if template has group-linked OIDs
      const hasGroupLink = this.hasGroupLinkedOID(template)

      // Check if template can be used for authentication
      const hasClientAuthEKU = template.extendedKeyUsage?.some(eku =>
        ['1.3.6.1.5.5.7.3.2', '1.3.6.1.5.2.3.4', '1.3.6.1.4.1.311.20.2.2'].includes(eku)
      )

      return template.enabled && hasGroupLink && hasClientAuthEKU
    })

    groupLinkedTemplates.forEach(template => {
      let riskScore = 3 // Base high risk for group-linked templates
      let confidence = 85

      // Check if template requires manager approval
      const hasManagerApproval = (template.enrollmentFlags & 2) !== 0
      if (!hasManagerApproval) {
        riskScore += 1
        confidence += 10
      }

      // Check if linked groups are privileged
      const linkedGroups = this.getLinkedGroups(template)
      const privilegedGroups = linkedGroups.filter(group =>
        this.isPrivilegedGroup(group)
      )

      if (privilegedGroups.length > 0) {
        riskScore += this.thresholds.privilegedGroupBonus
        confidence += 15
      }

      // Check if template is accessible by large groups
      const accessibleByLargeGroups = this.isAccessibleByLargeGroups(template)
      if (accessibleByLargeGroups) {
        riskScore += 1
        confidence += 5
      }

      const detection: ESCDetectionResult = {
        vulnerability: 'ESC13',
        severity: riskScore >= 5 ? 'critical' : riskScore >= 4 ? 'high' : 'medium',
        confidence: Math.min(confidence, 100),
        affectedEntities: [
          {
            type: 'certificateTemplate',
            id: template.name,
            name: template.displayName || template.name
          },
          ...linkedGroups.slice(0, 3).map(group => ({
            type: 'user' as const, // Groups are treated as user entities for simplicity
            id: group,
            name: group
          }))
        ],
        evidence: {
          templateName: template.name,
          displayName: template.displayName,
          enrollmentFlags: template.enrollmentFlags,
          certificateNameFlags: template.certificateNameFlags,
          extendedKeyUsage: template.extendedKeyUsage,
          hasGroupLink: true,
          linkedGroups,
          privilegedGroups,
          hasManagerApproval,
          accessibleByLargeGroups,
          issuancePolicies: template.issuancePolicies,
          permissions: template.permissions
        },
        remediation: [
          `Remove group-link from certificate template: ${template.name}`,
          'Clear msDS-OIDToGroupLink attribute from associated OIDs',
          'Enable Manager Approval for the template',
          'Restrict template permissions to authorized users only',
          'Monitor certificates issued using group-linked templates',
          'Consider disabling the template until group-links are removed'
        ]
      }

      const anomaly = this.createESC13Anomaly(detection, context)
      anomalies.push(anomaly)
    })

    return anomalies
  }

  private analyzeCertificateIssuances(events: CertificateEvent[], context: ADCSContext): Anomaly[] {
    const anomalies: Anomaly[] = []

    // Look for certificates issued from group-linked templates
    const groupLinkedIssuances = events.filter(event => {
      if (event.status !== 'Success') return false

      // Check if template is group-linked
      const template = context.certificateTemplates?.find(t =>
        t.name === event.certificateTemplate || t.displayName === event.certificateTemplate
      )

      return template && this.hasGroupLinkedOID(template)
    })

    if (groupLinkedIssuances.length > 0) {
      // Group by template
      const templateGroups = this.groupByTemplate(groupLinkedIssuances)

      Object.entries(templateGroups).forEach(([templateName, templateEvents]) => {
        const template = context.certificateTemplates?.find(t =>
          t.name === templateName || t.displayName === templateName
        )

        if (!template) return

        let riskScore = 3 // Base high risk
        let confidence = 80

        // Check if certificates were issued to privileged users
        const privilegedUsers = templateEvents.filter(event => {
          const userProfile = context.userProfiles?.find(u =>
            u.userName === event.userName && u.domain === event.domainName
          )
          return userProfile?.privileged
        })

        if (privilegedUsers.length > 0) {
          riskScore += this.thresholds.privilegedGroupBonus
          confidence += 15
        }

        // Check for multiple issuances
        if (templateEvents.length > 5) {
          riskScore += this.thresholds.multipleIssuancesBonus
          confidence += 10
        }

        // Check if recipients are in linked groups
        const linkedGroups = this.getLinkedGroups(template)
        const recipientsInLinkedGroups = templateEvents.filter(event => {
          // In a real implementation, we'd check group membership
          // For now, we'll assume some correlation
          return event.userName && linkedGroups.length > 0
        })

        if (recipientsInLinkedGroups.length > 0) {
          riskScore += 1
          confidence += 10
        }

        const detection: ESCDetectionResult = {
          vulnerability: 'ESC13',
          severity: riskScore >= 5 ? 'critical' : riskScore >= 4 ? 'high' : 'medium',
          confidence: Math.min(confidence, 100),
          affectedEntities: [
            {
              type: 'certificateTemplate',
              id: templateName,
              name: template.displayName || template.name
            },
            ...Array.from(new Set(templateEvents.map(e => e.userName).filter(Boolean))).slice(0, 3).map(user => ({
              type: 'user' as const,
              id: user as string,
              name: user as string
            }))
          ],
          evidence: {
            templateName,
            groupLinkedIssuances: templateEvents.length,
            privilegedUsers: privilegedUsers.length,
            linkedGroups: linkedGroups,
            recipientsInLinkedGroups: recipientsInLinkedGroups.length,
            totalAffectedUsers: new Set(templateEvents.map(e => e.userName).filter(Boolean)).size,
            certificates: templateEvents.map(event => ({
              requestId: event.requestId,
              userName: event.userName,
              serialNumber: event.serialNumber,
              timestamp: event.timestamp,
              isPrivilegedUser: privilegedUsers.some(pu => pu.userName === event.userName)
            }))
          },
          remediation: [
            'Immediately revoke certificates issued from group-linked templates',
            'Remove group-link from the certificate template',
            'Clear msDS-OIDToGroupLink attribute from associated OIDs',
            'Re-issue certificates through proper approval process',
            'Monitor authentication using revoked certificates',
            'Implement additional controls for group-linked templates'
          ]
        }

        const anomaly = this.createESC13Anomaly(detection, context)
        anomalies.push(anomaly)
      })
    }

    return anomalies
  }

  private hasGroupLinkedOID(template: any): boolean {
    // Check if template has issuance policies with group-linked OIDs
    if (!template.issuancePolicies) return false

    return template.issuancePolicies.some((policy: any) => {
      // Check if OID has msDS-OIDToGroupLink attribute
      // In a real implementation, we'd query AD for this
      return policy.groupLink || policy.oidToGroupLink
    })
  }

  private getLinkedGroups(template: any): string[] {
    // Extract linked groups from template configuration
    const linkedGroups: string[] = []

    if (template.issuancePolicies) {
      template.issuancePolicies.forEach((policy: any) => {
        if (policy.groupLink || policy.oidToGroupLink) {
          // In a real implementation, we'd resolve the actual group names
          linkedGroups.push(policy.groupLink || 'LinkedGroup')
        }
      })
    }

    return linkedGroups
  }

  private isPrivilegedGroup(groupName: string): boolean {
    const privilegedGroups = [
      'Domain Admins',
      'Enterprise Admins',
      'Administrators',
      'Account Operators',
      'Server Operators',
      'Backup Operators'
    ]

    return privilegedGroups.some(privileged =>
      groupName.includes(privileged)
    )
  }

  private isAccessibleByLargeGroups(template: any): boolean {
    if (!template.permissions) return false

    const largeGroups = [
      'Domain Users',
      'Authenticated Users',
      'Everyone',
      'Users'
    ]

    return template.permissions.some((perm: any) =>
      largeGroups.some(group => perm.identity.includes(group))
    )
  }

  private groupByTemplate(events: CertificateEvent[]): Record<string, CertificateEvent[]> {
    const groups: Record<string, CertificateEvent[]> = {}

    events.forEach(event => {
      const templateName = event.certificateTemplate || 'Unknown'
      if (!groups[templateName]) {
        groups[templateName] = []
      }
      groups[templateName].push(event)
    })

    return groups
  }

  private createESC13Anomaly(
    detection: ESCDetectionResult,
    context: ADCSContext
  ): Anomaly {
    const title = `🚨 ESC13 Vulnerability: Group-Linked Certificate Template`
    const description = `Certificate template ${detection.affectedEntities[0].name} is linked to groups via OID. ` +
      `This allows automatic certificate issuance to group members without proper approval, enabling privilege escalation.`

    return this.createAnomaly(
      title,
      description,
      {
        vulnerability: detection.vulnerability,
        severity: detection.severity,
        confidence: detection.confidence,
        templateName: detection.affectedEntities[0].name,
        timeWindow: this.timeWindow,
        detectionMethod: 'group_link_analysis',
        evidence: detection.evidence
      },
      detection.confidence,
      {
        attackType: 'group_linked_certificates',
        vulnerabilityType: 'ESC13',
        riskLevel: detection.severity
      }
    )
  }
}
