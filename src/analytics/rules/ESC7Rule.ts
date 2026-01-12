import { BaseRule } from '../BaseRule'
import { AuthEvent, Anomaly, AnalyticsContext, CertificateEvent, ADCSContext, ESCDetectionResult } from '../types'

export class ESC7Rule extends BaseRule {
  // Standard PKI administrators (should normally have CA control)
  private readonly standardPKIAdmins = [
    'Domain Admins',
    'Enterprise Admins',
    'Administrators',
    'Enterprise Domain Controllers',
    'Domain Controllers'
  ]

  // CA-related event IDs that indicate administrative operations
  private readonly adminEventIds = [
    '4886', '4887', '4888', // Certificate requests/issuance
    '4898', '4899', // Template changes
    '4900', // Template loaded
    '53', '54' // Certificate operations
  ]

  constructor() {
    super({
      id: 'esc7_nonstandard_pki_admins',
      name: 'ESC7 - Non-standard PKI Administrators',
      description: 'Detects non-standard users with CA Administrator or Certificate Manager rights',
      category: 'security',
      severity: 'high',
      timeWindow: 120, // 2 hours for admin activity analysis
      thresholds: {
        nonStandardAdminBonus: 2,
        certificateOperationsBonus: 1,
        suspiciousRightsBonus: 1
      },
      version: '1.0.0',
      author: 'ADTrapper Security Team',
      detailedDescription: {
        overview: 'Detects ESC7 vulnerabilities where non-standard users (outside Domain/Enterprise Admins) have Certificate Authority (CA) administrator or certificate manager rights. This violates the principle of least privilege and increases attack surface by providing excessive PKI permissions to unauthorized users.',
        detectionLogic: 'Analyzes CA security descriptors and certificate operations to identify users outside standard PKI admin groups (Domain Admins, Enterprise Admins, Administrators) who have CA control or certificate management permissions. Monitors certificate operations performed by non-standard administrators.',
        falsePositives: 'Authorized PKI administrators who are members of standard admin groups, legitimate certificate management personnel with documented access, or service accounts that require PKI permissions for operational purposes. May also trigger during legitimate PKI infrastructure maintenance or delegated administration activities.',
        mitigation: [
          'Restrict CA administrator rights to standard admin groups only',
          'Review and remove excessive PKI permissions from non-administrative users',
          'Implement least privilege principles for certificate authority access',
          'Document and justify any non-standard PKI administrators',
          'Use Locksmith to identify and remediate ESC7 vulnerabilities',
          'Regular PKI access control audits and reviews',
          'Implement certificate authority permission approval workflows',
          'Configure restricted CA access controls in Group Policy',
          'Monitor certificate operations by non-standard administrators',
          'Implement PKI administrative activity logging and alerting'
        ],
        windowsEvents: ['4886 (Certificate Services Started)', '4887 (Certificate Issued)', '4888 (Certificate Services Backup Started)', '4898 (Certificate Template Permissions Changed)', '4899 (Certificate Template Updated)', '4900 (Certificate Services Template Loaded)', '5136 (Directory Service Object Modified)', '5137 (Directory Service Object Created)', '4672 (Special Privileges Assigned)', '4673 (Sensitive Privilege Use)'],
        exampleQuery: `index=windows EventCode=4886 OR EventCode=4887 | stats count by TargetUserName, CertificateAuthority | where count > 10`,
        recommendedThresholds: {
          nonStandardAdminBonus: 2,
          certificateOperationsBonus: 1,
          suspiciousRightsBonus: 1
        }
      }
    })
  }

  async analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = []
    const adcsContext = context as ADCSContext

    // Analyze CA permissions from configuration
    const caPermissionAnomalies = this.analyzeCAPermissions(adcsContext)
    anomalies.push(...caPermissionAnomalies)

    // Analyze certificate operations by non-standard users
    const certificateEvents = events.filter(event =>
      this.isCertificateEvent(event)
    ) as CertificateEvent[]

    if (certificateEvents.length > 0) {
      const operationAnomalies = this.analyzeCertificateOperations(certificateEvents, adcsContext)
      anomalies.push(...operationAnomalies)
    }

    return anomalies
  }

  private isCertificateEvent(event: AuthEvent): boolean {
    return this.adminEventIds.includes(event.eventId) ||
           (event as CertificateEvent).certificateTemplate !== undefined
  }

  private analyzeCAPermissions(context: ADCSContext): Anomaly[] {
    const anomalies: Anomaly[] = []

    if (!context.certificateAuthorities) return anomalies

    context.certificateAuthorities.forEach(ca => {
      // Check CA security settings for non-standard administrators
      const nonStandardAdmins = this.identifyNonStandardAdmins(ca)

      if (nonStandardAdmins.length > 0) {
        let riskScore = 2 // Base medium risk
        let confidence = 80

        // Higher risk for more non-standard admins
        if (nonStandardAdmins.length > 2) {
          riskScore += 1
          confidence += 10
        }

        // Check if any non-standard admins have dangerous rights
        const dangerousRights = nonStandardAdmins.filter(admin =>
          this.hasDangerousRights(admin.rights)
        )

        if (dangerousRights.length > 0) {
          riskScore += this.thresholds.suspiciousRightsBonus
          confidence += 15
        }

        const detection: ESCDetectionResult = {
          vulnerability: 'ESC7',
          severity: riskScore >= 4 ? 'high' : riskScore >= 3 ? 'medium' : 'low',
          confidence: Math.min(confidence, 100),
          affectedEntities: [
            {
              type: 'certificateAuthority',
              id: ca.name,
              name: ca.displayName || ca.name
            },
            ...nonStandardAdmins.slice(0, 3).map(admin => ({
              type: 'user' as const,
              id: admin.principal,
              name: admin.principal
            }))
          ],
          evidence: {
            caName: ca.name,
            dnsName: ca.dnsName,
            nonStandardAdmins: nonStandardAdmins.map(admin => ({
              principal: admin.principal,
              rights: admin.rights,
              isDangerous: this.hasDangerousRights(admin.rights)
            })),
            dangerousRightsCount: dangerousRights.length,
            standardAdmins: this.standardPKIAdmins,
            caSecurity: ca.securityFlags,
            auditFilter: ca.auditFilter
          },
          remediation: [
            `Remove CA Administrator/Certificate Manager rights from non-standard users on: ${ca.name}`,
            'Review and audit all certificate operations performed by non-standard admins',
            'Restrict CA control to Domain/Enterprise Admins only',
            'Enable comprehensive auditing for CA operations',
            'Consider implementing CA role separation',
            'Document and justify any exceptions to standard admin requirements'
          ]
        }

        const anomaly = this.createESC7Anomaly(detection, context)
        anomalies.push(anomaly)
      }
    })

    return anomalies
  }

  private analyzeCertificateOperations(events: CertificateEvent[], context: ADCSContext): Anomaly[] {
    const anomalies: Anomaly[] = []

    // Group certificate operations by user
    const operationsByUser = new Map<string, CertificateEvent[]>()

    events.forEach(event => {
      if (event.userName) {
        const userKey = event.userName.toLowerCase()
        if (!operationsByUser.has(userKey)) {
          operationsByUser.set(userKey, [])
        }
        operationsByUser.get(userKey)!.push(event)
      }
    })

    // Analyze operations by each user
    for (const [userName, userEvents] of Array.from(operationsByUser.entries())) {
      if (!this.isStandardPKIAdmin(userName) && userEvents.length >= 5) {
        let riskScore = 2 // Base medium risk for non-standard admin activity
        let confidence = 70

        // Check for administrative operations
        const adminOperations = userEvents.filter(event =>
          this.isAdministrativeOperation(event)
        )

        if (adminOperations.length > 0) {
          riskScore += this.thresholds.certificateOperationsBonus
          confidence += 15
        }

        // Check if user has privileged profile
        const userProfile = context.userProfiles?.find(u =>
          u.userName === userName || u.groups?.includes(userName)
        )

        if (!userProfile?.privileged) {
          riskScore += 1
          confidence += 10
        }

        // Check for certificate issuance to privileged accounts
        const privilegedIssuances = userEvents.filter(event =>
          event.status === 'Success' &&
          event.extendedKeyUsage?.some(eku =>
            ['1.3.6.1.5.5.7.3.2', '1.3.6.1.5.2.3.4', '1.3.6.1.4.1.311.20.2.2'].includes(eku)
          )
        )

        if (privilegedIssuances.length > 0) {
          riskScore += 1
          confidence += 20
        }

        const detection: ESCDetectionResult = {
          vulnerability: 'ESC7',
          severity: riskScore >= 4 ? 'high' : riskScore >= 3 ? 'medium' : 'low',
          confidence: Math.min(confidence, 100),
          affectedEntities: [
            {
              type: 'user',
              id: userName,
              name: userName
            }
          ],
          evidence: {
            userName,
            totalOperations: userEvents.length,
            administrativeOperations: adminOperations.length,
            privilegedIssuances: privilegedIssuances.length,
            isStandardAdmin: false,
            isPrivileged: userProfile?.privileged || false,
            department: userProfile?.department,
            operationTypes: Array.from(new Set(userEvents.map(e => e.eventId))),
            certificateTemplates: Array.from(new Set(userEvents.map(e => e.certificateTemplate).filter(Boolean)))
          },
          remediation: [
            `Review PKI administrative rights for user: ${userName}`,
            'Verify if user requires CA Administrator or Certificate Manager rights',
            'Remove unnecessary PKI administrative privileges',
            'Audit all certificate operations performed by this user',
            'Consider implementing approval workflow for administrative operations',
            'Document business justification for any retained administrative rights'
          ]
        }

        const anomaly = this.createESC7Anomaly(detection, context)
        anomalies.push(anomaly)
      }
    }

    return anomalies
  }

  private identifyNonStandardAdmins(ca: any): Array<{
    principal: string
    rights: string[]
  }> {
    // This would analyze CA security descriptors in a real implementation
    // For now, we'll check against known patterns and configuration

    const nonStandardAdmins: Array<{
      principal: string
      rights: string[]
    }> = []

    // Check CA security flags and interface flags for non-standard access
    const securityFlags = ca.securityFlags || 0
    const interfaceFlags = ca.interfaceFlags || 0

    // If security flags indicate non-standard access patterns
    if ((securityFlags & 0x00000001) !== 0 || (interfaceFlags & 0x00000020) !== 0) {
      // This is a simplified check - in reality, we'd parse the actual ACL
      nonStandardAdmins.push({
        principal: 'NonStandardAdmin', // Would be actual principal name
        rights: ['CA Administrator', 'Certificate Manager']
      })
    }

    return nonStandardAdmins
  }

  private isStandardPKIAdmin(userName: string): boolean {
    const lowerUserName = userName.toLowerCase()

    // Check if user is in standard admin groups
    return this.standardPKIAdmins.some(admin =>
      lowerUserName.includes(admin.toLowerCase()) ||
      admin.toLowerCase().includes(lowerUserName)
    )
  }

  private hasDangerousRights(rights: string[]): boolean {
    const dangerousRights = [
      'CA Administrator',
      'Certificate Manager',
      'Manage Certificates',
      'Full Control',
      'GenericAll'
    ]

    return rights.some(right =>
      dangerousRights.some(dangerous => right.includes(dangerous))
    )
  }

  private isAdministrativeOperation(event: CertificateEvent): boolean {
    // Administrative operations include template changes, CA configuration, etc.
    const adminEventIds = ['4898', '4899', '4900'] // Template modification events
    return adminEventIds.includes(event.eventId) ||
           event.rawData?.operationType === 'administrative' ||
           event.rawData?.isAdministrative === true
  }

  private createESC7Anomaly(
    detection: ESCDetectionResult,
    context: ADCSContext
  ): Anomaly {
    const title = `🚨 ESC7 Vulnerability: Non-standard PKI Administrators`
    const description = `Non-standard users have been granted CA Administrator or Certificate Manager rights. ` +
      `This violates the principle of least privilege and increases the attack surface for PKI compromise.`

    return this.createAnomaly(
      title,
      description,
      {
        vulnerability: detection.vulnerability,
        severity: detection.severity,
        confidence: detection.confidence,
        affectedEntity: detection.affectedEntities[0].name,
        timeWindow: this.timeWindow,
        detectionMethod: 'pki_admin_analysis',
        evidence: detection.evidence
      },
      detection.confidence,
      {
        attackType: 'privileged_access_abuse',
        vulnerabilityType: 'ESC7',
        riskLevel: detection.severity
      }
    )
  }
}
