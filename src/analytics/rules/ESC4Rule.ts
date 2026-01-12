import { BaseRule } from '../BaseRule'
import { AuthEvent, Anomaly, AnalyticsContext, CertificateEvent, ADCSContext, ESCDetectionResult } from '../types'

export class ESC4Rule extends BaseRule {
  // Dangerous permissions that can lead to ESC4 exploitation
  private readonly dangerousRights = [
    'GenericAll',
    'WriteDacl',
    'WriteOwner',
    'WriteProperty',
    'GenericWrite',
    'Delete',
    'DeleteTree'
  ]

  // Event IDs related to permission changes
  private readonly permissionEventIds = [
    '4898', // Certificate template permissions changed
    '4899', // Certificate template updated
    '4900', // Certificate Services template loaded
    '5136', // Directory Service object modified
    '5137', // Directory Service object created
    '5141'  // Directory Service object deleted
  ]

  // Privileged groups that should normally have access
  private readonly privilegedGroups = [
    'Domain Admins',
    'Enterprise Admins',
    'Administrators',
    'Certificate Publishers',
    'Cert Publishers'
  ]

  constructor() {
    super({
      id: 'esc4_access_control_detection',
      name: 'ESC4 - Vulnerable Access Control Detection',
      description: 'Detects dangerous permissions on certificate templates and PKI objects that can be exploited',
      category: 'security',
      severity: 'critical',
      timeWindow: 120, // 2 hours for permission change analysis
      thresholds: {
        minPermissionChanges: 1,
        dangerousRightsBonus: 2,
        unprivilegedUserBonus: 3,
        largeGroupAccessBonus: 1
      },
      version: '1.0.0',
      author: 'ADTrapper Security Team',
      detailedDescription: {
        overview: 'Detects ESC4 vulnerabilities where certificate templates and PKI objects have overly permissive access controls. Dangerous permissions like GenericAll, WriteDACL, or WriteOwner on certificate templates allow attackers to modify template configurations and escalate privileges through certificate-based attacks.',
        detectionLogic: 'Analyzes access control lists (ACLs) on certificate templates and PKI objects for dangerous permission combinations. Monitors permission changes and identifies when unprivileged users or large groups gain dangerous rights on critical AD CS infrastructure components.',
        falsePositives: 'Legitimate administrative permissions assigned to authorized personnel, properly configured certificate template permissions for certificate publishers, or permission changes that follow organizational change management processes. May also trigger during legitimate PKI infrastructure maintenance or template updates.',
        mitigation: [
          'Review and restrict certificate template permissions',
          'Remove GenericAll, WriteDACL, and WriteOwner rights from non-administrative users',
          'Limit certificate template access to authorized certificate publishers only',
          'Implement least privilege principles for PKI object permissions',
          'Use Locksmith to identify and remediate ESC4 vulnerabilities',
          'Monitor certificate template permission changes',
          'Implement certificate template permission approval workflows',
          'Regular AD CS access control audits and assessments',
          'Configure restricted certificate template inheritance',
          'Enable AD CS auditing for permission changes'
        ],
        windowsEvents: ['4898 (Certificate Template Permissions Changed)', '4899 (Certificate Template Updated)', '4900 (Certificate Services Template Loaded)', '5136 (Directory Service Object Modified)', '5137 (Directory Service Object Created)', '5141 (Directory Service Object Deleted)', '4909 (Certificate Services Template Settings Changed)', '4910 (Certificate Services Template Updated)'],
        exampleQuery: `index=windows EventCode=4898 OR EventCode=4899 | stats count by TargetUserName, ObjectDN | where count > 3`,
        recommendedThresholds: {
          minPermissionChanges: 1,
          dangerousRightsBonus: 2,
          unprivilegedUserBonus: 3,
          largeGroupAccessBonus: 1
        }
      }
    })
  }

  async analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = []
    const adcsContext = context as ADCSContext

    // Filter permission-related events
    const permissionEvents = events.filter(event =>
      this.isPermissionEvent(event)
    )

    if (permissionEvents.length === 0) return anomalies

    // Analyze template permission changes
    const templatePermissionAnomalies = this.analyzeTemplatePermissions(permissionEvents, adcsContext)
    anomalies.push(...templatePermissionAnomalies)

    // Analyze PKI object permission changes
    const pkiObjectPermissionAnomalies = this.analyzePKIObjectPermissions(permissionEvents, adcsContext)
    anomalies.push(...pkiObjectPermissionAnomalies)

    // Analyze current template permissions if available
    const currentPermissionAnomalies = this.analyzeCurrentPermissions(adcsContext)
    anomalies.push(...currentPermissionAnomalies)

    return anomalies
  }

  private isPermissionEvent(event: AuthEvent): boolean {
    return this.permissionEventIds.includes(event.eventId) ||
           event.rawData?.operationType === 'permission_change' ||
           event.rawData?.operationType === 'acl_modification'
  }

  private analyzeTemplatePermissions(
    events: AuthEvent[],
    context: ADCSContext
  ): Anomaly[] {
    const anomalies: Anomaly[] = []

    // Look for certificate template permission changes
    const templatePermissionChanges = events.filter(event =>
      event.eventId === '4898' || event.eventId === '4899' ||
      event.rawData?.objectType === 'certificateTemplate'
    )

    if (templatePermissionChanges.length === 0) return anomalies

    // Group by template
    const templateGroups = this.groupByObject(templatePermissionChanges)

    Object.entries(templateGroups).forEach(([templateName, templateEvents]) => {
      const dangerousPermissions = this.identifyDangerousPermissions(templateEvents)

      if (dangerousPermissions.length > 0) {
        const riskAssessment = this.assessPermissionRisk(dangerousPermissions, context)

        if (riskAssessment.riskScore >= 3) { // Medium risk or higher
          const detection: ESCDetectionResult = {
            vulnerability: 'ESC4',
            severity: riskAssessment.riskScore >= 5 ? 'critical' : riskAssessment.riskScore >= 4 ? 'high' : 'medium',
            confidence: riskAssessment.confidence,
            affectedEntities: [
              {
                type: 'certificateTemplate',
                id: templateName,
                name: templateName
              },
              ...dangerousPermissions.slice(0, 3).map(perm => ({
                type: 'user' as const,
                id: perm.principal,
                name: perm.principal
              }))
            ],
            evidence: {
              templateName,
              dangerousPermissions,
              totalPermissionChanges: templateEvents.length,
              riskAssessment,
              permissionChanges: templateEvents.map(event => ({
                timestamp: event.timestamp,
                userName: event.userName,
                operation: event.rawData?.operation || 'permission_change',
                details: event.rawData?.details
              }))
            },
            remediation: this.getPermissionRemediation(dangerousPermissions, templateName)
          }

          const anomaly = this.createESC4Anomaly(detection, templateEvents, context)
          anomalies.push(anomaly)
        }
      }
    })

    return anomalies
  }

  private analyzePKIObjectPermissions(
    events: AuthEvent[],
    context: ADCSContext
  ): Anomaly[] {
    const anomalies: Anomaly[] = []

    // Look for PKI object permission changes (CA objects, containers, etc.)
    const pkiObjectChanges = events.filter(event =>
      event.rawData?.objectType === 'pkiObject' ||
      event.rawData?.objectType === 'certificateAuthority' ||
      event.rawData?.objectCategory?.includes('PKI') ||
      event.rawData?.objectCategory?.includes('Public Key Services')
    )

    if (pkiObjectChanges.length === 0) return anomalies

    // Group by object
    const objectGroups = this.groupByObject(pkiObjectChanges)

    Object.entries(objectGroups).forEach(([objectName, objectEvents]) => {
      const dangerousPermissions = this.identifyDangerousPermissions(objectEvents)

      if (dangerousPermissions.length > 0) {
        const riskAssessment = this.assessPKIObjectRisk(dangerousPermissions, objectName, context)

        if (riskAssessment.riskScore >= 4) { // High risk or higher for PKI objects
          const detection: ESCDetectionResult = {
            vulnerability: 'ESC4',
            severity: 'critical',
            confidence: riskAssessment.confidence,
            affectedEntities: [
              {
                type: 'certificateAuthority',
                id: objectName,
                name: objectName
              },
              ...dangerousPermissions.slice(0, 3).map(perm => ({
                type: 'user' as const,
                id: perm.principal,
                name: perm.principal
              }))
            ],
            evidence: {
              objectName,
              objectType: 'pki_object',
              dangerousPermissions,
              totalPermissionChanges: objectEvents.length,
              riskAssessment,
              permissionChanges: objectEvents.map(event => ({
                timestamp: event.timestamp,
                userName: event.userName,
                operation: event.rawData?.operation || 'permission_change'
              }))
            },
            remediation: this.getPKIObjectRemediation(dangerousPermissions, objectName)
          }

          const anomaly = this.createESC4Anomaly(detection, objectEvents, context)
          anomalies.push(anomaly)
        }
      }
    })

    return anomalies
  }

  private analyzeCurrentPermissions(context: ADCSContext): Anomaly[] {
    const anomalies: Anomaly[] = []

    if (!context.certificateTemplates) return anomalies

    context.certificateTemplates.forEach(template => {
      if (!template.permissions) return

      const dangerousPermissions = template.permissions.filter(perm =>
        perm.rights.some(right => this.dangerousRights.includes(right))
      )

      if (dangerousPermissions.length > 0) {
        const riskAssessment = this.assessCurrentPermissionRisk(dangerousPermissions, template, context)

        if (riskAssessment.riskScore >= 3) {
          const detection: ESCDetectionResult = {
            vulnerability: 'ESC4',
            severity: riskAssessment.riskScore >= 5 ? 'critical' : riskAssessment.riskScore >= 4 ? 'high' : 'medium',
            confidence: riskAssessment.confidence,
            affectedEntities: [
              {
                type: 'certificateTemplate',
                id: template.name,
                name: template.displayName || template.name
              },
              ...dangerousPermissions.slice(0, 3).map(perm => ({
                type: 'user' as const,
                id: perm.identity,
                name: perm.identity
              }))
            ],
            evidence: {
              templateName: template.name,
              dangerousPermissions: dangerousPermissions.map(perm => ({
                principal: perm.identity,
                rights: perm.rights,
                inheritance: perm.inheritance
              })),
              riskAssessment,
              currentPermissions: template.permissions
            },
            remediation: this.getCurrentPermissionRemediation(dangerousPermissions, template.name)
          }

          const anomaly = this.createESC4Anomaly(detection, [], context)
          anomalies.push(anomaly)
        }
      }
    })

    return anomalies
  }

  private groupByObject(events: AuthEvent[]): Record<string, AuthEvent[]> {
    const groups: Record<string, AuthEvent[]> = {}

    events.forEach(event => {
      const objectName = event.rawData?.objectName ||
                        event.rawData?.targetObject ||
                        event.computerName ||
                        'Unknown'
      if (!groups[objectName]) {
        groups[objectName] = []
      }
      groups[objectName].push(event)
    })

    return groups
  }

  private identifyDangerousPermissions(events: AuthEvent[]): Array<{
    principal: string
    rights: string[]
    timestamp: Date
    eventId: string
  }> {
    const dangerousPermissions: Array<{
      principal: string
      rights: string[]
      timestamp: Date
      eventId: string
    }> = []

    events.forEach(event => {
      const permissions = event.rawData?.permissions ||
                         event.rawData?.aclChanges ||
                         event.rawData?.rights

      if (permissions) {
        const permsArray = Array.isArray(permissions) ? permissions : [permissions]

        permsArray.forEach((perm: any) => {
          const principal = perm.principal || perm.identity || perm.user || event.userName
          const rights = Array.isArray(perm.rights) ? perm.rights : [perm.rights || perm.right]

          const hasDangerousRights = rights.some((right: string) =>
            this.dangerousRights.some(dangerous => right.includes(dangerous))
          )

          if (hasDangerousRights && principal) {
            dangerousPermissions.push({
              principal,
              rights,
              timestamp: event.timestamp,
              eventId: event.eventId
            })
          }
        })
      }
    })

    return dangerousPermissions
  }

  private assessPermissionRisk(
    dangerousPermissions: Array<{
      principal: string
      rights: string[]
      timestamp: Date
      eventId: string
    }>,
    context: ADCSContext
  ): { riskScore: number; confidence: number; factors: string[] } {
    let riskScore = 2 // Base low risk
    let confidence = 70
    const factors: string[] = []

    dangerousPermissions.forEach(perm => {
      // Check if principal has dangerous rights
      if (perm.rights.some(right => right.includes('GenericAll'))) {
        riskScore += this.thresholds.dangerousRightsBonus
        factors.push('GenericAll rights granted')
      }

      if (perm.rights.some(right => right.includes('WriteDacl'))) {
        riskScore += this.thresholds.dangerousRightsBonus
        factors.push('WriteDacl rights granted')
      }

      // Check if principal is unprivileged
      if (!this.isPrivilegedPrincipal(perm.principal, context)) {
        riskScore += this.thresholds.unprivilegedUserBonus
        factors.push('Unprivileged principal granted dangerous rights')
      }

      // Check if rights affect large groups
      if (this.affectsLargeGroups(perm.principal)) {
        riskScore += this.thresholds.largeGroupAccessBonus
        factors.push('Rights affect large user groups')
      }
    })

    return {
      riskScore: Math.min(riskScore, 5),
      confidence: Math.min(confidence + (dangerousPermissions.length * 5), 100),
      factors
    }
  }

  private assessPKIObjectRisk(
    dangerousPermissions: Array<{
      principal: string
      rights: string[]
      timestamp: Date
      eventId: string
    }>,
    objectName: string,
    context: ADCSContext
  ): { riskScore: number; confidence: number; factors: string[] } {
    let riskScore = 3 // Base medium risk for PKI objects
    let confidence = 75
    const factors: string[] = []

    // Higher risk for critical PKI objects
    if (objectName.includes('NTAuthCertificates') || objectName.includes('Root CA')) {
      riskScore += 2
      factors.push('Critical PKI object affected')
    }

    dangerousPermissions.forEach(perm => {
      if (perm.rights.some(right => right.includes('GenericAll'))) {
        riskScore += this.thresholds.dangerousRightsBonus
        factors.push('GenericAll rights on PKI object')
      }

      if (!this.isPrivilegedPrincipal(perm.principal, context)) {
        riskScore += this.thresholds.unprivilegedUserBonus
        factors.push('Unprivileged user has dangerous PKI object rights')
      }
    })

    return {
      riskScore: Math.min(riskScore, 5),
      confidence: Math.min(confidence + (dangerousPermissions.length * 5), 100),
      factors
    }
  }

  private assessCurrentPermissionRisk(
    dangerousPermissions: Array<{
      identity: string
      rights: string[]
      inheritance: boolean
    }>,
    template: any,
    context: ADCSContext
  ): { riskScore: number; confidence: number; factors: string[] } {
    let riskScore = 2
    let confidence = 80
    const factors: string[] = []

    dangerousPermissions.forEach(perm => {
      if (perm.rights.includes('GenericAll')) {
        riskScore += this.thresholds.dangerousRightsBonus
        factors.push('GenericAll rights assigned')
      }

      if (!this.isPrivilegedPrincipal(perm.identity, context)) {
        riskScore += this.thresholds.unprivilegedUserBonus
        factors.push('Unprivileged user has dangerous template rights')
      }

      if (this.affectsLargeGroups(perm.identity)) {
        riskScore += this.thresholds.largeGroupAccessBonus
        factors.push('Rights affect large groups')
      }
    })

    return {
      riskScore: Math.min(riskScore, 5),
      confidence,
      factors
    }
  }

  private isPrivilegedPrincipal(principal: string, context: ADCSContext): boolean {
    // Check if principal is in privileged groups
    if (this.privilegedGroups.some(group =>
      principal.includes(group) || principal.includes('Admin')
    )) {
      return true
    }

    // Check user profiles
    const userProfile = context.userProfiles?.find(u =>
      u.userName === principal || u.groups?.includes(principal)
    )

    return userProfile?.privileged || false
  }

  private affectsLargeGroups(principal: string): boolean {
    const largeGroups = [
      'Domain Users',
      'Authenticated Users',
      'Everyone',
      'Users'
    ]

    return largeGroups.some(group => principal.includes(group))
  }

  private getPermissionRemediation(
    dangerousPermissions: Array<{
      principal: string
      rights: string[]
      timestamp: Date
      eventId: string
    }>,
    templateName: string
  ): string[] {
    const remediation: string[] = [
      `Remove dangerous permissions from certificate template: ${templateName}`,
      'Restrict template access to privileged users only',
      'Enable Manager Approval if not already enabled'
    ]

    dangerousPermissions.forEach(perm => {
      remediation.push(`Revoke ${perm.rights.join(', ')} rights from ${perm.principal}`)
    })

    remediation.push('Audit all certificates issued using this template')
    remediation.push('Consider disabling the template until permissions are corrected')

    return remediation
  }

  private getPKIObjectRemediation(
    dangerousPermissions: Array<{
      principal: string
      rights: string[]
      timestamp: Date
      eventId: string
    }>,
    objectName: string
  ): string[] {
    return [
      `Remove dangerous permissions from PKI object: ${objectName}`,
      'Change object ownership to Domain Admins or Enterprise Admins',
      'Restrict access to certified PKI administrators only',
      'Enable comprehensive auditing on PKI objects',
      'Review all changes made to this PKI object',
      'Consider implementing PKI object protection policies'
    ]
  }

  private getCurrentPermissionRemediation(
    dangerousPermissions: Array<{
      identity: string
      rights: string[]
      inheritance: boolean
    }>,
    templateName: string
  ): string[] {
    return [
      `Remove dangerous permissions from certificate template: ${templateName}`,
      'Restrict template permissions to authorized personnel only',
      'Enable Manager Approval for the template',
      'Implement regular permission audits',
      'Consider template migration to secure configuration'
    ]
  }

  private createESC4Anomaly(
    detection: ESCDetectionResult,
    events: AuthEvent[],
    context: ADCSContext
  ): Anomaly {
    const title = `🚨 ESC4 Vulnerability: ${detection.affectedEntities[0].name}`
    const description = `Dangerous permissions detected on ${detection.affectedEntities[0].type} ${detection.affectedEntities[0].name}. ` +
      `These permissions can be exploited to modify certificate templates and escalate privileges.`

    return this.createAnomaly(
      title,
      description,
      {
        vulnerability: detection.vulnerability,
        severity: detection.severity,
        confidence: detection.confidence,
        objectName: detection.affectedEntities[0].name,
        dangerousPermissions: detection.evidence.dangerousPermissions,
        totalChanges: events.length,
        timeWindow: this.timeWindow,
        detectionMethod: 'permission_analysis',
        evidence: detection.evidence
      },
      detection.confidence,
      {
        attackType: 'permission_exploit',
        vulnerabilityType: 'ESC4',
        riskLevel: detection.severity
      }
    )
  }
}
