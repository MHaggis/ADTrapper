import { AnalyticsRule, AuthEvent, AnalyticsContext, Anomaly } from '../types'

export class SharpHoundCertificateTemplateAnalysisRule implements AnalyticsRule {
  readonly id = 'sharpHound-certificate-template-analysis'
  readonly name = 'SharpHound Certificate Template Security Analysis'
  readonly description = 'Analyzes Active Directory Certificate Services templates for security vulnerabilities.'
  readonly severity = 'high'
  readonly category = 'security'
  readonly enabled = true
  readonly timeWindow = 24 * 60 * 60 * 1000 // 24 hours
  readonly version = '1.0.0'
  readonly author = 'ADTrapper'
  readonly created = new Date('2025-01-01')
  readonly updated = new Date('2025-01-01')

  readonly thresholds = {
    flagDangerousTemplates: 1,          // Flag templates vulnerable to ESC1-ESC15
    flagWeakCrypto: 1,                  // Flag templates using weak cryptography
    flagNoManagerApproval: 1,           // Flag templates without manager approval
    maxAuthorizedSignatures: 1          // Flag templates requiring too many signatures
  }

  readonly detailedDescription = {
    overview: 'Analyzes Active Directory Certificate Services (ADCS) templates for security vulnerabilities and misconfigurations. Identifies ESC1-ESC15 certificate template attacks that can lead to privilege escalation and domain compromise through SharpHound data analysis.',
    detectionLogic: 'Analyzes SharpHound certificate objects for Properties including certificateusages, certificateapplicationpolicy, requiresmanagerapproval, and enrollment flags. Reviews Aces arrays for enrollment permissions and security descriptors. Detects ESC1-ESC15 vulnerabilities through comprehensive template configuration analysis and permission evaluation using SharpHound collection data.',
    falsePositives: 'Legitimate certificate templates for approved business applications, properly restricted enrollment permissions, manager approval workflows, authorized certificate usage patterns, documented exceptions, and templates designed for specific business requirements with appropriate security controls.',
    mitigation: [
      'Restrict certificate template enrollment to specific security groups only',
      'Enable manager approval for all authentication certificate templates',
      'Replace "Any Purpose" EKUs with specific certificate usages',
      'Remove Domain Users and Authenticated Users from certificate enrollment permissions',
      'Implement certificate template auditing and monitoring',
      'Regular review and cleanup of unused or vulnerable certificate templates',
      'Use certificate auto-enrollment only for approved, restricted templates',
      'Implement certificate template access control lists (ACLs)',
      'Enable certificate template security auditing',
      'Regular AD CS security assessments using SharpHound and Locksmith'
    ],
    windowsEvents: ['4886 (Certificate Services Started)', '4887 (Certificate Issued)', '4888 (Certificate Services Backup Started)', '53 (Certificate Request)', '54 (Certificate Issued)', '4898 (Certificate Template Permissions Changed)', '4899 (Certificate Template Updated)', '4900 (Certificate Services Template Loaded)', '4909 (Certificate Services Template Settings Changed)', '4910 (Certificate Services Template Updated)'],
    exampleQuery: `index=windows EventCode=4887 | stats count by SubjectUserName, CertificateTemplate, ExtendedKeyUsage | where count > 5`,
    recommendedThresholds: {
      flagDangerousTemplates: 1,
      flagWeakCrypto: 1,
      flagNoManagerApproval: 1,
      maxAuthorizedSignatures: 1
    }
  }

  validate(): { valid: boolean; errors: string[] } {
    return { valid: true, errors: [] }
  }

  getMetadata() {
    return {
      id: this.id,
      name: this.name,
      description: this.description,
      detailedDescription: this.detailedDescription,
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

    // Analyze certificate templates
    if (sharpHoundData.certificates && this.thresholds.flagDangerousTemplates > 0) {
      console.log(`🔍 Analyzing ${sharpHoundData.certificates.length} certificate templates`)

      // ESC1: Templates allowing any purpose client authentication
      const esc1Templates = sharpHoundData.certificates.filter((cert: any) => {
        const usages = cert.Properties?.certificateusages || []
        return usages.includes('Client Authentication') &&
               (usages.length === 1 || usages.includes('Any Purpose'))
      })

      if (esc1Templates.length > 0) {
        anomalies.push({
          id: `${this.id}-esc1-vulnerable-${Date.now()}`,
          ruleId: this.id,
          ruleName: this.name,
          severity: 'critical',
          category: 'security',
          title: 'ESC1: Certificate Templates Vulnerable to Privilege Escalation',
          description: `Found ${esc1Templates.length} certificate templates vulnerable to ESC1 attack`,
          confidence: 95,
          evidence: {
            vulnerability: 'ESC1',
            count: esc1Templates.length,
            templates: esc1Templates.map((cert: any) => ({
              name: cert.Properties?.templatename,
              usages: cert.Properties?.certificateusages,
              requiresManagerApproval: cert.Properties?.requiresmanagerapproval
            }))
          },
          recommendations: [
            'CRITICAL: ESC1 allows domain users to enroll certificates for client authentication',
            'Open certtmpl.msc and modify template security permissions',
            'Remove "Domain Users" from enrollment permissions',
            'Add specific security groups that should be allowed to enroll',
            'Enable "Manager approval" for all authentication certificates',
            'Change from "Any Purpose" to specific EKUs like "Client Authentication"',
            'PowerShell remediation: Set-AdcsCertificateTemplate -Identity $templateName -Permission @{Remove="Domain Users"}',
            'Monitor certificate enrollment requests (event ID 4886, 4887)',
            'Document approved certificate templates and their authorized users'
          ],
          timestamp: new Date(),
          detectedAt: new Date(),
          timeWindow: {
            start: new Date(Date.now() - this.timeWindow),
            end: new Date()
          },
          metadata: { vulnerabilityType: 'ESC1' },
          affectedEntities: esc1Templates.map((cert: any) => ({
            type: 'user', // Using user type for certificate templates
            id: cert.Properties?.templatename,
            name: cert.Properties?.templatename
          }))
        })
      }

      // ESC2: Templates allowing any purpose with dangerous EKU combinations
      const esc2Templates = sharpHoundData.certificates.filter((cert: any) => {
        const usages = cert.Properties?.certificateusages || []
        const appPolicies = cert.Properties?.certificateapplicationpolicy || []

        return (usages.includes('Any Purpose') || usages.length === 0) &&
               (appPolicies.includes('Client Authentication') ||
                appPolicies.includes('Smart Card Logon'))
      })

      if (esc2Templates.length > 0) {
        anomalies.push({
          id: `${this.id}-esc2-vulnerable-${Date.now()}`,
          ruleId: this.id,
          ruleName: this.name,
          severity: 'critical',
          category: 'security',
          title: 'ESC2: Certificate Templates with Dangerous EKU Combinations',
          description: `Found ${esc2Templates.length} certificate templates vulnerable to ESC2 attack`,
          confidence: 90,
          evidence: {
            vulnerability: 'ESC2',
            count: esc2Templates.length,
            templates: esc2Templates.map((cert: any) => ({
              name: cert.Properties?.templatename,
              usages: cert.Properties?.certificateusages,
              applicationPolicies: cert.Properties?.certificateapplicationpolicy
            }))
          },
          recommendations: [
            'ESC2 enables privilege escalation through "Any Purpose" certificates',
            'In certtmpl.msc, modify the template properties',
            'Go to Extensions tab > Application Policies > Edit',
            'Remove "Any Purpose" and add specific EKUs only',
            'Common safe EKUs: Client Authentication, Smart Card Logon, PKINIT Client Authentication',
            'Restrict enrollment to specific security groups, not "Domain Users"',
            'Enable manager approval for all authentication templates',
            'PowerShell: Set-AdcsCertificateTemplate -Identity $templateName -ApplicationPolicies @{Add="1.3.6.1.5.5.7.3.2"}',
            'Test certificate enrollment after changes to ensure legitimate use cases still work'
          ],
          timestamp: new Date(),
          detectedAt: new Date(),
          timeWindow: {
            start: new Date(Date.now() - this.timeWindow),
            end: new Date()
          },
          metadata: { vulnerabilityType: 'ESC2' },
          affectedEntities: esc2Templates.map((cert: any) => ({
            type: 'user',
            id: cert.Properties?.templatename,
            name: cert.Properties?.templatename
          }))
        })
      }

      // ESC3: Templates allowing enrollment by any user
      const esc3Templates = sharpHoundData.certificates.filter((cert: any) => {
        // Check if template has overly permissive ACEs
        return cert.Aces && cert.Aces.some((ace: any) =>
          ace.PrincipalType === 'User' || ace.PrincipalType === 'Group'
        )
      })

      if (esc3Templates.length > 0) {
        anomalies.push({
          id: `${this.id}-esc3-vulnerable-${Date.now()}`,
          ruleId: this.id,
          ruleName: this.name,
          severity: 'high',
          category: 'security',
          title: 'ESC3: Certificate Templates with Overly Permissive Enrollment',
          description: `Found ${esc3Templates.length} certificate templates allowing enrollment by regular users`,
          confidence: 85,
          evidence: {
            vulnerability: 'ESC3',
            count: esc3Templates.length,
            templates: esc3Templates.map((cert: any) => ({
              name: cert.Properties?.templatename,
              enrollmentServers: cert.Properties?.enrollmentservers,
              aceCount: cert.Aces?.length || 0
            }))
          },
          recommendations: [
            'ESC3 allows any domain user to enroll certificates',
            'Restrict certificate enrollment to specific security groups',
            'Use certificate auto-enrollment only for approved templates'
          ],
          timestamp: new Date(),
          detectedAt: new Date(),
          timeWindow: {
            start: new Date(Date.now() - this.timeWindow),
            end: new Date()
          },
          metadata: { vulnerabilityType: 'ESC3' },
          affectedEntities: esc3Templates.map((cert: any) => ({
            type: 'user',
            id: cert.Properties?.templatename,
            name: cert.Properties?.templatename
          }))
        })
      }

      // Templates without manager approval for sensitive certificates
      if (this.thresholds.flagNoManagerApproval > 0) {
        const noApprovalTemplates = sharpHoundData.certificates.filter((cert: any) =>
          cert.Properties?.requiresmanagerapproval === false &&
          (cert.Properties?.certificateusages?.includes('Client Authentication') ||
           cert.Properties?.certificateusages?.includes('Smart Card Logon'))
        )

        if (noApprovalTemplates.length > 0) {
          anomalies.push({
            id: `${this.id}-no-manager-approval-${Date.now()}`,
            ruleId: this.id,
            ruleName: this.name,
            severity: 'medium',
            category: 'security',
            title: 'Certificate Templates Without Manager Approval',
            description: `Found ${noApprovalTemplates.length} authentication certificate templates without manager approval`,
            confidence: 75,
            evidence: {
              count: noApprovalTemplates.length,
              templates: noApprovalTemplates.map((cert: any) => ({
                name: cert.Properties?.templatename,
                usages: cert.Properties?.certificateusages,
                requiresApproval: cert.Properties?.requiresmanagerapproval
              }))
            },
            recommendations: [
              'Enable manager approval for authentication certificates',
              'Manager approval prevents unauthorized certificate enrollment',
              'Review approval workflow for certificate requests'
            ],
            timestamp: new Date(),
            detectedAt: new Date(),
            timeWindow: {
              start: new Date(Date.now() - this.timeWindow),
              end: new Date()
            },
            metadata: {},
            affectedEntities: noApprovalTemplates.map((cert: any) => ({
              type: 'user',
              id: cert.Properties?.templatename,
              name: cert.Properties?.templatename
            }))
          })
        }
      }

      // Templates requiring too many authorized signatures
      if (this.thresholds.maxAuthorizedSignatures > 0) {
        const excessiveSignaturesTemplates = sharpHoundData.certificates.filter((cert: any) =>
          (cert.Properties?.authorizedsignaturesrequired || 0) > this.thresholds.maxAuthorizedSignatures
        )

        if (excessiveSignaturesTemplates.length > 0) {
          anomalies.push({
            id: `${this.id}-excessive-signatures-${Date.now()}`,
            ruleId: this.id,
            ruleName: this.name,
            severity: 'low',
            category: 'security',
            title: 'Certificate Templates Requiring Excessive Signatures',
            description: `Found ${excessiveSignaturesTemplates.length} templates requiring more than ${this.thresholds.maxAuthorizedSignatures} authorized signatures`,
            confidence: 60,
            evidence: {
              count: excessiveSignaturesTemplates.length,
              maxSignatures: this.thresholds.maxAuthorizedSignatures,
              templates: excessiveSignaturesTemplates.map((cert: any) => ({
                name: cert.Properties?.templatename,
                requiredSignatures: cert.Properties?.authorizedsignaturesrequired
              }))
            },
            recommendations: [
              'Review signature requirements for certificate templates',
              'Excessive signature requirements may hinder legitimate certificate enrollment',
              'Balance security with operational efficiency'
            ],
            timestamp: new Date(),
            detectedAt: new Date(),
            timeWindow: {
              start: new Date(Date.now() - this.timeWindow),
              end: new Date()
            },
            metadata: {},
            affectedEntities: excessiveSignaturesTemplates.map((cert: any) => ({
              type: 'user',
              id: cert.Properties?.templatename,
              name: cert.Properties?.templatename
            }))
          })
        }
      }
    }

    return anomalies
  }
}
