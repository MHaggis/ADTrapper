import { AnalyticsRule, AuthEvent, AnalyticsContext, Anomaly } from '../types'

export class SharpHoundLAPSAnalysisRule implements AnalyticsRule {
  readonly id = 'sharpHound-laps-analysis'
  readonly name = 'SharpHound LAPS Analysis'
  readonly description = 'Analyzes Local Administrator Password Solution (LAPS) implementation across domain computers.'
  readonly severity = 'medium'
  readonly category = 'security'
  readonly enabled = true
  readonly timeWindow = 24 * 60 * 60 * 1000 // 24 hours
  readonly version = '1.0.0'
  readonly author = 'ADTrapper'
  readonly created = new Date('2025-01-01')
  readonly updated = new Date('2025-01-01')

  readonly thresholds = {
    maxComputersWithoutLAPS: 20,    // Max computers without LAPS
    requireLAPSOnServers: 1,        // Flag servers without LAPS (1 = true, 0 = false)
    requireLAPSOnWorkstations: 0    // Flag workstations without LAPS (1 = true, 0 = false)
  }

  readonly detailedDescription = {
    overview: 'Analyzes Local Administrator Password Solution (LAPS) deployment across domain computers using SharpHound data. Monitors LAPS installation status and identifies systems vulnerable to Pass-the-Hash attacks and lateral movement through exposed local administrator passwords.',
    detectionLogic: 'Evaluates SharpHound computer objects for Properties.haslaps flag to determine LAPS deployment status. Analyzes Properties.operatingsystem for server vs workstation categorization. Calculates coverage statistics and prioritizes risks by system criticality (Domain Controllers > Servers > Workstations). Identifies systems where local administrator passwords are stored in clear text in Active Directory.',
    falsePositives: 'Computers with LAPS temporarily disabled for maintenance windows, legacy systems incompatible with LAPS requirements, isolated systems with unique local admin password management, authorized exceptions documented in security policy, and systems with alternative approved password management solutions.',
    mitigation: [
      'Deploy LAPS to all domain computers immediately (critical priority for servers and domain controllers)',
      'Configure GPO with appropriate password complexity and rotation policies for LAPS',
      'Grant read permissions to ms-Mcs-AdmPwd attribute only for authorized helpdesk and admin personnel',
      'Monitor LAPS password changes and access attempts to ms-Mcs-AdmPwd',
      'Regularly audit LAPS deployment coverage and effectiveness across the domain',
      'Test LAPS functionality and emergency password retrieval procedures',
      'Implement LAPS password complexity and length requirements',
      'Configure LAPS password expiration and rotation policies',
      'Enable auditing for LAPS-related events and attribute access',
      'Regular security assessments of LAPS implementation and configuration'
    ],
    windowsEvents: ['4662 (Object Operation on ms-Mcs-AdmPwd)', '5136 (Directory Service Object Modified)', '4909 (Local Security Authority Loaded)', '4719 (System Audit Policy Changed)', '4739 (Domain Policy Changed)', '4746 (Computer Account Changed)', '4904 (Security Event Source Registered)', '4905 (Security Event Source Unregistered)'],
    exampleQuery: `index=windows EventCode=4662 ObjectName="*ms-Mcs-AdmPwd*" | stats count by SubjectUserName, ComputerName | where count > 10`,
    recommendedThresholds: {
      maxComputersWithoutLAPS: 20,
      requireLAPSOnServers: 1,
      requireLAPSOnWorkstations: 0
    }
  }

  validate(): { valid: boolean; errors: string[] } {
    if (this.thresholds.maxComputersWithoutLAPS < 0) {
      return { valid: false, errors: ['maxComputersWithoutLAPS cannot be negative'] }
    }
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

    // This rule is designed for SharpHound data, not traditional auth events
    if (!context.sharpHoundData) {
      return anomalies
    }

    const sharpHoundData = context.sharpHoundData

    // Analyze computers for LAPS implementation
    if (sharpHoundData.computers) {
      const computersWithoutLAPS = sharpHoundData.computers.filter(
        (computer: any) => computer.Properties?.haslaps === false || computer.Properties?.haslaps === null
      )

      const serversWithoutLAPS = computersWithoutLAPS.filter(
        (computer: any) => {
          const os = computer.Properties?.operatingsystem?.toLowerCase() || ''
          return os.includes('server') && !os.includes('workstation')
        }
      )

      const workstationsWithoutLAPS = computersWithoutLAPS.filter(
        (computer: any) => {
          const os = computer.Properties?.operatingsystem?.toLowerCase() || ''
          return os.includes('workstation') || (!os.includes('server') && os.includes('windows'))
        }
      )

      // Check for excessive computers without LAPS
      if (computersWithoutLAPS.length > this.thresholds.maxComputersWithoutLAPS) {
        anomalies.push({
          id: `${this.id}-no-laps-total-${Date.now()}`,
          ruleId: this.id,
          ruleName: this.name,
          severity: 'medium',
          category: 'security',
          title: 'High Number of Computers Without LAPS',
          description: `Found ${computersWithoutLAPS.length} computers without LAPS protection (threshold: ${this.thresholds.maxComputersWithoutLAPS})`,
          confidence: 75,
          evidence: {
            totalWithoutLAPS: computersWithoutLAPS.length,
            serversWithoutLAPS: serversWithoutLAPS.length,
            workstationsWithoutLAPS: workstationsWithoutLAPS.length,
            totalComputers: sharpHoundData.computers.length,
            coverage: `${((sharpHoundData.computers.length - computersWithoutLAPS.length) / sharpHoundData.computers.length * 100).toFixed(1)}%`
          },
          recommendations: [
            'Download and install LAPS from Microsoft: https://www.microsoft.com/en-us/download/details.aspx?id=46899',
            'Deploy LAPS MSI package to all domain computers using Group Policy',
            'Configure GPO settings under: Computer Configuration > Policies > Administrative Templates > LAPS',
            'Set "Enable local admin password management" to Enabled',
            'Configure password complexity and length requirements',
            'Set password expiration policy (default: 30 days)',
            'Grant read permissions to confidential attributes for helpdesk/administrators',
            'Test LAPS functionality on pilot systems before full deployment'
          ],
          timestamp: new Date(),
          detectedAt: new Date(),
          timeWindow: {
            start: new Date(Date.now() - this.timeWindow),
            end: new Date()
          },
          metadata: {},
          affectedEntities: computersWithoutLAPS.slice(0, 10).map((c: any) => ({
            type: 'computer',
            id: c.Properties?.samaccountname,
            name: c.Properties?.samaccountname
          }))
        })
      }

      // Flag servers without LAPS
      if (this.thresholds.requireLAPSOnServers > 0 && serversWithoutLAPS.length > 0) {
        anomalies.push({
          id: `${this.id}-servers-no-laps-${Date.now()}`,
          ruleId: this.id,
          ruleName: this.name,
          severity: 'high',
          category: 'security',
          title: 'Servers Without LAPS Protection',
          description: `Found ${serversWithoutLAPS.length} servers without LAPS protection`,
          confidence: 85,
          evidence: {
            count: serversWithoutLAPS.length,
            servers: serversWithoutLAPS.map((c: any) => ({
              name: c.Properties?.samaccountname,
              os: c.Properties?.operatingsystem
            })).slice(0, 10)
          },
          recommendations: [
            'CRITICAL: Servers MUST have LAPS implemented immediately',
            'Priority order: Domain Controllers > File Servers > Application Servers > Other Servers',
            'Deploy LAPS GPO to server OUs with highest priority',
            'Verify LAPS client installation: Confirm ms-Mcs-AdmPwd attribute exists',
            'Test password retrieval: Get-AdmPwdPassword -ComputerName $serverName',
            'Configure emergency password retrieval procedures for administrators',
            'Enable LAPS logging in Group Policy for troubleshooting',
            'Monitor LAPS password changes in security logs (event ID 4662 on ms-Mcs-AdmPwd)'
          ],
          timestamp: new Date(),
          detectedAt: new Date(),
          timeWindow: {
            start: new Date(Date.now() - this.timeWindow),
            end: new Date()
          },
          metadata: {},
          affectedEntities: serversWithoutLAPS.slice(0, 10).map((c: any) => ({
            type: 'computer',
            id: c.Properties?.samaccountname,
            name: c.Properties?.samaccountname
          }))
        })
      }

      // Flag workstations without LAPS (if configured)
      if (this.thresholds.requireLAPSOnWorkstations > 0 && workstationsWithoutLAPS.length > 0) {
        anomalies.push({
          id: `${this.id}-workstations-no-laps-${Date.now()}`,
          ruleId: this.id,
          ruleName: this.name,
          severity: 'low',
          category: 'security',
          title: 'Workstations Without LAPS Protection',
          description: `Found ${workstationsWithoutLAPS.length} workstations without LAPS protection`,
          confidence: 60,
          evidence: {
            count: workstationsWithoutLAPS.length,
            workstations: workstationsWithoutLAPS.map((c: any) => ({
              name: c.Properties?.samaccountname,
              os: c.Properties?.operatingsystem
            })).slice(0, 10)
          },
          recommendations: [
            'Consider LAPS deployment on workstations for enhanced security',
            'Evaluate business requirements: High-security environments should implement LAPS everywhere',
            'For large deployments: Phase rollout by department or location',
            'Configure different password policies for workstations vs servers if needed',
            'Limit helpdesk access to workstation LAPS passwords based on business needs',
            'Monitor for unauthorized LAPS password access attempts',
            'Document exceptions for workstations that cannot have LAPS',
            'Consider alternatives like Microsoft Intune for non-domain scenarios'
          ],
          timestamp: new Date(),
          detectedAt: new Date(),
          timeWindow: {
            start: new Date(Date.now() - this.timeWindow),
            end: new Date()
          },
          metadata: {},
          affectedEntities: workstationsWithoutLAPS.slice(0, 10).map((c: any) => ({
            type: 'computer',
            id: c.Properties?.samaccountname,
            name: c.Properties?.samaccountname
          }))
        })
      }

      // Check for domain controllers without LAPS (this is concerning)
      const dcsWithoutLAPS = computersWithoutLAPS.filter(
        (computer: any) => computer.Properties?.isdc === true
      )

      if (dcsWithoutLAPS.length > 0) {
        anomalies.push({
          id: `${this.id}-dc-no-laps-${Date.now()}`,
          ruleId: this.id,
          ruleName: this.name,
          severity: 'critical',
          category: 'security',
          title: 'Domain Controllers Without LAPS',
          description: `Found ${dcsWithoutLAPS.length} domain controllers without LAPS protection`,
          confidence: 95,
          evidence: {
            count: dcsWithoutLAPS.length,
            domainControllers: dcsWithoutLAPS.map((c: any) => c.Properties?.samaccountname)
          },
          recommendations: [
            'EMERGENCY PRIORITY: Domain controllers MUST have LAPS implemented immediately',
            'Domain controllers are the most critical systems to protect with LAPS',
            'Manual password management on DCs creates significant security risks',
            'Verify LAPS schema extensions are properly installed',
            'Test LAPS functionality thoroughly before production deployment',
            'Configure restricted read permissions for DC LAPS passwords (Domain Admins only)',
            'Enable audit logging for all LAPS password access on domain controllers',
            'Create incident response procedures for DC local admin password scenarios',
            'Consider additional security measures like Credential Guard for DCs'
          ],
          timestamp: new Date(),
          detectedAt: new Date(),
          timeWindow: {
            start: new Date(Date.now() - this.timeWindow),
            end: new Date()
          },
          metadata: {},
          affectedEntities: dcsWithoutLAPS.map((c: any) => ({
            type: 'computer',
            id: c.Properties?.samaccountname,
            name: c.Properties?.samaccountname
          }))
        })
      }
    }

    return anomalies
  }
}
