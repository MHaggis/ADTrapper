import { AnalyticsRule, AuthEvent, AnalyticsContext, Anomaly } from '../types'

export class SharpHoundDomainControllerAnalysisRule implements AnalyticsRule {
  readonly id = 'sharpHound-domain-controller-analysis'
  readonly name = 'SharpHound Domain Controller Security Analysis'
  readonly description = 'Analyzes domain controllers for security misconfigurations and vulnerabilities.'
  readonly severity = 'critical'
  readonly category = 'security'
  readonly enabled = true
  readonly timeWindow = 24 * 60 * 60 * 1000 // 24 hours
  readonly version = '1.0.0'
  readonly author = 'ADTrapper'
  readonly created = new Date('2025-01-01')
  readonly updated = new Date('2025-01-01')

  readonly thresholds = {
    maxDCsWithoutLAPS: 0,              // Domain controllers MUST have LAPS
    flagDCsWithDelegation: 1,          // Flag DCs with delegation (unusual)
    flagDCsWithOldOS: 1,               // Flag DCs with old OS versions
    minDCUptimeHours: 24 * 7           // Minimum expected uptime (7 days)
  }

  readonly detailedDescription = {
    overview: 'Analyzes domain controllers for security misconfigurations and operational vulnerabilities using SharpHound data. Critical infrastructure assessment focusing on LAPS deployment, delegation settings, OS versions, high availability configurations, and privilege escalation risks.',
    detectionLogic: 'Evaluates SharpHound computer objects with Properties.isdc=true. Checks Properties.haslaps for local admin password protection. Analyzes Properties.unconstraineddelegation and AllowedToDelegate arrays for delegation vulnerabilities. Assesses Properties.operatingsystem for version risks and security patch levels. Validates domain controller count and redundancy configurations.',
    falsePositives: 'Domain controllers with legitimate delegation for specific business applications, planned single DC environments for small organizations, temporary LAPS exceptions for maintenance, authorized legacy OS usage with compensating controls, or test/development domain controllers.',
    mitigation: [
      'Deploy LAPS to all domain controllers immediately (critical priority)',
      'Remove Kerberos delegation from domain controllers unless absolutely required',
      'Maintain multiple domain controllers for redundancy and high availability',
      'Keep domain controllers updated with latest security patches',
      'Implement network segmentation and access controls for domain controllers',
      'Enable comprehensive auditing and monitoring for DC activities',
      'Regular backup and testing of Active Directory disaster recovery procedures',
      'Implement domain controller hardening and security baselines',
      'Monitor domain controller performance and availability',
      'Regular security assessments of domain controller configurations'
    ],
    windowsEvents: ['4624 (Account Logon Success)', '4625 (Account Logon Failure)', '4672 (Special Privileges Assigned)', '4673 (Sensitive Privilege Use)', '4768 (Kerberos TGT Requested)', '4771 (Kerberos Pre-auth Failed)', '5136 (Directory Service Object Modified)', '5137 (Directory Service Object Created)', '5141 (Directory Service Object Deleted)', '4904 (Security Event Source Registered)', '4905 (Security Event Source Unregistered)'],
    exampleQuery: `index=windows EventCode=4672 ComputerName=*dc* | stats count by TargetUserName, ComputerName | where count > 10`,
    recommendedThresholds: {
      maxDCsWithoutLAPS: 0,
      flagDCsWithDelegation: 1,
      flagDCsWithOldOS: 1,
      minDCUptimeHours: 168
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

    // Analyze domain controllers
    if (sharpHoundData.computers) {
      const domainControllers = sharpHoundData.computers.filter((computer: any) =>
        computer.Properties?.isdc === true
      )

      console.log(`🔍 Analyzing ${domainControllers.length} domain controllers`)

      // Check for domain controllers without LAPS
      const dcsWithoutLAPS = domainControllers.filter((dc: any) =>
        dc.Properties?.haslaps === false || dc.Properties?.haslaps === null
      )

      if (dcsWithoutLAPS.length > this.thresholds.maxDCsWithoutLAPS) {
        anomalies.push({
          id: `${this.id}-dc-without-laps-${Date.now()}`,
          ruleId: this.id,
          ruleName: this.name,
          severity: 'critical',
          category: 'security',
          title: 'Domain Controllers Without LAPS Protection',
          description: `Found ${dcsWithoutLAPS.length} domain controllers without LAPS protection`,
          confidence: 100,
          evidence: {
            count: dcsWithoutLAPS.length,
            totalDCs: domainControllers.length,
            unprotectedDCs: dcsWithoutLAPS.map((dc: any) => dc.Properties?.samaccountname)
          },
          recommendations: [
            'EMERGENCY PRIORITY: Domain controllers MUST have LAPS implemented immediately',
            'Install LAPS on all domain controllers: https://www.microsoft.com/en-us/download/details.aspx?id=46899',
            'Configure GPO: Computer Configuration > Administrative Templates > LAPS > Enable password management',
            'Set password complexity requirements in LAPS GPO settings',
            'Configure password expiration (default 30 days) and length requirements',
            'Grant Domain Admins read access to ms-Mcs-AdmPwd attribute for password retrieval',
            'Test LAPS functionality: Get-AdmPwdPassword -ComputerName $dcName',
            'Enable LAPS event logging for monitoring password changes',
            'Document emergency procedures for DC local admin password access'
          ],
          timestamp: new Date(),
          detectedAt: new Date(),
          timeWindow: {
            start: new Date(Date.now() - this.timeWindow),
            end: new Date()
          },
          metadata: {},
          affectedEntities: dcsWithoutLAPS.map((dc: any) => ({
            type: 'computer',
            id: dc.Properties.samaccountname,
            name: dc.Properties.samaccountname
          }))
        })
      }

      // Check for domain controllers with unusual delegation
      if (this.thresholds.flagDCsWithDelegation > 0) {
        const dcsWithDelegation = domainControllers.filter((dc: any) =>
          dc.Properties?.unconstraineddelegation === true ||
          (dc.AllowedToDelegate && dc.AllowedToDelegate.length > 0)
        )

        if (dcsWithDelegation.length > 0) {
          anomalies.push({
            id: `${this.id}-dc-with-delegation-${Date.now()}`,
            ruleId: this.id,
            ruleName: this.name,
            severity: 'high',
            category: 'security',
            title: 'Domain Controllers with Kerberos Delegation',
            description: `Found ${dcsWithDelegation.length} domain controllers with Kerberos delegation enabled`,
            confidence: 85,
            evidence: {
              count: dcsWithDelegation.length,
              delegationTypes: dcsWithDelegation.map((dc: any) => ({
                name: dc.Properties?.samaccountname,
                unconstrained: dc.Properties?.unconstraineddelegation,
                constrainedCount: dc.AllowedToDelegate?.length || 0
              }))
            },
            recommendations: [
              'CRITICAL: Domain controllers should NEVER have Kerberos delegation enabled',
              'PowerShell remediation: Set-ADComputer -Identity $dcName -TrustedForDelegation $false',
              'Verify business requirement - DCs rarely need delegation for legitimate purposes',
              'If delegation is required, use constrained delegation instead of unconstrained',
              'Audit all delegation permissions: Get-ADComputer -Filter {TrustedForDelegation -eq $true}',
              'Monitor for unusual Kerberos service ticket requests (event ID 4769)',
              'Enable Kerberos armoring to prevent delegation-based relay attacks',
              'Document any approved delegation configurations for DCs'
            ],
            timestamp: new Date(),
            detectedAt: new Date(),
            timeWindow: {
              start: new Date(Date.now() - this.timeWindow),
              end: new Date()
            },
            metadata: {},
            affectedEntities: dcsWithDelegation.map((dc: any) => ({
              type: 'computer',
              id: dc.Properties.samaccountname,
              name: dc.Properties.samaccountname
            }))
          })
        }
      }

      // Check for domain controllers with old operating systems
      if (this.thresholds.flagDCsWithOldOS > 0) {
        const oldOSPatterns = ['windows server 2008', 'windows server 2012', 'windows server 2016']
        const dcsWithOldOS = domainControllers.filter((dc: any) => {
          const os = dc.Properties?.operatingsystem?.toLowerCase() || ''
          return oldOSPatterns.some(pattern => os.includes(pattern))
        })

        if (dcsWithOldOS.length > 0) {
          anomalies.push({
            id: `${this.id}-dc-old-os-${Date.now()}`,
            ruleId: this.id,
            ruleName: this.name,
            severity: 'medium',
            category: 'security',
            title: 'Domain Controllers Running Outdated Operating Systems',
            description: `Found ${dcsWithOldOS.length} domain controllers running outdated OS versions`,
            confidence: 90,
            evidence: {
              count: dcsWithOldOS.length,
              oldDCs: dcsWithOldOS.map((dc: any) => ({
                name: dc.Properties?.samaccountname,
                os: dc.Properties?.operatingsystem
              }))
            },
            recommendations: [
              'Upgrade domain controllers to supported OS versions',
              'Outdated OS versions may lack security patches and features',
              'Consider Windows Server 2022 or 2025 for new deployments'
            ],
            timestamp: new Date(),
            detectedAt: new Date(),
            timeWindow: {
              start: new Date(Date.now() - this.timeWindow),
              end: new Date()
            },
            metadata: {},
            affectedEntities: dcsWithOldOS.map((dc: any) => ({
              type: 'computer',
              id: dc.Properties.samaccountname,
              name: dc.Properties.samaccountname
            }))
          })
        }
      }

      // Analyze DC count and distribution
      if (domainControllers.length === 0) {
        anomalies.push({
          id: `${this.id}-no-domain-controllers-${Date.now()}`,
          ruleId: this.id,
          ruleName: this.name,
          severity: 'critical',
          category: 'security',
          title: 'No Domain Controllers Found',
          description: 'SharpHound collection contains no domain controllers',
          confidence: 100,
          evidence: {
            totalComputers: sharpHoundData.computers.length,
            domainControllersFound: 0
          },
          recommendations: [
            'Verify SharpHound collection includes domain controller data',
            'Domain controllers are critical for Active Directory functionality',
            'Ensure SharpHound has permissions to enumerate domain controllers'
          ],
          timestamp: new Date(),
          detectedAt: new Date(),
          timeWindow: {
            start: new Date(Date.now() - this.timeWindow),
            end: new Date()
          },
          metadata: {},
          affectedEntities: []
        })
      } else if (domainControllers.length === 1) {
        anomalies.push({
          id: `${this.id}-single-domain-controller-${Date.now()}`,
          ruleId: this.id,
          ruleName: this.name,
          severity: 'high',
          category: 'security',
          title: 'Single Domain Controller Environment',
          description: 'Domain has only one domain controller - high availability risk',
          confidence: 95,
          evidence: {
            dcCount: domainControllers.length,
            dcNames: domainControllers.map((dc: any) => dc.Properties?.samaccountname)
          },
          recommendations: [
            'Deploy additional domain controllers for redundancy',
            'Single DC environments are vulnerable to outages and attacks',
            'Consider at least 2 DCs per domain for high availability'
          ],
          timestamp: new Date(),
          detectedAt: new Date(),
          timeWindow: {
            start: new Date(Date.now() - this.timeWindow),
            end: new Date()
          },
          metadata: {},
          affectedEntities: domainControllers.map((dc: any) => ({
            type: 'computer',
            id: dc.Properties.samaccountname,
            name: dc.Properties.samaccountname
          }))
        })
      }
    }

    return anomalies
  }
}
