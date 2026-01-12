import { AnalyticsRule, AuthEvent, AnalyticsContext, Anomaly } from '../types'

export class SharpHoundKerberosDelegationRule implements AnalyticsRule {
  readonly id = 'sharpHound-kerberos-delegation'
  readonly name = 'SharpHound Kerberos Delegation Analysis'
  readonly description = 'Analyzes Kerberos delegation configurations that can lead to privilege escalation and lateral movement attacks.'
  readonly severity = 'high'
  readonly category = 'privilege'
  readonly enabled = true
  readonly timeWindow = 24 * 60 * 60 * 1000 // 24 hours
  readonly version = '1.0.0'
  readonly author = 'ADTrapper'
  readonly created = new Date('2025-01-01')
  readonly updated = new Date('2025-01-01')

  readonly thresholds = {
    maxUnconstrainedDelegation: 5, // Max number of accounts with unconstrained delegation
    maxConstrainedDelegation: 10,   // Max number of accounts with constrained delegation
  }

  readonly detailedDescription = {
    overview: 'Analyzes Kerberos delegation configurations that can lead to privilege escalation and lateral movement attacks using SharpHound data. Monitors delegation misconfigurations including unconstrained and constrained delegation settings that enable attackers to impersonate users and access network resources.',
    detectionLogic: 'Analyzes SharpHound data structures: checks user Properties.unconstraineddelegation and AllowedToDelegate arrays, computer Properties.unconstraineddelegation for delegation settings, filters objects where unconstraineddelegation=true or AllowedToDelegate.length > 0. Risk assessment prioritizes admin accounts with delegation as critical, unconstrained delegation as high risk, and constrained delegation as medium risk.',
    falsePositives: 'Legitimate service accounts with constrained delegation for business applications (like web servers accessing databases), domain controllers with necessary unconstrained delegation for replication, properly configured application servers with documented delegation requirements, and service accounts with approved delegation for specific business functions.',
    mitigation: [
      'Remove unconstrained delegation from administrator accounts immediately (critical priority)',
      'Replace unconstrained delegation with constrained delegation (TrustedToAuthForDelegation)',
      'Use Resource-Based Constrained Delegation (RBCD) for modern applications',
      'Regularly audit delegation permissions using SharpHound or BloodHound',
      'Enable Kerberos armoring (FAST) to prevent relay attacks',
      'Monitor for unusual Kerberos ticket requests (event ID 4769)',
      'Implement principle of least privilege for delegation configurations',
      'Document and approve all delegation requirements',
      'Regular security assessments of delegation settings',
      'Enable detailed Kerberos auditing and monitoring'
    ],
    windowsEvents: ['4769 (Kerberos Service Ticket Operations)', '4770 (Kerberos Service Ticket Renewals)', '4768 (Kerberos TGT Requested)', '4771 (Kerberos Pre-auth Failed)', '4624 (Account Logon Success)', '4625 (Account Logon Failure)', '4672 (Special Privileges Assigned)', '4673 (Sensitive Privilege Use)', '4 (Sysmon - Network Connection)', '3 (Sysmon - Network Connection)'],
    exampleQuery: `index=windows EventCode=4769 ServiceName!=*$ | stats count by Client, ServiceName, TargetDomainName | where count > 10`,
    recommendedThresholds: {
      maxUnconstrainedDelegation: 5,
      maxConstrainedDelegation: 10
    }
  }

  validate(): { valid: boolean; errors: string[] } {
    if (this.thresholds.maxUnconstrainedDelegation < 1) {
      return { valid: false, errors: ['maxUnconstrainedDelegation must be at least 1'] }
    }
    if (this.thresholds.maxConstrainedDelegation < 1) {
      return { valid: false, errors: ['maxConstrainedDelegation must be at least 1'] }
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

    // Analyze users for delegation settings
    if (sharpHoundData.users) {
      const unconstrainedDelegationUsers = sharpHoundData.users.filter(
        (user: any) => user.Properties?.unconstraineddelegation === true
      )

      const constrainedDelegationUsers = sharpHoundData.users.filter(
        (user: any) => user.AllowedToDelegate && user.AllowedToDelegate.length > 0
      )

      // Check for excessive unconstrained delegation
      if (unconstrainedDelegationUsers.length > this.thresholds.maxUnconstrainedDelegation) {
        anomalies.push({
          id: `${this.id}-unconstrained-${Date.now()}`,
          ruleId: this.id,
          ruleName: this.name,
          severity: 'high',
          category: 'privilege',
          title: 'Excessive Unconstrained Kerberos Delegation',
          description: `Found ${unconstrainedDelegationUsers.length} accounts with unconstrained delegation (threshold: ${this.thresholds.maxUnconstrainedDelegation})`,
          confidence: 85,
          evidence: {
            count: unconstrainedDelegationUsers.length,
            accounts: unconstrainedDelegationUsers.map((u: any) => u.Properties?.samaccountname).slice(0, 10)
          },
          recommendations: [
            'Audit all unconstrained delegation settings using: Get-ADUser -Filter {TrustedForDelegation -eq $true}',
            'Replace unconstrained delegation with constrained delegation (TrustedToAuthForDelegation)',
            'Limit constrained delegation to specific services using protocol transition restrictions',
            'Implement Resource-Based Constrained Delegation (RBCD) for modern applications',
            'Regularly review service account permissions and delegation rights',
            'Monitor for unusual Kerberos ticket requests using event ID 4769'
          ],
          timestamp: new Date(),
          detectedAt: new Date(),
          timeWindow: {
            start: new Date(Date.now() - this.timeWindow),
            end: new Date()
          },
          metadata: {},
          affectedEntities: unconstrainedDelegationUsers.map((u: any) => ({
            type: 'user',
            id: u.Properties?.samaccountname,
            name: u.Properties?.displayname || u.Properties?.samaccountname
          }))
        })
      }

      // Check for excessive constrained delegation
      if (constrainedDelegationUsers.length > this.thresholds.maxConstrainedDelegation) {
        anomalies.push({
          id: `${this.id}-constrained-${Date.now()}`,
          ruleId: this.id,
          ruleName: this.name,
          severity: 'medium',
          category: 'privilege',
          title: 'High Number of Constrained Delegation Configurations',
          description: `Found ${constrainedDelegationUsers.length} accounts with constrained delegation (threshold: ${this.thresholds.maxConstrainedDelegation})`,
          confidence: 75,
          evidence: {
            count: constrainedDelegationUsers.length,
            accounts: constrainedDelegationUsers.map((u: any) => u.Properties?.samaccountname).slice(0, 10)
          },
          recommendations: [
            'Verify constrained delegation is configured for legitimate business needs only',
            'Use "Use any authentication protocol" only when absolutely necessary',
            'Enable "Use Kerberos only" for better security where possible',
            'Regularly audit delegation permissions using: Get-ADUser -Filter {TrustedToAuthForDelegation -like "*"}',
            'Document all approved constrained delegation configurations',
            'Monitor for S4U2Self/S4U2Proxy attacks in security logs'
          ],
          timestamp: new Date(),
          detectedAt: new Date(),
          timeWindow: {
            start: new Date(Date.now() - this.timeWindow),
            end: new Date()
          },
          metadata: {},
          affectedEntities: constrainedDelegationUsers.map((u: any) => ({
            type: 'user',
            id: u.Properties?.samaccountname,
            name: u.Properties?.displayname || u.Properties?.samaccountname
          }))
        })
      }

      // Check for specific dangerous delegation patterns
      unconstrainedDelegationUsers.forEach((user: any) => {
        if (user.Properties?.admincount === true) {
          anomalies.push({
            id: `${this.id}-admin-unconstrained-${user.Properties.samaccountname}-${Date.now()}`,
            ruleId: this.id,
            ruleName: this.name,
                                  severity: 'critical',
            category: 'privilege',
            title: 'Administrator Account with Unconstrained Delegation',
          description: `Administrator account ${user.Properties.samaccountname} has unconstrained delegation enabled`,
          confidence: 95,
          evidence: {
            account: user.Properties.samaccountname,
            domain: user.Properties.domain,
            adminCount: user.Properties.admincount
          },
          recommendations: [
            'IMMEDIATE ACTION: Remove unconstrained delegation from all administrator accounts',
            'PowerShell command: Set-ADUser -Identity $account -TrustedForDelegation $false',
            'If delegation is required, implement Resource-Based Constrained Delegation instead',
            'Enable Privileged Access Management (PAM) for administrative accounts',
            'Implement Just-In-Time (JIT) access for administrative privileges',
            'Monitor administrator account usage with enhanced logging (event IDs 4672, 4720)',
            'Consider using different service accounts for delegation vs. administration'
          ],
          timestamp: new Date(),
          detectedAt: new Date(),
          timeWindow: {
            start: new Date(Date.now() - this.timeWindow),
            end: new Date()
          },
          metadata: {},
          affectedEntities: [{
            type: 'user',
            id: user.Properties.samaccountname,
            name: user.Properties.displayname || user.Properties.samaccountname
          }]
          })
        }
      })
    }

    // Analyze computers for delegation
    if (sharpHoundData.computers) {
      const computersWithUnconstrainedDelegation = sharpHoundData.computers.filter(
        (computer: any) => computer.Properties?.unconstraineddelegation === true
      )

      computersWithUnconstrainedDelegation.forEach((computer: any) => {
        anomalies.push({
          id: `${this.id}-computer-unconstrained-${computer.Properties.samaccountname}-${Date.now()}`,
          ruleId: this.id,
          ruleName: this.name,
          severity: 'medium',
          category: 'privilege',
          title: 'Computer with Unconstrained Delegation',
          description: `Computer ${computer.Properties.samaccountname} has unconstrained delegation enabled`,
          confidence: 70,
          evidence: {
            computer: computer.Properties.samaccountname,
            domain: computer.Properties.domain,
            os: computer.Properties.operatingsystem
          },
          recommendations: [
            'Verify if this computer requires unconstrained delegation for legitimate business purposes',
            'For domain controllers: Delegation is often necessary but should be carefully monitored',
            'For member servers: Replace with constrained delegation if possible',
            'PowerShell remediation: Set-ADComputer -Identity $computer -TrustedForDelegation $false',
            'Enable Kerberos armoring (msDS-SupportedEncryptionTypes) to prevent relay attacks',
            'Implement network segmentation to limit impact if compromised',
            'Regularly audit computer delegation rights using SharpHound or BloodHound'
          ],
          timestamp: new Date(),
          detectedAt: new Date(),
          timeWindow: {
            start: new Date(Date.now() - this.timeWindow),
            end: new Date()
          },
          metadata: {},
          affectedEntities: [{
            type: 'computer',
            id: computer.Properties.samaccountname,
            name: computer.Properties.samaccountname
          }]
        })
      })
    }

    return anomalies
  }
}
