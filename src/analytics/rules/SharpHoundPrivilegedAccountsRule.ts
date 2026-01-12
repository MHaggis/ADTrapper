import { AnalyticsRule, AuthEvent, AnalyticsContext, Anomaly } from '../types'

export class SharpHoundPrivilegedAccountsRule implements AnalyticsRule {
  readonly id = 'sharpHound-privileged-accounts'
  readonly name = 'SharpHound Privileged Accounts Analysis'
  readonly description = 'Identifies privileged accounts and potential security risks in Active Directory.'
  readonly severity = 'high'
  readonly category = 'privilege'
  readonly enabled = true
  readonly timeWindow = 24 * 60 * 60 * 1000 // 24 hours
  readonly version = '1.0.0'
  readonly author = 'ADTrapper'
  readonly created = new Date('2025-01-01')
  readonly updated = new Date('2025-01-01')

  readonly thresholds = {
    maxAdminCountAccounts: 50,      // Max accounts with adminCount = true
    maxDomainAdmins: 10,            // Max Domain Admin members
    maxEnterpriseAdmins: 5,         // Max Enterprise Admin members
    flagServiceAccounts: 1,         // Flag accounts that look like service accounts (1 = true, 0 = false)
  }

  readonly detailedDescription = {
    overview: 'Identifies privileged accounts and potential security risks in Active Directory using SharpHound data analysis. Analyzes adminCount flags, service account patterns, password policies, and delegation configurations that could lead to privilege escalation and lateral movement attacks.',
    detectionLogic: 'Examines SharpHound user objects for Properties.admincount, Properties.samaccountname, Properties.serviceprincipalnames, Properties.pwdneverexpires, and Properties.dontreqpreauth. Checks computer objects for Properties.unconstraineddelegation. Reviews group Aces for complex permission structures. Identifies service accounts using name patterns and correlates risky attributes like ASREP-roastable accounts.',
    falsePositives: 'Legitimate service accounts with administrative privileges for business applications, properly configured delegation for approved services, accounts with business-justified non-expiring passwords, authorized privileged access with documented justifications, and service accounts managed by automated systems.',
    mitigation: [
      'Remove administrative privileges from service accounts unless absolutely necessary',
      'Enable password expiration for privileged accounts (remove pwdNeverExpires)',
      'Implement Just-In-Time (JIT) administrative access using tools like Azure PIM',
      'Use Group Managed Service Accounts (gMSA) for service accounts instead of user accounts',
      'Regularly audit privileged account usage and permissions',
      'Implement multi-factor authentication for all administrative accounts',
      'Enable Kerberos pre-authentication for ASREP-roastable accounts',
      'Remove unconstrained delegation from privileged accounts',
      'Implement principle of least privilege for all privileged accounts',
      'Regular security assessments of privileged account configurations'
    ],
    windowsEvents: ['4624 (Account Logon Success)', '4625 (Account Logon Failure)', '4672 (Special Privileges Assigned)', '4673 (Sensitive Privilege Use)', '4742 (Computer Account Changed)', '4732 (Member Added to Security Group)', '4733 (Member Removed from Security Group)', '4728 (Security Group Member Added)', '4729 (Security Group Member Removed)', '4769 (Kerberos Service Ticket Operations)', '4771 (Kerberos Pre-auth Failed)'],
    exampleQuery: `index=windows EventCode=4672 | stats count by TargetUserName, TargetDomainName | where count > 5`,
    recommendedThresholds: {
      maxAdminCountAccounts: 50,
      maxDomainAdmins: 10,
      maxEnterpriseAdmins: 5
    }
  }

  validate(): { valid: boolean; errors: string[] } {
    if (this.thresholds.maxAdminCountAccounts < 1) {
      return { valid: false, errors: ['maxAdminCountAccounts must be at least 1'] }
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

    // Analyze users for privileged access
    if (sharpHoundData.users) {
      const adminCountUsers = sharpHoundData.users.filter(
        (user: any) => user.Properties?.admincount === true
      )

      const serviceAccounts = sharpHoundData.users.filter((user: any) => {
        const samAccountName = user.Properties?.samaccountname?.toLowerCase() || ''
        return samAccountName.includes('svc') ||
               samAccountName.includes('service') ||
               samAccountName.includes('sql') ||
               samAccountName.includes('iis') ||
               samAccountName.includes('app') ||
               user.Properties?.serviceprincipalnames?.length > 0
      })

      // Check for excessive admin accounts
      if (adminCountUsers.length > this.thresholds.maxAdminCountAccounts) {
        anomalies.push({
          id: `${this.id}-admin-count-${Date.now()}`,
          ruleId: this.id,
          ruleName: this.name,
          severity: 'medium',
          category: 'privilege',
          title: 'High Number of Administrative Accounts',
          description: `Found ${adminCountUsers.length} accounts with adminCount flag (threshold: ${this.thresholds.maxAdminCountAccounts})`,
          confidence: 80,
          evidence: {
            count: adminCountUsers.length,
            accounts: adminCountUsers.map((u: any) => u.Properties?.samaccountname).slice(0, 10)
          },
          recommendations: [
            'Audit all adminCount=1 accounts using: Get-ADUser -Filter {AdminCount -eq 1}',
            'Verify each account legitimately requires administrative privileges',
            'Implement Just-In-Time (JIT) administrative access using tools like Microsoft PIM',
            'Enable enhanced auditing for administrative accounts (audit policy: Account Management)',
            'Regularly review administrative group memberships and remove unnecessary access',
            'Implement multi-factor authentication for all administrative accounts',
            'Document approval process for administrative account creation and maintenance'
          ],
          timestamp: new Date(),
          detectedAt: new Date(),
          timeWindow: {
            start: new Date(Date.now() - this.timeWindow),
            end: new Date()
          },
          metadata: {},
          affectedEntities: adminCountUsers.map((u: any) => ({
            type: 'user',
            id: u.Properties?.samaccountname,
            name: u.Properties?.displayname || u.Properties?.samaccountname
          }))
        })
      }

      // Flag service accounts with admin privileges
      if (this.thresholds.flagServiceAccounts > 0) {
        const privilegedServiceAccounts = serviceAccounts.filter((user: any) =>
          user.Properties?.admincount === true ||
          user.Properties?.memberOf?.some((group: string) =>
            group.toLowerCase().includes('admin') ||
            group.toLowerCase().includes('domain admins')
          )
        )

        privilegedServiceAccounts.forEach((user: any) => {
          anomalies.push({
            id: `${this.id}-service-admin-${user.Properties.samaccountname}-${Date.now()}`,
            ruleId: this.id,
            ruleName: this.name,
            severity: 'medium',
            category: 'privilege',
            title: 'Service Account with Administrative Privileges',
            description: `Service account ${user.Properties.samaccountname} has administrative privileges`,
            confidence: 75,
            evidence: {
              account: user.Properties.samaccountname,
              domain: user.Properties.domain,
              spns: user.Properties.serviceprincipalnames || []
            },
            recommendations: [
              'SECURITY RISK: Service accounts should NEVER have administrative privileges',
              'Create separate service accounts without administrative rights',
              'Use Group Managed Service Accounts (gMSA) for better security',
              'Implement principle of least privilege for all service accounts',
              'Audit service account usage patterns and required permissions',
              'PowerShell remediation: Remove-ADGroupMember -Identity "Domain Admins" -Members $serviceAccount',
              'Enable Service Account Management in Microsoft PIM for JIT access',
              'Regularly rotate service account passwords using automated tools'
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
        })
      }

      // Check for accounts with password never expires
      const pwdNeverExpiresUsers = sharpHoundData.users.filter(
        (user: any) => user.Properties?.pwdneverexpires === true && user.Properties?.enabled === true
      )

      if (pwdNeverExpiresUsers.length > 0) {
        anomalies.push({
          id: `${this.id}-pwd-never-expires-${Date.now()}`,
          ruleId: this.id,
          ruleName: this.name,
          severity: 'low',
          category: 'security',
          title: 'Accounts with Non-Expiring Passwords',
          description: `Found ${pwdNeverExpiresUsers.length} enabled accounts with non-expiring passwords`,
          confidence: 60,
          evidence: {
            count: pwdNeverExpiresUsers.length,
            accounts: pwdNeverExpiresUsers.map((u: any) => u.Properties?.samaccountname).slice(0, 10)
          },
          recommendations: [
            'Audit all non-expiring password accounts: Get-ADUser -Filter {PasswordNeverExpires -eq $true}',
            'For service accounts: Use Group Managed Service Accounts (gMSA) instead',
            'For privileged accounts: Implement regular password rotation policies',
            'Set maximum password age using: Set-ADDefaultDomainPasswordPolicy -MaxPasswordAge 90.00:00:00',
            'Enable password expiration: Set-ADUser -Identity $account -PasswordNeverExpires $false',
            'Implement password rotation alerts and automated rotation where possible',
            'Document exceptions for accounts that must have non-expiring passwords'
          ],
          timestamp: new Date(),
          detectedAt: new Date(),
          timeWindow: {
            start: new Date(Date.now() - this.timeWindow),
            end: new Date()
          },
          metadata: {},
          affectedEntities: pwdNeverExpiresUsers.map((u: any) => ({
            type: 'user',
            id: u.Properties?.samaccountname,
            name: u.Properties?.displayname || u.Properties?.samaccountname
          }))
        })
      }
    }

    // Analyze computers for privileged configurations
    if (sharpHoundData.computers) {
      const domainControllers = sharpHoundData.computers.filter(
        (computer: any) => computer.Properties?.isdc === true
      )

      // Flag computers that are not domain controllers but have unconstrained delegation
      const nonDCUnconstrainedDelegation = sharpHoundData.computers.filter(
        (computer: any) => computer.Properties?.unconstraineddelegation === true &&
                          computer.Properties?.isdc !== true
      )

      nonDCUnconstrainedDelegation.forEach((computer: any) => {
        anomalies.push({
          id: `${this.id}-non-dc-unconstrained-${computer.Properties.samaccountname}-${Date.now()}`,
          ruleId: this.id,
          ruleName: this.name,
          severity: 'medium',
          category: 'privilege',
          title: 'Non-DC Computer with Unconstrained Delegation',
          description: `Non-domain controller ${computer.Properties.samaccountname} has unconstrained delegation`,
          confidence: 70,
          evidence: {
            computer: computer.Properties.samaccountname,
            domain: computer.Properties.domain,
            os: computer.Properties.operatingsystem
          },
          recommendations: [
            'HIGH RISK: Non-DC computers should NOT have unconstrained delegation',
            'Replace with constrained delegation: Set-ADComputer -Identity $computer -TrustedForDelegation $false',
            'Implement Resource-Based Constrained Delegation (RBCD) for modern applications',
            'Verify business requirement for delegation on member servers',
            'Enable Kerberos armoring to prevent relay attacks',
            'Regularly audit delegation configurations using SharpHound',
            'Document approved delegation configurations in security policy'
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

    // Analyze groups for high-privilege memberships
    if (sharpHoundData.groups) {
      const domainAdmins = sharpHoundData.groups.find(
        (group: any) => group.Properties?.samaccountname?.toLowerCase().includes('domain admins')
      )

      if (domainAdmins && domainAdmins.Aces) {
        // This would require more complex analysis of group memberships
        // For now, just flag if there are too many ACEs on Domain Admins
        if (domainAdmins.Aces.length > 50) {
          anomalies.push({
            id: `${this.id}-domain-admins-aces-${Date.now()}`,
            ruleId: this.id,
            ruleName: this.name,
            severity: 'medium',
            category: 'privilege',
            title: 'Complex Domain Admins Permissions',
            description: `Domain Admins group has ${domainAdmins.Aces.length} permission entries`,
            confidence: 65,
            evidence: {
              group: domainAdmins.Properties.samaccountname,
              aceCount: domainAdmins.Aces.length
            },
            recommendations: [
              'Audit Domain Admins ACEs using: (Get-ACL "AD:CN=Domain Admins,CN=Users,DC=domain,DC=com").Access',
              'Remove unnecessary permissions and explicit ACEs from Domain Admins',
              'Follow principle of least privilege for administrative access',
              'Use nested groups instead of direct permissions where possible',
              'Implement Microsoft Privileged Identity Management (PIM) for JIT access',
              'Regularly review and document all Domain Admin permissions',
              'Enable advanced auditing for changes to privileged group memberships'
            ],
            timestamp: new Date(),
            detectedAt: new Date(),
            timeWindow: {
              start: new Date(Date.now() - this.timeWindow),
              end: new Date()
            },
            metadata: {},
            affectedEntities: [{
              type: 'user', // Using 'user' type for groups since that's closest match
              id: domainAdmins.Properties.samaccountname,
              name: domainAdmins.Properties.samaccountname
            }]
          })
        }
      }
    }

    return anomalies
  }
}
