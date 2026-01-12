import { AnalyticsRule, AuthEvent, AnalyticsContext, Anomaly } from '../types'

export class SharpHoundServiceAccountAnalysisRule implements AnalyticsRule {
  readonly id = 'sharpHound-service-account-analysis'
  readonly name = 'SharpHound Service Account Analysis'
  readonly description = 'Analyzes service accounts for security misconfigurations and excessive privileges'
  readonly severity = 'high'
  readonly category = 'privilege'
  readonly enabled = true
  readonly timeWindow = 24 * 60 * 60 * 1000 // 24 hours
  readonly version = '1.0.0'
  readonly author = 'ADTrapper'
  readonly created = new Date('2025-01-01')
  readonly updated = new Date('2025-01-01')

  readonly thresholds = {
    maxServiceAccountsWithDomainAdmin: 5,   // Max service accounts in Domain Admins
    maxServiceAccountsWithAdminPrivs: 10,   // Max service accounts with admin privileges
    flagServiceAccountsWithSPNs: 1,         // Flag service accounts with SPNs (1 = true, 0 = false)
    flagOldPasswords: 90                    // Days after which to flag old passwords
  }

  readonly detailedDescription = {
    overview: 'Analyzes service accounts for security misconfigurations and excessive privileges using SharpHound data. Identifies service accounts with domain admin privileges, old passwords, and SPNs that could be vulnerable to Kerberoasting attacks.',
    detectionLogic: 'Analyzes SharpHound user objects for service account patterns (names containing svc, service, sql, etc.) and SPNs. Checks membership in privileged groups like Domain Admins. Reviews password age and privilege assignments. Identifies service accounts that violate least privilege principles.',
    falsePositives: 'Service accounts with approved administrative privileges for specific business applications, accounts managed by automated systems with approved configurations, service accounts with documented privilege requirements, and accounts where elevated privileges are managed through approved change management processes.',
    mitigation: [
      'Remove service accounts from Domain Admin and Enterprise Admin groups immediately',
      'Implement Group Managed Service Accounts (gMSA) for service accounts',
      'Use least privilege principle for all service account permissions',
      'Regularly rotate service account passwords and review password policies',
      'Monitor service accounts with SPNs for Kerberoasting attacks',
      'Implement service account inventory and lifecycle management',
      'Use constrained delegation instead of unconstrained delegation',
      'Regularly audit service account privileges and access patterns',
      'Implement approval workflows for service account privilege changes',
      'Enable detailed monitoring for service account activities'
    ],
    windowsEvents: ['4624 (Account Logon Success)', '4625 (Account Logon Failure)', '4672 (Special Privileges Assigned)', '4673 (Sensitive Privilege Use)', '4769 (Kerberos Service Ticket Operations)', '4771 (Kerberos Pre-auth Failed)', '4723 (Password Change Attempted)', '4724 (Password Reset Attempted)', '4738 (User Account Changed)', '4767 (User Account Unlocked)'],
    exampleQuery: `index=windows EventCode=4624 | stats count by TargetUserName | where TargetUserName LIKE "*svc*" OR TargetUserName LIKE "*service*" | where count > 10`,
    recommendedThresholds: {
      maxServiceAccountsWithDomainAdmin: 5,
      maxServiceAccountsWithAdminPrivs: 10,
      flagServiceAccountsWithSPNs: 1,
      flagOldPasswords: 90
    }
  }

  validate(): { valid: boolean; errors: string[] } {
    if (this.thresholds.maxServiceAccountsWithDomainAdmin < 0) {
      return { valid: false, errors: ['maxServiceAccountsWithDomainAdmin cannot be negative'] }
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

    // Analyze service accounts
    if (sharpHoundData.users) {
      const serviceAccounts = sharpHoundData.users.filter((user: any) => {
        const samAccountName = user.Properties?.samaccountname?.toLowerCase() || ''
        return samAccountName.includes('svc') ||
               samAccountName.includes('service') ||
               samAccountName.includes('sql') ||
               samAccountName.includes('iis') ||
               samAccountName.includes('app') ||
               samAccountName.includes('web') ||
               samAccountName.includes('db') ||
               samAccountName.includes('sql') ||
               samAccountName.includes('ldap') ||
               samAccountName.includes('ftp') ||
               samAccountName.includes('mail') ||
               (user.Properties?.serviceprincipalnames && user.Properties.serviceprincipalnames.length > 0)
      })

      // Find service accounts with Domain Admin membership
      const serviceAccountsWithDomainAdmin = serviceAccounts.filter((user: any) =>
        user.Properties?.memberof?.some((group: string) =>
          group.toLowerCase().includes('domain admins') ||
          group.toLowerCase().includes('enterprise admins')
        )
      )

      if (serviceAccountsWithDomainAdmin.length > this.thresholds.maxServiceAccountsWithDomainAdmin) {
        anomalies.push({
          id: `${this.id}-service-accounts-domain-admin-${Date.now()}`,
          ruleId: this.id,
          ruleName: this.name,
          severity: 'critical',
          category: 'privilege',
          title: 'Service Accounts with Domain Admin Privileges',
          description: `Found ${serviceAccountsWithDomainAdmin.length} service accounts with Domain Admin privileges (threshold: ${this.thresholds.maxServiceAccountsWithDomainAdmin})`,
          confidence: 95,
          evidence: {
            count: serviceAccountsWithDomainAdmin.length,
            accounts: serviceAccountsWithDomainAdmin.map((u: any) => u.Properties?.samaccountname).slice(0, 10)
          },
          recommendations: ['Service accounts should never have Domain Admin privileges. Use least privilege principle.'],
          timestamp: new Date(),
          detectedAt: new Date(),
          timeWindow: {
            start: new Date(Date.now() - this.timeWindow),
            end: new Date()
          },
          metadata: {},
          affectedEntities: serviceAccountsWithDomainAdmin.slice(0, 5).map((u: any) => ({
            type: 'user',
            id: u.Properties.samaccountname,
            name: u.Properties.displayname || u.Properties.samaccountname
          }))
        })
      }

      // Find service accounts with admin privileges (but not Domain Admin)
      const serviceAccountsWithAdminPrivs = serviceAccounts.filter((user: any) =>
        user.Properties?.admincount === true &&
        !user.Properties?.memberof?.some((group: string) =>
          group.toLowerCase().includes('domain admins') ||
          group.toLowerCase().includes('enterprise admins')
        )
      )

      if (serviceAccountsWithAdminPrivs.length > this.thresholds.maxServiceAccountsWithAdminPrivs) {
        anomalies.push({
          id: `${this.id}-service-accounts-admin-privs-${Date.now()}`,
          ruleId: this.id,
          ruleName: this.name,
          severity: 'high',
          category: 'privilege',
          title: 'Service Accounts with Administrative Privileges',
          description: `Found ${serviceAccountsWithAdminPrivs.length} service accounts with admin privileges (threshold: ${this.thresholds.maxServiceAccountsWithAdminPrivs})`,
          confidence: 85,
          evidence: {
            count: serviceAccountsWithAdminPrivs.length,
            accounts: serviceAccountsWithAdminPrivs.map((u: any) => u.Properties?.samaccountname).slice(0, 10)
          },
          recommendations: ['Review if service accounts require administrative privileges. Consider using separate service accounts with minimal privileges.'],
          timestamp: new Date(),
          detectedAt: new Date(),
          timeWindow: {
            start: new Date(Date.now() - this.timeWindow),
            end: new Date()
          },
          metadata: {},
          affectedEntities: serviceAccountsWithAdminPrivs.slice(0, 5).map((u: any) => ({
            type: 'user',
            id: u.Properties.samaccountname,
            name: u.Properties.displayname || u.Properties.samaccountname
          }))
        })
      }

      // Analyze service accounts with SPNs (potential for Kerberoasting)
      if (this.thresholds.flagServiceAccountsWithSPNs > 0) {
        const serviceAccountsWithSPNs = serviceAccounts.filter((user: any) =>
          user.Properties?.serviceprincipalnames &&
          user.Properties.serviceprincipalnames.length > 0 &&
          user.Properties?.enabled === true
        )

        serviceAccountsWithSPNs.forEach((user: any) => {
          anomalies.push({
            id: `${this.id}-service-account-spn-${user.Properties.samaccountname}-${Date.now()}`,
            ruleId: this.id,
            ruleName: this.name,
            severity: 'medium',
            category: 'privilege',
            title: 'Service Account with SPN (Kerberoasting Risk)',
            description: `Service account ${user.Properties.samaccountname} has SPNs configured`,
            confidence: 70,
            evidence: {
              account: user.Properties.samaccountname,
              spns: user.Properties.serviceprincipalnames,
              domain: user.Properties.domain
            },
            recommendations: ['Ensure service account passwords are strong and consider using managed service accounts (MSA/gMSA)'],
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

      // Check for service accounts with old password changes
      const oldServiceAccounts = serviceAccounts.filter((user: any) => {
        if (!user.Properties?.pwdlastset || user.Properties.pwdlastset === 0) return false
        const daysSincePasswordChange = (Date.now() - user.Properties.pwdlastset * 1000) / (1000 * 60 * 60 * 24)
        return daysSincePasswordChange > this.thresholds.flagOldPasswords
      })

      if (oldServiceAccounts.length > 0) {
        anomalies.push({
          id: `${this.id}-service-accounts-old-passwords-${Date.now()}`,
          ruleId: this.id,
          ruleName: this.name,
          severity: 'medium',
          category: 'security',
          title: 'Service Accounts with Old Password Changes',
          description: `Found ${oldServiceAccounts.length} service accounts with passwords older than ${this.thresholds.flagOldPasswords} days`,
          confidence: 75,
          evidence: {
            count: oldServiceAccounts.length,
            thresholdDays: this.thresholds.flagOldPasswords,
            accounts: oldServiceAccounts.map((u: any) => ({
              name: u.Properties?.samaccountname,
              lastChanged: u.Properties?.pwdlastset ? new Date(u.Properties.pwdlastset * 1000).toISOString() : 'Never'
            })).slice(0, 10)
          },
          recommendations: ['Regularly rotate service account passwords and consider using managed service accounts'],
          timestamp: new Date(),
          detectedAt: new Date(),
          timeWindow: {
            start: new Date(Date.now() - this.timeWindow),
            end: new Date()
          },
          metadata: {},
          affectedEntities: oldServiceAccounts.slice(0, 5).map((u: any) => ({
            type: 'user',
            id: u.Properties.samaccountname,
            name: u.Properties.displayname || u.Properties.samaccountname
          }))
        })
      }
    }

    return anomalies
  }
}
