import { AnalyticsRule, AuthEvent, AnalyticsContext, Anomaly } from '../types'

export class SharpHoundPasswordPolicyAnalysisRule implements AnalyticsRule {
  readonly id = 'sharpHound-password-policy-analysis'
  readonly name = 'SharpHound Password Policy Analysis'
  readonly description = 'Analyzes password policies and user account configurations for security weaknesses'
  readonly severity = 'high'
  readonly category = 'security'
  readonly enabled = true
  readonly timeWindow = 24 * 60 * 60 * 1000 // 24 hours
  readonly version = '1.0.0'
  readonly author = 'ADTrapper'
  readonly created = new Date('2025-01-01')
  readonly updated = new Date('2025-01-01')

  readonly thresholds = {
    minPasswordLength: 8,           // Minimum recommended password length
    maxPasswordAge: 90,             // Maximum password age in days
    flagPasswordNeverExpires: 1,    // Flag accounts with password never expires (1 = true, 0 = false)
    flagPreAuthDisabled: 1          // Flag accounts with pre-auth disabled (ASREP roastable)
  }

  readonly detailedDescription = {
    overview: 'Analyzes password policies and user account configurations for security weaknesses using SharpHound data. Identifies accounts with non-expiring passwords, disabled Kerberos pre-authentication (ASREP-roastable), and other password policy violations that could enable offline attacks.',
    detectionLogic: 'Analyzes SharpHound user objects for Properties.pwdneverexpires, Properties.dontreqpreauth, Properties.pwdlastset, and password policy settings. Identifies accounts with weak password configurations, non-expiring passwords, and Kerberos pre-authentication disabled. Reviews password age and policy compliance.',
    falsePositives: 'Service accounts with approved non-expiring passwords for automated systems, accounts with business-justified exceptions to password policies, legacy accounts managed by external systems, and accounts where password policies have been reviewed and approved for specific business requirements.',
    mitigation: [
      'Enable password expiration for all user accounts unless specifically approved',
      'Enable Kerberos pre-authentication for all accounts to prevent ASREP roasting',
      'Implement strong password policies with complexity requirements',
      'Regularly rotate passwords for accounts with non-expiring passwords',
      'Use Group Managed Service Accounts (gMSA) for service accounts',
      'Implement multi-factor authentication to reduce password-based attack impact',
      'Regularly audit password policy compliance across the domain',
      'Monitor for ASREP roasting attempts against vulnerable accounts',
      'Implement password policy enforcement and monitoring',
      'Conduct regular password security assessments'
    ],
    windowsEvents: ['4723 (Password Change Attempted)', '4724 (Password Reset Attempted)', '4768 (Kerberos TGT Requested)', '4771 (Kerberos Pre-auth Failed)', '4624 (Account Logon Success)', '4625 (Account Logon Failure)', '4739 (Domain Policy Changed)', '4719 (System Audit Policy Changed)', '4907 (Auditing Settings on Object Changed)', '4908 (Special Registry Item Modified)'],
    exampleQuery: `index=windows EventCode=4771 | stats count by TargetUserName | where count > 5`,
    recommendedThresholds: {
      minPasswordLength: 8,
      maxPasswordAge: 90,
      flagPasswordNeverExpires: 1,
      flagPreAuthDisabled: 1
    }
  }

  validate(): { valid: boolean; errors: string[] } {
    if (this.thresholds.minPasswordLength < 8) {
      return { valid: false, errors: ['minPasswordLength should be at least 8'] }
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

    // Analyze user password configurations
    if (sharpHoundData.users) {
      // Find accounts with password never expires
      if (this.thresholds.flagPasswordNeverExpires > 0) {
        const passwordNeverExpiresUsers = sharpHoundData.users.filter((user: any) =>
          user.Properties?.pwdneverexpires === true &&
          user.Properties?.enabled === true
        )

        if (passwordNeverExpiresUsers.length > 0) {
          anomalies.push({
            id: `${this.id}-password-never-expires-${Date.now()}`,
            ruleId: this.id,
            ruleName: this.name,
            severity: 'medium',
            category: 'security',
            title: 'Accounts with Non-Expiring Passwords',
            description: `Found ${passwordNeverExpiresUsers.length} enabled accounts with non-expiring passwords`,
            confidence: 75,
            evidence: {
              count: passwordNeverExpiresUsers.length,
              accounts: passwordNeverExpiresUsers.map((u: any) => ({
                name: u.Properties?.samaccountname,
                domain: u.Properties?.domain,
                privileged: u.Properties?.admincount === true
              })).slice(0, 10)
            },
            recommendations: ['Enable password expiration for all user accounts, especially non-privileged ones'],
            timestamp: new Date(),
            detectedAt: new Date(),
            timeWindow: {
              start: new Date(Date.now() - this.timeWindow),
              end: new Date()
            },
            metadata: {},
            affectedEntities: passwordNeverExpiresUsers.slice(0, 5).map((u: any) => ({
              type: 'user',
              id: u.Properties.samaccountname,
              name: u.Properties.displayname || u.Properties.samaccountname
            }))
          })
        }
      }

      // Find accounts vulnerable to ASREP roasting (pre-auth disabled)
      if (this.thresholds.flagPreAuthDisabled > 0) {
        const preAuthDisabledUsers = sharpHoundData.users.filter((user: any) =>
          user.Properties?.dontreqpreauth === true &&
          user.Properties?.enabled === true
        )

        if (preAuthDisabledUsers.length > 0) {
          anomalies.push({
            id: `${this.id}-preauth-disabled-${Date.now()}`,
            ruleId: this.id,
            ruleName: this.name,
            severity: 'high',
            category: 'security',
            title: 'Accounts Vulnerable to ASREP Roasting',
            description: `Found ${preAuthDisabledUsers.length} accounts with pre-authentication disabled`,
            confidence: 85,
            evidence: {
              count: preAuthDisabledUsers.length,
              accounts: preAuthDisabledUsers.map((u: any) => ({
                name: u.Properties?.samaccountname,
                domain: u.Properties?.domain,
                privileged: u.Properties?.admincount === true
              })).slice(0, 10)
            },
            recommendations: ['Enable pre-authentication for all accounts to prevent ASREP roasting attacks'],
            timestamp: new Date(),
            detectedAt: new Date(),
            timeWindow: {
              start: new Date(Date.now() - this.timeWindow),
              end: new Date()
            },
            metadata: {},
            affectedEntities: preAuthDisabledUsers.slice(0, 5).map((u: any) => ({
              type: 'user',
              id: u.Properties.samaccountname,
              name: u.Properties.displayname || u.Properties.samaccountname
            }))
          })
        }
      }

      // Find accounts with old password changes
      const oldPasswordUsers = sharpHoundData.users.filter((user: any) => {
        if (!user.Properties?.pwdlastset || user.Properties.pwdlastset === 0) return false
        if (user.Properties?.pwdneverexpires === true) return false // Skip accounts with non-expiring passwords
        const daysSincePasswordChange = (Date.now() - user.Properties.pwdlastset * 1000) / (1000 * 60 * 60 * 24)
        return daysSincePasswordChange > this.thresholds.maxPasswordAge
      })

      if (oldPasswordUsers.length > 0) {
        anomalies.push({
          id: `${this.id}-old-passwords-${Date.now()}`,
          ruleId: this.id,
          ruleName: this.name,
          severity: 'medium',
          category: 'security',
          title: 'Accounts with Old Password Changes',
          description: `Found ${oldPasswordUsers.length} accounts with passwords older than ${this.thresholds.maxPasswordAge} days`,
          confidence: 70,
          evidence: {
            count: oldPasswordUsers.length,
            thresholdDays: this.thresholds.maxPasswordAge,
            accounts: oldPasswordUsers.map((u: any) => ({
              name: u.Properties?.samaccountname,
              lastChanged: u.Properties?.pwdlastset ? new Date(u.Properties.pwdlastset * 1000).toISOString() : 'Never',
              privileged: u.Properties?.admincount === true
            })).slice(0, 10)
          },
          recommendations: ['Enforce regular password changes and consider implementing password policies'],
          timestamp: new Date(),
          detectedAt: new Date(),
          timeWindow: {
            start: new Date(Date.now() - this.timeWindow),
            end: new Date()
          },
          metadata: {},
          affectedEntities: oldPasswordUsers.slice(0, 5).map((u: any) => ({
            type: 'user',
            id: u.Properties.samaccountname,
            name: u.Properties.displayname || u.Properties.samaccountname
          }))
        })
      }

      // Analyze password settings by privilege level
      const privilegedUsers = sharpHoundData.users.filter((user: any) =>
        user.Properties?.admincount === true && user.Properties?.enabled === true
      )

      const nonPrivilegedUsers = sharpHoundData.users.filter((user: any) =>
        user.Properties?.admincount !== true && user.Properties?.enabled === true
      )

      // Flag privileged accounts with weak password configurations
      const privilegedWeakPasswords = privilegedUsers.filter((user: any) =>
        user.Properties?.pwdneverexpires === true ||
        user.Properties?.dontreqpreauth === true
      )

      if (privilegedWeakPasswords.length > 0) {
        anomalies.push({
          id: `${this.id}-privileged-weak-passwords-${Date.now()}`,
          ruleId: this.id,
          ruleName: this.name,
          severity: 'critical',
          category: 'security',
          title: 'Privileged Accounts with Weak Password Configurations',
          description: `Found ${privilegedWeakPasswords.length} privileged accounts with weak password settings`,
          confidence: 90,
          evidence: {
            count: privilegedWeakPasswords.length,
            accounts: privilegedWeakPasswords.map((u: any) => ({
              name: u.Properties?.samaccountname,
              pwdNeverExpires: u.Properties?.pwdneverexpires,
              preAuthDisabled: u.Properties?.dontreqpreauth
            })).slice(0, 10)
          },
          recommendations: ['Privileged accounts must have strong password policies - enable expiration and pre-authentication'],
          timestamp: new Date(),
          detectedAt: new Date(),
          timeWindow: {
            start: new Date(Date.now() - this.timeWindow),
            end: new Date()
          },
          metadata: {},
          affectedEntities: privilegedWeakPasswords.slice(0, 5).map((u: any) => ({
            type: 'user',
            id: u.Properties.samaccountname,
            name: u.Properties.displayname || u.Properties.samaccountname
          }))
        })
      }

      // Compare privileged vs non-privileged password policies
      const privilegedStats = {
        total: privilegedUsers.length,
        pwdNeverExpires: privilegedUsers.filter(u => u.Properties?.pwdneverexpires).length,
        preAuthDisabled: privilegedUsers.filter(u => u.Properties?.dontreqpreauth).length
      }

      const nonPrivilegedStats = {
        total: nonPrivilegedUsers.length,
        pwdNeverExpires: nonPrivilegedUsers.filter(u => u.Properties?.pwdneverexpires).length,
        preAuthDisabled: nonPrivilegedUsers.filter(u => u.Properties?.dontreqpreauth).length
      }

      // Flag if non-privileged accounts have better password policies than privileged ones
      if (privilegedStats.pwdNeverExpires > nonPrivilegedStats.pwdNeverExpires) {
        anomalies.push({
          id: `${this.id}-inverted-password-policies-${Date.now()}`,
          ruleId: this.id,
          ruleName: this.name,
          severity: 'high',
          category: 'security',
          title: 'Inverted Password Policies',
          description: `More privileged accounts have non-expiring passwords than non-privileged accounts`,
          confidence: 80,
          evidence: {
            privilegedWithNeverExpire: privilegedStats.pwdNeverExpires,
            nonPrivilegedWithNeverExpire: nonPrivilegedStats.pwdNeverExpires,
            privilegedTotal: privilegedStats.total,
            nonPrivilegedTotal: nonPrivilegedStats.total
          },
          recommendations: ['Privileged accounts should have the strongest password policies, not weaker ones'],
          timestamp: new Date(),
          detectedAt: new Date(),
          timeWindow: {
            start: new Date(Date.now() - this.timeWindow),
            end: new Date()
          },
          metadata: {},
          affectedEntities: [] // This is a policy-level issue, not specific to accounts
        })
      }
    }

    return anomalies
  }
}
