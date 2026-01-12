import { BaseRule } from '../BaseRule'
import { AuthEvent, Anomaly, AnalyticsContext } from '../types'

export class ServiceAccountLifecycleRule extends BaseRule {
  constructor() {
    super({
      id: 'service_account_lifecycle_detection',
      name: 'Service Account Lifecycle Management',
      description: 'Monitors service account lifecycle events and password management',
      category: 'authentication',
      severity: 'medium',
      timeWindow: 720, // 30 days (lifecycle events are less frequent)
      thresholds: {
        passwordAgeThreshold: 365, // Flag passwords older than 1 year
        accountInactiveThreshold: 90, // Flag accounts inactive for 90 days
        frequentPasswordChanges: 5, // Flag if password changed more than 5 times in window
        unmanagedAccounts: 50 // Flag if more than 50% of service accounts are unmanaged
      },
      version: '1.0.0',
      author: 'ADTrapper Security Team',
      detailedDescription: {
        overview: 'Monitors service account lifecycle management including password aging, account inactivity, unmanaged accounts, and password change patterns. Ensures service accounts follow proper lifecycle management practices and security policies.',
        detectionLogic: 'Analyzes service account attributes including password age, last logon dates, account types, and password change frequency. Identifies service accounts that may be improperly managed, have outdated passwords, or show unusual lifecycle patterns that could indicate security issues.',
        falsePositives: 'Legitimate service accounts with extended password lifetimes for compatibility, accounts managed by automated systems, or service accounts with approved exceptions to standard policies. May also trigger during legitimate account lifecycle management or system migrations.',
        mitigation: [
          'Regular review and rotation of service account passwords',
          'Identify and remediate inactive service accounts',
          'Properly classify and manage service account types',
          'Implement automated service account lifecycle management',
          'Regular audit of service account privileges and usage',
          'Establish service account governance policies',
          'Monitor service account password change patterns',
          'Implement service account inventory and tracking',
          'Conduct regular service account security assessments',
          'Enable service account lifecycle monitoring and alerting'
        ],
        windowsEvents: ['4723 (Password Change Attempted)', '4724 (Password Reset Attempted)', '4738 (User Account Changed)', '4767 (User Account Unlocked)', '4624 (Account Logon Success)', '4625 (Account Logon Failure)', '4720 (User Account Created)', '4722 (User Account Enabled)', '4725 (Account Disabled)', '4740 (Account Locked Out)', '4781 (Account Name Changed)'],
        exampleQuery: `index=windows EventCode=4723 OR EventCode=4724 | stats count by TargetUserName | where count > 3`,
        recommendedThresholds: {
          passwordAgeThreshold: 365,
          accountInactiveThreshold: 90,
          frequentPasswordChanges: 5,
          unmanagedAccounts: 50
        }
      }
    })
  }

  async analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = []

    // Analyze service account profiles
    const serviceAccounts = context.userProfiles?.filter(profile => profile.isServiceAccount) || []

    if (serviceAccounts.length === 0) {
      return anomalies
    }

    // 1. Password Age Analysis
    const oldPasswords = serviceAccounts.filter(account =>
      account.passwordLastSet &&
      (new Date().getTime() - new Date(account.passwordLastSet).getTime()) / (1000 * 60 * 60 * 24) > this.thresholds.passwordAgeThreshold
    )

    if (oldPasswords.length > 0) {
      const confidence = oldPasswords.length >= serviceAccounts.length * 0.5 ? 75 :
                         oldPasswords.length >= serviceAccounts.length * 0.3 ? 65 : 55

      const anomaly = this.createAnomaly(
        'Service Account Password Aging',
        `${oldPasswords.length} service accounts have passwords older than ${this.thresholds.passwordAgeThreshold} days`,
        {
          oldPasswordCount: oldPasswords.length,
          totalServiceAccounts: serviceAccounts.length,
          percentage: ((oldPasswords.length / serviceAccounts.length) * 100).toFixed(1) + '%',
          accounts: oldPasswords.map(account => ({
            userName: account.userName,
            passwordAgeDays: account.passwordLastSet ?
              Math.floor((new Date().getTime() - new Date(account.passwordLastSet).getTime()) / (1000 * 60 * 60 * 24)) :
              'Unknown',
            serviceAccountType: account.serviceAccountType
          }))
        },
        confidence
      )
      anomalies.push(anomaly)
    }

    // 2. Inactive Service Accounts
    const inactiveAccounts = serviceAccounts.filter(account =>
      account.lastLogonDate &&
      (new Date().getTime() - new Date(account.lastLogonDate).getTime()) / (1000 * 60 * 60 * 24) > this.thresholds.accountInactiveThreshold
    )

    if (inactiveAccounts.length > 0) {
      const confidence = inactiveAccounts.length >= serviceAccounts.length * 0.4 ? 65 :
                         inactiveAccounts.length >= serviceAccounts.length * 0.2 ? 55 : 45

      const anomaly = this.createAnomaly(
        'Inactive Service Accounts',
        `${inactiveAccounts.length} service accounts have been inactive for more than ${this.thresholds.accountInactiveThreshold} days`,
        {
          inactiveCount: inactiveAccounts.length,
          totalServiceAccounts: serviceAccounts.length,
          percentage: ((inactiveAccounts.length / serviceAccounts.length) * 100).toFixed(1) + '%',
          accounts: inactiveAccounts.slice(0, 10).map(account => ({
            userName: account.userName,
            daysSinceLastLogon: account.lastLogonDate ?
              Math.floor((new Date().getTime() - new Date(account.lastLogonDate).getTime()) / (1000 * 60 * 60 * 24)) :
              'Never',
            serviceAccountType: account.serviceAccountType
          }))
        },
        confidence
      )
      anomalies.push(anomaly)
    }

    // 3. Unmanaged Service Accounts
    const unmanagedAccounts = serviceAccounts.filter(account =>
      !account.passwordNeverExpires &&
      !account.cannotChangePassword &&
      account.serviceAccountType === 'regular_user'
    )

    if (unmanagedAccounts.length > serviceAccounts.length * (this.thresholds.unmanagedAccounts / 100)) {
      const confidence = unmanagedAccounts.length >= serviceAccounts.length * 0.6 ? 75 :
                         unmanagedAccounts.length >= serviceAccounts.length * 0.4 ? 65 : 55

      const anomaly = this.createAnomaly(
        'Unmanaged Service Accounts',
        `${unmanagedAccounts.length} service accounts appear to be unmanaged regular user accounts`,
        {
          unmanagedCount: unmanagedAccounts.length,
          totalServiceAccounts: serviceAccounts.length,
          percentage: ((unmanagedAccounts.length / serviceAccounts.length) * 100).toFixed(1) + '%',
          accounts: unmanagedAccounts.slice(0, 10).map(account => ({
            userName: account.userName,
            indicators: account.serviceAccountIndicators,
            hasPasswordExpiry: !account.passwordNeverExpires
          }))
        },
        confidence
      )
      anomalies.push(anomaly)
    }

    // 4. Service Account Type Distribution
    const typeDistribution = serviceAccounts.reduce((acc, account) => {
      acc[account.serviceAccountType || 'unknown'] = (acc[account.serviceAccountType || 'unknown'] || 0) + 1
      return acc
    }, {} as Record<string, number>)

    // Flag if there are too many unmanaged accounts
    const regularUserCount = typeDistribution['regular_user'] || 0
    if (regularUserCount > serviceAccounts.length * 0.4) {
      const confidence = regularUserCount >= serviceAccounts.length * 0.7 ? 65 :
                         regularUserCount >= serviceAccounts.length * 0.5 ? 55 : 45

      const anomaly = this.createAnomaly(
        'Service Account Type Distribution',
        `${regularUserCount} service accounts are regular user accounts, which may indicate poor service account management`,
        {
          typeDistribution,
          regularUserCount,
          totalServiceAccounts: serviceAccounts.length,
          recommendedTypes: ['managed_service', 'group_managed', 'application_service'],
          riskAccounts: serviceAccounts
            .filter(account => account.serviceAccountType === 'regular_user')
            .slice(0, 5)
            .map(account => ({
              userName: account.userName,
              indicators: account.serviceAccountIndicators
            }))
        },
        confidence
      )
      anomalies.push(anomaly)
    }

    // 5. Service Account Authentication Patterns
    const recentEvents = this.filterByTimeWindow(events)
    const serviceAccountEvents = recentEvents.filter(event =>
      serviceAccounts.some(account =>
        account.userName.toLowerCase() === (event.userName || '').toLowerCase()
      )
    )

    // Check for service accounts with high authentication volumes (could indicate misuse)
    const authVolumeByAccount = this.groupBy(serviceAccountEvents, event => event.userName || 'unknown')
    const highVolumeAccounts = Object.entries(authVolumeByAccount)
      .filter(([userName, userEvents]) => userEvents.length > 1000) // More than 1000 auth events in time window
      .map(([userName, userEvents]) => ({ userName, eventCount: userEvents.length }))

    if (highVolumeAccounts.length > 0) {
      const confidence = highVolumeAccounts.length >= 5 ? 75 :
                         highVolumeAccounts.length >= 3 ? 65 : 55

      const anomaly = this.createAnomaly(
        'High Volume Service Account Authentication',
        `${highVolumeAccounts.length} service accounts have unusually high authentication volumes`,
        {
          highVolumeCount: highVolumeAccounts.length,
          accounts: highVolumeAccounts.slice(0, 5),
          threshold: 1000,
          timeWindowHours: this.timeWindow
        },
        confidence
      )
      anomalies.push(anomaly)
    }

    return anomalies
  }

  private calculateSeverity(value: number, threshold: number): 'low' | 'medium' | 'high' | 'critical' {
    const ratio = value / threshold

    if (ratio >= 2) return 'critical'
    if (ratio >= 1.5) return 'high'
    if (ratio >= 1) return 'medium'
    return 'low'
  }
}
