import { AnalyticsRule, AuthEvent, AnalyticsContext, Anomaly } from '../types'

export class SharpHoundComputerAccountAnalysisRule implements AnalyticsRule {
  readonly id = 'sharpHound-computer-account-analysis'
  readonly name = 'SharpHound Computer Account Analysis'
  readonly description = 'Analyzes computer accounts for security issues and operational problems'
  readonly severity = 'medium'
  readonly category = 'security'
  readonly enabled = true
  readonly timeWindow = 24 * 60 * 60 * 1000 // 24 hours
  readonly version = '1.0.0'
  readonly author = 'ADTrapper'
  readonly created = new Date('2025-01-01')
  readonly updated = new Date('2025-01-01')

  readonly thresholds = {
    maxStaleComputers: 10,        // Max computers without recent logins
    staleComputerDays: 90,        // Days without login to be considered stale
    flagDisabledComputers: 1,     // Flag disabled computer accounts (1 = true, 0 = false)
    flagPre2000Computers: 1       // Flag computers created before 2000
  }

  readonly detailedDescription = {
    overview: 'Analyzes computer accounts for security issues and operational problems using SharpHound data. Identifies stale computer accounts, disabled systems, legacy computers, and other computer account management issues that could pose security or operational risks.',
    detectionLogic: 'Analyzes SharpHound computer objects for Properties.lastlogon (stale accounts), Properties.enabled (disabled accounts), Properties.whencreated (legacy accounts), and Properties.operatingsystem (OS version risks). Identifies computer accounts that may pose security risks or indicate poor asset management.',
    falsePositives: 'Computers temporarily offline for maintenance, systems with approved extended inactivity periods, legacy systems with compensating security controls, disabled computers maintained for backup/restore purposes, and test/development computer accounts.',
    mitigation: [
      'Regularly review and clean up stale computer accounts',
      'Implement automated computer account lifecycle management',
      'Monitor computer account creation and modification activities',
      'Implement computer account naming conventions and documentation',
      'Regularly audit computer account permissions and group memberships',
      'Use Group Policy for computer account management',
      'Implement computer account access control and approval workflows',
      'Regularly review computer operating system versions and patch levels',
      'Implement computer account decommissioning procedures',
      'Conduct regular Active Directory computer account audits'
    ],
    windowsEvents: ['4741 (Computer Account Created)', '4742 (Computer Account Changed)', '4743 (Computer Account Deleted)', '4624 (Account Logon Success)', '4625 (Account Logon Failure)', '4768 (Kerberos TGT Requested)', '4771 (Kerberos Pre-auth Failed)', '5136 (Directory Service Object Modified)', '5137 (Directory Service Object Created)', '5141 (Directory Service Object Deleted)'],
    exampleQuery: `index=windows EventCode=4741 OR EventCode=4743 | stats count by TargetUserName | where count > 5`,
    recommendedThresholds: {
      maxStaleComputers: 10,
      staleComputerDays: 90,
      flagDisabledComputers: 1,
      flagPre2000Computers: 1
    }
  }

  validate(): { valid: boolean; errors: string[] } {
    if (this.thresholds.staleComputerDays < 30) {
      return { valid: false, errors: ['staleComputerDays must be at least 30'] }
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

    // Analyze computer accounts
    if (sharpHoundData.computers) {
      // Find stale computer accounts
      const staleComputers = sharpHoundData.computers.filter((computer: any) => {
        if (!computer.Properties?.lastlogon || computer.Properties.lastlogon === 0) return false
        const daysSinceLastLogon = (Date.now() - computer.Properties.lastlogon * 1000) / (1000 * 60 * 60 * 24)
        return daysSinceLastLogon > this.thresholds.staleComputerDays
      })

      if (staleComputers.length > this.thresholds.maxStaleComputers) {
        anomalies.push({
          id: `${this.id}-stale-computers-${Date.now()}`,
          ruleId: this.id,
          ruleName: this.name,
          severity: 'medium',
          category: 'security',
          title: 'High Number of Stale Computer Accounts',
          description: `Found ${staleComputers.length} computer accounts with no login in ${this.thresholds.staleComputerDays}+ days (threshold: ${this.thresholds.maxStaleComputers})`,
          confidence: 80,
          evidence: {
            count: staleComputers.length,
            thresholdDays: this.thresholds.staleComputerDays,
            computers: staleComputers.map((c: any) => ({
              name: c.Properties?.samaccountname,
              lastLogon: c.Properties?.lastlogon ? new Date(c.Properties.lastlogon * 1000).toISOString() : 'Never',
              os: c.Properties?.operatingsystem
            })).slice(0, 10)
          },
          recommendations: ['Review and disable/remove stale computer accounts to reduce attack surface'],
          timestamp: new Date(),
          detectedAt: new Date(),
          timeWindow: {
            start: new Date(Date.now() - this.timeWindow),
            end: new Date()
          },
          metadata: {},
          affectedEntities: staleComputers.slice(0, 5).map((c: any) => ({
            type: 'computer',
            id: c.Properties.samaccountname,
            name: c.Properties.samaccountname
          }))
        })
      }

      // Flag disabled computer accounts
      if (this.thresholds.flagDisabledComputers > 0) {
        const disabledComputers = sharpHoundData.computers.filter((computer: any) =>
          computer.Properties?.enabled === false
        )

        if (disabledComputers.length > 0) {
          anomalies.push({
            id: `${this.id}-disabled-computers-${Date.now()}`,
            ruleId: this.id,
            ruleName: this.name,
            severity: 'low',
            category: 'security',
            title: 'Disabled Computer Accounts Found',
            description: `Found ${disabledComputers.length} disabled computer accounts`,
            confidence: 60,
            evidence: {
              count: disabledComputers.length,
              computers: disabledComputers.map((c: any) => c.Properties?.samaccountname).slice(0, 10)
            },
            recommendations: ['Review disabled computer accounts and remove if no longer needed'],
            timestamp: new Date(),
            detectedAt: new Date(),
            timeWindow: {
              start: new Date(Date.now() - this.timeWindow),
              end: new Date()
            },
            metadata: {},
            affectedEntities: disabledComputers.slice(0, 5).map((c: any) => ({
              type: 'computer',
              id: c.Properties.samaccountname,
              name: c.Properties.samaccountname
            }))
          })
        }
      }

      // Flag computers created before year 2000 (potential legacy systems)
      if (this.thresholds.flagPre2000Computers > 0) {
        const pre2000Computers = sharpHoundData.computers.filter((computer: any) => {
          if (!computer.Properties?.whencreated) return false
          const creationYear = new Date(computer.Properties.whencreated * 1000).getFullYear()
          return creationYear < 2000
        })

        if (pre2000Computers.length > 0) {
          anomalies.push({
            id: `${this.id}-pre2000-computers-${Date.now()}`,
            ruleId: this.id,
            ruleName: this.name,
            severity: 'low',
            category: 'security',
            title: 'Legacy Computer Accounts (Pre-2000)',
            description: `Found ${pre2000Computers.length} computer accounts created before year 2000`,
            confidence: 55,
            evidence: {
              count: pre2000Computers.length,
              computers: pre2000Computers.map((c: any) => ({
                name: c.Properties?.samaccountname,
                created: c.Properties?.whencreated ? new Date(c.Properties.whencreated * 1000).toISOString() : 'Unknown',
                os: c.Properties?.operatingsystem
              })).slice(0, 10)
            },
            recommendations: ['Review legacy computer accounts for security updates and modern authentication support'],
            timestamp: new Date(),
            detectedAt: new Date(),
            timeWindow: {
              start: new Date(Date.now() - this.timeWindow),
              end: new Date()
            },
            metadata: {},
            affectedEntities: pre2000Computers.slice(0, 5).map((c: any) => ({
              type: 'computer',
              id: c.Properties.samaccountname,
              name: c.Properties.samaccountname
            }))
          })
        }
      }

      // Analyze computer operating systems for security
      const osVersions = sharpHoundData.computers.reduce((acc: any, computer: any) => {
        const os = computer.Properties?.operatingsystem || 'Unknown'
        acc[os] = (acc[os] || 0) + 1
        return acc
      }, {})

      // Flag computers with outdated operating systems
      const outdatedOSPatterns = ['windows xp', 'windows vista', 'windows 7', 'windows 8', 'windows server 2003', 'windows server 2008']
      const outdatedComputers = sharpHoundData.computers.filter((computer: any) => {
        const os = computer.Properties?.operatingsystem?.toLowerCase() || ''
        return outdatedOSPatterns.some(pattern => os.includes(pattern))
      })

      if (outdatedComputers.length > 0) {
        anomalies.push({
          id: `${this.id}-outdated-os-computers-${Date.now()}`,
          ruleId: this.id,
          ruleName: this.name,
          severity: 'high',
          category: 'security',
          title: 'Computers with Outdated Operating Systems',
          description: `Found ${outdatedComputers.length} computers running outdated operating systems`,
          confidence: 90,
          evidence: {
            count: outdatedComputers.length,
            osBreakdown: Object.entries(osVersions).filter(([os]) =>
              outdatedOSPatterns.some(pattern => os.toLowerCase().includes(pattern))
            ),
            computers: outdatedComputers.map((c: any) => ({
              name: c.Properties?.samaccountname,
              os: c.Properties?.operatingsystem
            })).slice(0, 10)
          },
          recommendations: ['Upgrade outdated operating systems to supported versions with security updates'],
          timestamp: new Date(),
          detectedAt: new Date(),
          timeWindow: {
            start: new Date(Date.now() - this.timeWindow),
            end: new Date()
          },
          metadata: {},
          affectedEntities: outdatedComputers.slice(0, 5).map((c: any) => ({
            type: 'computer',
            id: c.Properties.samaccountname,
            name: c.Properties.samaccountname
          }))
        })
      }

      // Analyze domain controllers specifically
      const domainControllers = sharpHoundData.computers.filter((computer: any) =>
        computer.Properties?.isdc === true
      )

      if (domainControllers.length > 0) {
        // Flag domain controllers without recent logins (unusual)
        const dcWithoutRecentLogins = domainControllers.filter((dc: any) => {
          if (!dc.Properties?.lastlogon || dc.Properties.lastlogon === 0) return false
          const daysSinceLastLogon = (Date.now() - dc.Properties.lastlogon * 1000) / (1000 * 60 * 60 * 24)
          return daysSinceLastLogon > 7 // Domain controllers should log in weekly at minimum
        })

        if (dcWithoutRecentLogins.length > 0) {
          anomalies.push({
            id: `${this.id}-dc-no-recent-logins-${Date.now()}`,
            ruleId: this.id,
            ruleName: this.name,
            severity: 'high',
            category: 'security',
            title: 'Domain Controllers Without Recent Logins',
            description: `Found ${dcWithoutRecentLogins.length} domain controllers without recent login activity`,
            confidence: 85,
            evidence: {
              count: dcWithoutRecentLogins.length,
              domainControllers: dcWithoutRecentLogins.map((dc: any) => ({
                name: dc.Properties?.samaccountname,
                lastLogon: dc.Properties?.lastlogon ? new Date(dc.Properties.lastlogon * 1000).toISOString() : 'Never'
              }))
            },
            recommendations: ['Investigate domain controllers with no recent activity - may indicate decommissioned or compromised systems'],
            timestamp: new Date(),
            detectedAt: new Date(),
            timeWindow: {
              start: new Date(Date.now() - this.timeWindow),
              end: new Date()
            },
            metadata: {},
            affectedEntities: dcWithoutRecentLogins.map((dc: any) => ({
              type: 'computer',
              id: dc.Properties.samaccountname,
              name: dc.Properties.samaccountname
            }))
          })
        }
      }
    }

    return anomalies
  }
}
