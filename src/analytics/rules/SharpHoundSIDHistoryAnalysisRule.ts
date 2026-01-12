import { AnalyticsRule, AuthEvent, AnalyticsContext, Anomaly } from '../types'

export class SharpHoundSIDHistoryAnalysisRule implements AnalyticsRule {
  readonly id = 'sharpHound-sid-history-analysis'
  readonly name = 'SharpHound SID History Analysis'
  readonly description = 'Analyzes SID History attributes for persistence and privilege escalation risks'
  readonly severity = 'medium'
  readonly category = 'privilege'
  readonly enabled = true
  readonly timeWindow = 24 * 60 * 60 * 1000 // 24 hours
  readonly version = '1.0.0'
  readonly author = 'ADTrapper'
  readonly created = new Date('2025-01-01')
  readonly updated = new Date('2025-01-01')

  readonly thresholds = {
    flagSIDHistory: 1,                  // Flag accounts with SID history
    maxSIDHistoryEntries: 3,            // Max SID history entries per account
    flagPrivilegedSIDHistory: 1,        // Flag privileged SIDs in history
    flagCrossDomainSIDHistory: 1        // Flag SID history from different domains
  }

  readonly detailedDescription = {
    overview: 'Analyzes SID History attributes for persistence and privilege escalation risks using SharpHound data. Identifies accounts with SID history that may retain privileged access from domain migrations, posing risks for lateral movement and privilege escalation attacks.',
    detectionLogic: 'Analyzes SharpHound user objects for Properties.sidhistory arrays. Identifies accounts with excessive SID history entries, privileged SIDs in history, and cross-domain SID history. Flags accounts that may have retained administrative privileges from previous domains or migrations.',
    falsePositives: 'Accounts with legitimate SID history from approved domain migrations, accounts with SID history from trusted partner domains, service accounts with documented SID history requirements, and accounts where SID history has been properly reviewed and approved.',
    mitigation: [
      'Regularly audit and clean up unnecessary SID history entries',
      'Review accounts with privileged SIDs in history for continued need',
      'Implement SID filtering for cross-domain trust relationships',
      'Monitor for unauthorized use of SID history privileges',
      'Document legitimate SID history requirements for business applications',
      'Implement approval workflows for SID history modifications',
      'Regularly review domain migration and SID history cleanup procedures',
      'Enable detailed auditing for SID history attribute access',
      'Conduct regular privilege escalation risk assessments',
      'Implement automated SID history monitoring and alerting'
    ],
    windowsEvents: ['5136 (Directory Service Object Modified)', '5137 (Directory Service Object Created)', '5139 (Directory Service Object Moved)', '5141 (Directory Service Object Deleted)', '4904 (Security Event Source Registered)', '4905 (Security Event Source Unregistered)', '4907 (Auditing Settings on Object Changed)', '4908 (Special Registry Item Modified)', '4624 (Account Logon Success)', '4625 (Account Logon Failure)'],
    exampleQuery: `index=windows EventCode=5136 ObjectDN="*sidhistory*" | stats count by TargetUserName | where count > 3`,
    recommendedThresholds: {
      flagSIDHistory: 1,
      maxSIDHistoryEntries: 3,
      flagPrivilegedSIDHistory: 1,
      flagCrossDomainSIDHistory: 1
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

    if (this.thresholds.flagSIDHistory > 0) {
      // Analyze users with SID history
      if (sharpHoundData.users) {
        console.log(`🔍 Analyzing SID history for ${sharpHoundData.users.length} users`)

        const usersWithSIDHistory = sharpHoundData.users.filter((user: any) =>
          user.Properties?.sidhistory && Array.isArray(user.Properties.sidhistory) && user.Properties.sidhistory.length > 0
        )

        if (usersWithSIDHistory.length > 0) {
          // Check for excessive SID history entries
          const usersWithExcessiveSIDHistory = usersWithSIDHistory.filter((user: any) =>
            user.Properties.sidhistory.length > this.thresholds.maxSIDHistoryEntries
          )

          if (usersWithExcessiveSIDHistory.length > 0) {
            anomalies.push({
              id: `${this.id}-excessive-sid-history-${Date.now()}`,
              ruleId: this.id,
              ruleName: this.name,
              severity: 'low',
              category: 'privilege',
              title: 'Accounts with Excessive SID History Entries',
              description: `Found ${usersWithExcessiveSIDHistory.length} accounts with more than ${this.thresholds.maxSIDHistoryEntries} SID history entries`,
              confidence: 70,
              evidence: {
                count: usersWithExcessiveSIDHistory.length,
                maxEntries: this.thresholds.maxSIDHistoryEntries,
                accounts: usersWithExcessiveSIDHistory.map((user: any) => ({
                  name: user.Properties?.samaccountname,
                  domain: user.Properties?.domain,
                  sidHistoryCount: user.Properties?.sidhistory?.length || 0,
                  privileged: user.Properties?.admincount === true
                })).slice(0, 10)
              },
              recommendations: [
                'Review accounts with excessive SID history entries',
                'Multiple SID history entries may indicate account migration issues',
                'Clean up unnecessary SID history to reduce attack surface'
              ],
              timestamp: new Date(),
              detectedAt: new Date(),
              timeWindow: {
                start: new Date(Date.now() - this.timeWindow),
                end: new Date()
              },
              metadata: {},
              affectedEntities: usersWithExcessiveSIDHistory.slice(0, 5).map((user: any) => ({
                type: 'user',
                id: user.Properties.samaccountname,
                name: user.Properties.displayname || user.Properties.samaccountname
              }))
            })
          }

          // Check for privileged SIDs in history
          if (this.thresholds.flagPrivilegedSIDHistory > 0) {
            const privilegedSIDs = [
              'S-1-5-32-544', // Administrators
              'S-1-5-32-548', // Account Operators
              'S-1-5-32-549', // Server Operators
              'S-1-5-32-550', // Print Operators
              'S-1-5-32-551', // Backup Operators
              'S-1-5-32-552'  // Replicator
            ]

            const usersWithPrivilegedSIDHistory = usersWithSIDHistory.filter((user: any) =>
              user.Properties?.sidhistory?.some((sid: string) =>
                privilegedSIDs.some(privSID => sid.startsWith(privSID))
              )
            )

            if (usersWithPrivilegedSIDHistory.length > 0) {
              anomalies.push({
                id: `${this.id}-privileged-sid-history-${Date.now()}`,
                ruleId: this.id,
                ruleName: this.name,
                severity: 'high',
                category: 'privilege',
                title: 'Accounts with Privileged SID History',
                description: `Found ${usersWithPrivilegedSIDHistory.length} accounts with privileged SIDs in their history`,
                confidence: 85,
                evidence: {
                  count: usersWithPrivilegedSIDHistory.length,
                  privilegedSIDs: privilegedSIDs,
                  accounts: usersWithPrivilegedSIDHistory.map((user: any) => ({
                    name: user.Properties?.samaccountname,
                    domain: user.Properties?.domain,
                    sidHistory: user.Properties?.sidhistory,
                    privileged: user.Properties?.admincount === true
                  })).slice(0, 10)
                },
                recommendations: [
                  'Accounts with privileged SID history may retain old permissions',
                  'Review and clean up SID history for security',
                  'Consider if these accounts still need historical privileges',
                  'Monitor for privilege escalation using SID history'
                ],
                timestamp: new Date(),
                detectedAt: new Date(),
                timeWindow: {
                  start: new Date(Date.now() - this.timeWindow),
                  end: new Date()
                },
                metadata: {},
                affectedEntities: usersWithPrivilegedSIDHistory.slice(0, 5).map((user: any) => ({
                  type: 'user',
                  id: user.Properties.samaccountname,
                  name: user.Properties.displayname || user.Properties.samaccountname
                }))
              })
            }
          }

          // Check for cross-domain SID history
          if (this.thresholds.flagCrossDomainSIDHistory > 0 && sharpHoundData.domains) {
            const currentDomainSIDs = sharpHoundData.domains.map((domain: any) =>
              domain.Properties?.domainsid
            ).filter(Boolean)

            const usersWithCrossDomainSIDHistory = usersWithSIDHistory.filter((user: any) =>
              user.Properties?.sidhistory?.some((sid: string) => {
                // Check if SID belongs to a different domain
                return !currentDomainSIDs.some((domainSID: string) =>
                  sid.startsWith(domainSID)
                )
              })
            )

            if (usersWithCrossDomainSIDHistory.length > 0) {
              anomalies.push({
                id: `${this.id}-cross-domain-sid-history-${Date.now()}`,
                ruleId: this.id,
                ruleName: this.name,
                severity: 'medium',
                category: 'privilege',
                title: 'Accounts with Cross-Domain SID History',
                description: `Found ${usersWithCrossDomainSIDHistory.length} accounts with SID history from other domains`,
                confidence: 75,
                evidence: {
                  count: usersWithCrossDomainSIDHistory.length,
                  currentDomains: currentDomainSIDs,
                  accounts: usersWithCrossDomainSIDHistory.map((user: any) => ({
                    name: user.Properties?.samaccountname,
                    domain: user.Properties?.domain,
                    sidHistory: user.Properties?.sidhistory?.filter((sid: string) =>
                      !currentDomainSIDs.some((domainSID: string) => sid.startsWith(domainSID))
                    )
                  })).slice(0, 10)
                },
                recommendations: [
                  'Cross-domain SID history may indicate migrated accounts',
                  'Review permissions associated with historical SIDs',
                  'Ensure SID filtering is properly configured for trusts',
                  'Monitor for potential privilege escalation using old SIDs'
                ],
                timestamp: new Date(),
                detectedAt: new Date(),
                timeWindow: {
                  start: new Date(Date.now() - this.timeWindow),
                  end: new Date()
                },
                metadata: {},
                affectedEntities: usersWithCrossDomainSIDHistory.slice(0, 5).map((user: any) => ({
                  type: 'user',
                  id: user.Properties.samaccountname,
                  name: user.Properties.displayname || user.Properties.samaccountname
                }))
              })
            }
          }
        }

        // General SID history presence
        if (usersWithSIDHistory.length > 0) {
          const totalUsers = sharpHoundData.users.length
          const percentageWithSIDHistory = (usersWithSIDHistory.length / totalUsers * 100).toFixed(1)

          anomalies.push({
            id: `${this.id}-sid-history-overview-${Date.now()}`,
            ruleId: this.id,
            ruleName: this.name,
            severity: 'info',
            category: 'security',
            title: 'SID History Usage Overview',
            description: `${usersWithSIDHistory.length} accounts (${percentageWithSIDHistory}%) have SID history configured`,
            confidence: 60,
            evidence: {
              totalAccounts: totalUsers,
              accountsWithSIDHistory: usersWithSIDHistory.length,
              percentage: percentageWithSIDHistory,
              breakdown: usersWithSIDHistory.reduce((acc: any, user: any) => {
                const count = user.Properties?.sidhistory?.length || 0
                acc[count] = (acc[count] || 0) + 1
                return acc
              }, {})
            },
            recommendations: [
              'SID history is used for permission migration during domain operations',
              'Regular review of SID history is recommended for security',
              'Consider cleaning up unnecessary SID history entries',
              'Monitor for abuse of SID history in privilege escalation'
            ],
            timestamp: new Date(),
            detectedAt: new Date(),
            timeWindow: {
              start: new Date(Date.now() - this.timeWindow),
              end: new Date()
            },
            metadata: {},
            affectedEntities: [] // This is informational, not specific to accounts
          })
        }
      }
    }

    return anomalies
  }
}
