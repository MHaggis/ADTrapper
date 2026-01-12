import { AnalyticsRule, AuthEvent, AnalyticsContext, Anomaly } from '../types'

export class SharpHoundUserRightsAnalysisRule implements AnalyticsRule {
  readonly id = 'sharpHound-user-rights-analysis'
  readonly name = 'SharpHound User Rights Assignment Analysis'
  readonly description = 'Analyzes user rights assignments for privilege escalation risks'
  readonly severity = 'high'
  readonly category = 'privilege'
  readonly enabled = true
  readonly timeWindow = 24 * 60 * 60 * 1000 // 24 hours
  readonly version = '1.0.0'
  readonly author = 'ADTrapper'
  readonly created = new Date('2025-01-01')
  readonly updated = new Date('2025-01-01')

  readonly thresholds = {
    flagDangerousRights: 1,             // Flag dangerous user rights assignments
    maxUsersWithSeDebug: 5,             // Max users with SeDebugPrivilege
    maxUsersWithSeBackup: 10,           // Max users with SeBackupPrivilege
    flagDomainUsersWithAdminRights: 1   // Flag domain users with local admin rights
  }

  readonly detailedDescription = {
    overview: 'Analyzes user rights assignments for privilege escalation risks using SharpHound data. Identifies dangerous privilege assignments like SeDebugPrivilege, SeBackupPrivilege, and local administrator rights that can enable lateral movement and privilege escalation attacks.',
    detectionLogic: 'Analyzes SharpHound computer objects for dangerous ACE (Access Control Entry) assignments. Reviews local group memberships and privilege assignments. Identifies domain users with local administrator rights on computers, which enables Pass-the-Hash attacks and lateral movement.',
    falsePositives: 'Authorized administrators with legitimate need for elevated privileges, service accounts requiring specific user rights for application functionality, computers with approved exceptions for administrative access, and systems where elevated privileges are managed through approved change management processes.',
    mitigation: [
      'Remove domain users from local administrator groups on computers',
      'Use Group Policy Restricted Groups to control local admin membership',
      'Implement Just Enough Administration (JEA) for privileged access management',
      'Regularly audit and remove unnecessary user rights assignments',
      'Limit SeDebugPrivilege and SeBackupPrivilege to essential service accounts only',
      'Implement principle of least privilege for all user accounts',
      'Use centralized privilege management tools for access control',
      'Enable detailed auditing for privilege assignment changes',
      'Conduct regular privilege escalation risk assessments',
      'Implement automated privilege monitoring and alerting'
    ],
    windowsEvents: ['4672 (Special Privileges Assigned)', '4673 (Sensitive Privilege Use)', '4674 (Privileged Object Operation)', '4732 (Member Added to Local Group)', '4733 (Member Removed from Local Group)', '4904 (Security Event Source Registered)', '4905 (Security Event Source Unregistered)', '4907 (Auditing Settings on Object Changed)', '4908 (Special Registry Item Modified)'],
    exampleQuery: `index=windows EventCode=4672 | stats count by TargetUserName, PrivilegeList | where count > 5`,
    recommendedThresholds: {
      flagDangerousRights: 1,
      maxUsersWithSeDebug: 5,
      maxUsersWithSeBackup: 10,
      flagDomainUsersWithAdminRights: 1
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

    if (this.thresholds.flagDangerousRights > 0) {
      // Analyze computers for dangerous user rights assignments
      if (sharpHoundData.computers) {
        console.log(`🔍 Analyzing user rights on ${sharpHoundData.computers.length} computers`)

        // Find computers with dangerous local admin assignments
        if (this.thresholds.flagDomainUsersWithAdminRights > 0) {
          const computersWithDomainAdminRights = sharpHoundData.computers.filter((computer: any) => {
            // Check if domain users/groups have admin rights on this computer
            return computer.Aces && computer.Aces.some((ace: any) => {
              const rightName = ace.RightName?.toLowerCase() || ''
              return rightName.includes('admin') ||
                     rightName.includes('full control') ||
                     rightName.includes('genericall')
            })
          })

          if (computersWithDomainAdminRights.length > 0) {
            anomalies.push({
              id: `${this.id}-domain-users-admin-rights-${Date.now()}`,
              ruleId: this.id,
              ruleName: this.name,
              severity: 'high',
              category: 'privilege',
              title: 'Domain Users with Local Administrator Rights',
              description: `Found ${computersWithDomainAdminRights.length} computers where domain users have local admin rights`,
              confidence: 85,
              evidence: {
                count: computersWithDomainAdminRights.length,
                computers: computersWithDomainAdminRights.slice(0, 10).map((comp: any) => ({
                  name: comp.Properties?.samaccountname,
                  domain: comp.Properties?.domain,
                  aceCount: comp.Aces?.length || 0
                }))
              },
              recommendations: [
                'Domain users should not have local administrator rights on computers',
                'Use Group Policy Restricted Groups to control local admin membership',
                'Implement Just Enough Administration (JEA) for privileged access',
                'Regularly audit and remove unnecessary admin rights'
              ],
              timestamp: new Date(),
              detectedAt: new Date(),
              timeWindow: {
                start: new Date(Date.now() - this.timeWindow),
                end: new Date()
              },
              metadata: {},
              affectedEntities: computersWithDomainAdminRights.slice(0, 5).map((comp: any) => ({
                type: 'computer',
                id: comp.Properties.samaccountname,
                name: comp.Properties.samaccountname
              }))
            })
          }
        }

        // Analyze domain controllers specifically for dangerous rights
        const domainControllers = sharpHoundData.computers.filter((computer: any) =>
          computer.Properties?.isdc === true
        )

        if (domainControllers.length > 0) {
          const dcsWithDangerousRights = domainControllers.filter((dc: any) => {
            // Check for dangerous permissions on domain controllers
            return dc.Aces && dc.Aces.some((ace: any) => {
              const rightName = ace.RightName?.toLowerCase() || ''
              return rightName.includes('domain admin') ||
                     rightName.includes('enterprise admin') ||
                     rightName.includes('schema admin') ||
                     rightName.includes('full control') ||
                     rightName.includes('genericall')
            })
          })

          if (dcsWithDangerousRights.length > 0) {
            anomalies.push({
              id: `${this.id}-dc-dangerous-rights-${Date.now()}`,
              ruleId: this.id,
              ruleName: this.name,
              severity: 'critical',
              category: 'privilege',
              title: 'Domain Controllers with Dangerous Permissions',
              description: `Found ${dcsWithDangerousRights.length} domain controllers with overly permissive permissions`,
              confidence: 95,
              evidence: {
                count: dcsWithDangerousRights.length,
                domainControllers: dcsWithDangerousRights.map((dc: any) => ({
                  name: dc.Properties?.samaccountname,
                  dangerousAceCount: dc.Aces?.filter((ace: any) => {
                    const rightName = ace.RightName?.toLowerCase() || ''
                    return rightName.includes('admin') || rightName.includes('full control')
                  }).length || 0
                }))
              },
              recommendations: [
                'Domain controllers should have minimal permissions granted',
                'Remove unnecessary administrative permissions from domain controllers',
                'Use principle of least privilege for DC access',
                'Regular security audits of DC permissions are essential'
              ],
              timestamp: new Date(),
              detectedAt: new Date(),
              timeWindow: {
                start: new Date(Date.now() - this.timeWindow),
                end: new Date()
              },
              metadata: {},
              affectedEntities: dcsWithDangerousRights.map((dc: any) => ({
                type: 'computer',
                id: dc.Properties.samaccountname,
                name: dc.Properties.samaccountname
              }))
            })
          }
        }
      }

      // Analyze users for dangerous group memberships that grant user rights
      if (sharpHoundData.users) {
        // Find users in groups that typically have dangerous user rights
        const dangerousGroups = ['Backup Operators', 'Print Operators', 'Server Operators', 'Account Operators']

        const usersInDangerousGroups = sharpHoundData.users.filter((user: any) =>
          user.Properties?.memberof?.some((group: string) =>
            dangerousGroups.some(dg => group.toLowerCase().includes(dg.toLowerCase()))
          )
        )

        if (usersInDangerousGroups.length > 0) {
          anomalies.push({
            id: `${this.id}-users-dangerous-groups-${Date.now()}`,
            ruleId: this.id,
            ruleName: this.name,
            severity: 'medium',
            category: 'privilege',
            title: 'Users in Groups with Dangerous User Rights',
            description: `Found ${usersInDangerousGroups.length} users in groups that grant dangerous user rights`,
            confidence: 80,
            evidence: {
              count: usersInDangerousGroups.length,
              dangerousGroups: dangerousGroups,
              users: usersInDangerousGroups.slice(0, 10).map((user: any) => ({
                name: user.Properties?.samaccountname,
                domain: user.Properties?.domain,
                groups: user.Properties?.memberof?.filter((group: string) =>
                  dangerousGroups.some(dg => group.toLowerCase().includes(dg.toLowerCase()))
                )
              }))
            },
            recommendations: [
              'Review membership in privileged groups carefully',
              'Backup Operators, Print Operators, etc. grant dangerous user rights',
              'Limit membership to essential users only',
              'Consider using Just Enough Administration (JEA) instead'
            ],
            timestamp: new Date(),
            detectedAt: new Date(),
            timeWindow: {
              start: new Date(Date.now() - this.timeWindow),
              end: new Date()
            },
            metadata: {},
            affectedEntities: usersInDangerousGroups.slice(0, 5).map((user: any) => ({
              type: 'user',
              id: user.Properties.samaccountname,
              name: user.Properties.displayname || user.Properties.samaccountname
            }))
          })
        }
      }

      // Analyze group permissions for dangerous rights assignments
      if (sharpHoundData.groups) {
        const groupsWithDangerousRights = sharpHoundData.groups.filter((group: any) =>
          group.Aces && group.Aces.some((ace: any) => {
            const rightName = ace.RightName?.toLowerCase() || ''
            return rightName.includes('admin') ||
                   rightName.includes('backup') ||
                   rightName.includes('restore') ||
                   rightName.includes('debug') ||
                   rightName.includes('full control')
          })
        )

        if (groupsWithDangerousRights.length > 0) {
          anomalies.push({
            id: `${this.id}-groups-dangerous-rights-${Date.now()}`,
            ruleId: this.id,
            ruleName: this.name,
            severity: 'medium',
            category: 'privilege',
            title: 'Groups with Dangerous User Rights',
            description: `Found ${groupsWithDangerousRights.length} groups with dangerous user rights assigned`,
            confidence: 75,
            evidence: {
              count: groupsWithDangerousRights.length,
              groups: groupsWithDangerousRights.slice(0, 10).map((group: any) => ({
                name: group.Properties?.samaccountname,
                domain: group.Properties?.domain,
                dangerousAceCount: group.Aces?.filter((ace: any) => {
                  const rightName = ace.RightName?.toLowerCase() || ''
                  return rightName.includes('admin') || rightName.includes('backup')
                }).length || 0
              }))
            },
            recommendations: [
              'Review group permissions that grant dangerous user rights',
              'Use Group Policy to assign user rights instead of direct group permissions',
              'Audit and document all user rights assignments',
              'Remove unnecessary privileged group memberships'
            ],
            timestamp: new Date(),
            detectedAt: new Date(),
            timeWindow: {
              start: new Date(Date.now() - this.timeWindow),
              end: new Date()
            },
            metadata: {},
            affectedEntities: groupsWithDangerousRights.slice(0, 5).map((group: any) => ({
              type: 'user', // Using user type for groups
              id: group.Properties.samaccountname,
              name: group.Properties.samaccountname
            }))
          })
        }
      }
    }

    return anomalies
  }
}
