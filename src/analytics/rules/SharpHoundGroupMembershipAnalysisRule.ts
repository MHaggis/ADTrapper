import { AnalyticsRule, AuthEvent, AnalyticsContext, Anomaly } from '../types'

export class SharpHoundGroupMembershipAnalysisRule implements AnalyticsRule {
  readonly id = 'sharpHound-group-membership-analysis'
  readonly name = 'SharpHound Group Membership Analysis'
  readonly description = 'Analyzes group memberships for privilege escalation risks and misconfigurations'
  readonly severity = 'high'
  readonly category = 'privilege'
  readonly enabled = true
  readonly timeWindow = 24 * 60 * 60 * 1000 // 24 hours
  readonly version = '1.0.0'
  readonly author = 'ADTrapper'
  readonly created = new Date('2025-01-01')
  readonly updated = new Date('2025-01-01')

  readonly thresholds = {
    maxNestedGroupDepth: 5,           // Maximum nested group depth before flagging
    maxUsersInPrivilegedGroups: 20,   // Max users in Domain Admins
    flagEmptyGroups: 1,               // Flag empty groups (1 = true, 0 = false)
    flagBuiltinAdminGroups: 1         // Flag users directly in built-in admin groups
  }

  readonly detailedDescription = {
    overview: 'Analyzes group memberships for privilege escalation risks and misconfigurations using SharpHound data. Identifies large privileged groups, nested group structures, empty security groups, and users with direct membership in built-in administrative groups.',
    detectionLogic: 'Analyzes SharpHound group objects for membership patterns and privilege accumulation. Reviews Members arrays for group size analysis. Identifies nested group relationships and privilege escalation paths. Flags groups with excessive direct memberships and users directly added to privileged built-in groups.',
    falsePositives: 'Groups with approved large memberships for business requirements, nested group structures designed for role-based access control, empty groups maintained for future use, and administrative groups with documented exceptions for specific business needs.',
    mitigation: [
      'Implement role-based access control with smaller, focused groups',
      'Use nested group structures instead of direct privileged group membership',
      'Regularly review and clean up empty security groups',
      'Limit direct membership in built-in administrative groups',
      'Implement approval workflows for privileged group membership changes',
      'Use Group Managed Service Accounts (gMSA) for service accounts',
      'Regularly audit group memberships and privilege assignments',
      'Implement automated group membership management and lifecycle',
      'Conduct regular privilege escalation path analysis',
      'Enable detailed auditing for group membership changes'
    ],
    windowsEvents: ['4728 (Security Group Member Added)', '4729 (Security Group Member Removed)', '4732 (Member Added to Local Group)', '4733 (Member Removed from Local Group)', '4756 (Member Added to Universal Group)', '4757 (Member Removed from Universal Group)', '4761 (Member Added to Global Group)', '4762 (Member Removed from Global Group)', '5136 (Directory Service Object Modified)', '5137 (Directory Service Object Created)', '5139 (Directory Service Object Moved)', '5141 (Directory Service Object Deleted)'],
    exampleQuery: `index=windows EventCode=4728 OR EventCode=4729 | stats count by TargetUserName, TargetGroupName | where count > 3`,
    recommendedThresholds: {
      maxNestedGroupDepth: 5,
      maxUsersInPrivilegedGroups: 20,
      flagEmptyGroups: 1,
      flagBuiltinAdminGroups: 1
    }
  }

  validate(): { valid: boolean; errors: string[] } {
    if (this.thresholds.maxNestedGroupDepth < 1) {
      return { valid: false, errors: ['maxNestedGroupDepth must be at least 1'] }
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

    // Analyze group memberships and structures
    if (sharpHoundData.groups) {
      // Find privileged groups
      const privilegedGroups = sharpHoundData.groups.filter((group: any) => {
        const name = group.Properties?.samaccountname?.toLowerCase() || ''
        return name.includes('domain admins') ||
               name.includes('enterprise admins') ||
               name.includes('schema admins') ||
               name.includes('administrators') ||
               name.includes('account operators') ||
               name.includes('backup operators') ||
               name.includes('server operators') ||
               name.includes('print operators')
      })

      // Analyze privileged group memberships
      privilegedGroups.forEach((group: any) => {
        if (group.Members && Array.isArray(group.Members)) {
          const memberCount = group.Members.length

          // Flag groups with too many direct members
          if (memberCount > this.thresholds.maxUsersInPrivilegedGroups) {
            anomalies.push({
              id: `${this.id}-large-privileged-group-${group.Properties.samaccountname}-${Date.now()}`,
              ruleId: this.id,
              ruleName: this.name,
              severity: 'medium',
              category: 'privilege',
              title: 'Large Privileged Group Membership',
              description: `Privileged group ${group.Properties.samaccountname} has ${memberCount} direct members (threshold: ${this.thresholds.maxUsersInPrivilegedGroups})`,
              confidence: 75,
              evidence: {
                group: group.Properties.samaccountname,
                memberCount: memberCount,
                members: group.Members.slice(0, 10)
              },
              recommendations: ['Consider using role groups and limiting direct membership in privileged groups'],
              timestamp: new Date(),
              detectedAt: new Date(),
              timeWindow: {
                start: new Date(Date.now() - this.timeWindow),
                end: new Date()
              },
              metadata: {},
              affectedEntities: [{
                type: 'user', // Using user type for groups
                id: group.Properties.samaccountname,
                name: group.Properties.samaccountname
              }]
            })
          }

          // Flag users directly in built-in admin groups (bypassing role groups)
          if (this.thresholds.flagBuiltinAdminGroups > 0) {
            const builtinAdminPatterns = ['domain admins', 'enterprise admins', 'administrators']
            const isBuiltinAdminGroup = builtinAdminPatterns.some(pattern =>
              group.Properties?.samaccountname?.toLowerCase().includes(pattern)
            )

            if (isBuiltinAdminGroup && memberCount > 0) {
              anomalies.push({
                id: `${this.id}-builtin-admin-direct-members-${group.Properties.samaccountname}-${Date.now()}`,
                ruleId: this.id,
                ruleName: this.name,
                severity: 'low',
                category: 'privilege',
                title: 'Users Directly in Built-in Admin Groups',
                description: `Built-in admin group ${group.Properties.samaccountname} has ${memberCount} direct members`,
                confidence: 65,
                evidence: {
                  group: group.Properties.samaccountname,
                  memberCount: memberCount,
                  members: group.Members.slice(0, 10)
                },
                recommendations: ['Consider using role-based groups instead of direct membership in built-in admin groups'],
                timestamp: new Date(),
                detectedAt: new Date(),
                timeWindow: {
                  start: new Date(Date.now() - this.timeWindow),
                  end: new Date()
                },
                metadata: {},
                affectedEntities: [{
                  type: 'user',
                  id: group.Properties.samaccountname,
                  name: group.Properties.samaccountname
                }]
              })
            }
          }
        }
      })

      // Find empty groups
      if (this.thresholds.flagEmptyGroups > 0) {
        const emptyGroups = sharpHoundData.groups.filter((group: any) =>
          !group.Members || group.Members.length === 0
        )

        if (emptyGroups.length > 0) {
          anomalies.push({
            id: `${this.id}-empty-groups-${Date.now()}`,
            ruleId: this.id,
            ruleName: this.name,
            severity: 'info',
            category: 'security',
            title: 'Empty Security Groups Found',
            description: `Found ${emptyGroups.length} empty security groups that may need cleanup`,
            confidence: 50,
            evidence: {
              count: emptyGroups.length,
              groups: emptyGroups.map((g: any) => g.Properties?.samaccountname).slice(0, 20)
            },
            recommendations: ['Review and remove unused empty groups to reduce attack surface'],
            timestamp: new Date(),
            detectedAt: new Date(),
            timeWindow: {
              start: new Date(Date.now() - this.timeWindow),
              end: new Date()
            },
            metadata: {},
            affectedEntities: emptyGroups.slice(0, 5).map((g: any) => ({
              type: 'user', // Using user type for groups
              id: g.Properties.samaccountname,
              name: g.Properties.samaccountname
            }))
          })
        }
      }
    }

    // Analyze user group memberships for privilege escalation paths
    if (sharpHoundData.users) {
      sharpHoundData.users.forEach((user: any) => {
        if (user.Properties?.memberof && Array.isArray(user.Properties.memberof)) {
          const groupCount = user.Properties.memberof.length

          // Flag users with too many group memberships (potential for privilege accumulation)
          if (groupCount > 50) {
            anomalies.push({
              id: `${this.id}-user-many-groups-${user.Properties.samaccountname}-${Date.now()}`,
              ruleId: this.id,
              ruleName: this.name,
              severity: 'low',
              category: 'privilege',
              title: 'User with Excessive Group Memberships',
              description: `User ${user.Properties.samaccountname} is member of ${groupCount} groups`,
              confidence: 60,
              evidence: {
                user: user.Properties.samaccountname,
                groupCount: groupCount,
                groups: user.Properties.memberof.slice(0, 10)
              },
              recommendations: ['Review user group memberships and remove unnecessary privileges'],
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

          // Flag users in both privileged and unprivileged groups (potential lateral movement)
          const privilegedGroupNames = ['domain admins', 'enterprise admins', 'administrators', 'account operators']
          const hasPrivileged = user.Properties.memberof.some((group: string) =>
            privilegedGroupNames.some(priv => group.toLowerCase().includes(priv))
          )

          const unprivilegedGroupNames = ['domain users', 'users']
          const hasUnprivileged = user.Properties.memberof.some((group: string) =>
            unprivilegedGroupNames.some(unpriv => group.toLowerCase().includes(unpriv))
          )

          if (hasPrivileged && hasUnprivileged) {
            anomalies.push({
              id: `${this.id}-user-mixed-privileges-${user.Properties.samaccountname}-${Date.now()}`,
              ruleId: this.id,
              ruleName: this.name,
              severity: 'medium',
              category: 'privilege',
              title: 'User with Mixed Privilege Levels',
              description: `User ${user.Properties.samaccountname} has both privileged and standard group memberships`,
              confidence: 70,
              evidence: {
                user: user.Properties.samaccountname,
                privilegedGroups: user.Properties.memberof.filter((group: string) =>
                  privilegedGroupNames.some(priv => group.toLowerCase().includes(priv))
                ),
                standardGroups: user.Properties.memberof.filter((group: string) =>
                  unprivilegedGroupNames.some(unpriv => group.toLowerCase().includes(unpriv))
                )
              },
              recommendations: ['Consider separating administrative and standard user accounts'],
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
        }
      })
    }

    return anomalies
  }
}
