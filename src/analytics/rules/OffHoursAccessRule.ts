import { BaseRule } from '../BaseRule'
import { AuthEvent, Anomaly, AnalyticsContext } from '../types'

export class OffHoursAccessRule extends BaseRule {
  constructor() {
    super({
      id: 'off_hours_access_detection',
      name: 'Off-Hours Access Detection',
      description: 'Detects login activity outside normal business hours',
      category: 'temporal',
      severity: 'medium',
      timeWindow: 1440, // 24 hours
      thresholds: {
        businessHourStart: 7,  // 7 AM
        businessHourEnd: 19,   // 7 PM
        weekendAccess: 1,      // Flag any weekend access
        holidayAccess: 1,      // Flag any holiday access
        minimumOffHoursLogins: 3 // Minimum logins to trigger alert
      },
      version: '1.0.0',
      author: 'ADTrapper Security Team',
      detailedDescription: {
        overview: 'Detects authentication attempts outside normal business hours, including after-hours access, weekend activity, and holiday logins. Monitors for unusual timing patterns that may indicate unauthorized access, emergency access, or policy violations.',
        detectionLogic: 'Analyzes authentication events against configurable business hours (default 7 AM - 7 PM). Categorizes logins into business hours, after-hours, weekend, and holiday access. Calculates confidence based on access frequency, privileged account status, and consistency of off-hours patterns.',
        falsePositives: 'Emergency access during system outages, on-call work, global teams in different time zones, approved overtime work, system maintenance activities, or users with legitimate extended work hours. May also trigger for users who work irregular schedules.',
        mitigation: [
          'Define and enforce business hours policies',
          'Implement time-based access controls',
          'Require approval for off-hours access',
          'Monitor and audit all off-hours activity',
          'Set up alerts for privileged account off-hours access',
          'Implement multi-factor authentication for off-hours',
          'Configure session recording for off-hours activity',
          'Regular review of off-hours access patterns',
          'Implement emergency access procedures',
          'Use conditional access policies for time restrictions'
        ],
        windowsEvents: ['4624 (Successful Logon)', '4625 (Failed Logon)', '4648 (Explicit Credential Logon)', '4778 (Session Reconnect)', '4779 (Session Disconnect)'],
        exampleQuery: `index=windows EventCode=4624 | eval hour = strftime(_time, "%H") | where hour < 7 OR hour > 19 | stats count by TargetUserName, hour`,
        recommendedThresholds: {
          businessHourStart: 7,
          businessHourEnd: 19,
          weekendAccess: 1,
          holidayAccess: 1,
          minimumOffHoursLogins: 3
        }
      }
    })
  }

  // Common holidays (US-centric, but configurable)
  private readonly holidays = new Set([
    '01-01', // New Year's Day
    '07-04', // Independence Day
    '11-11', // Veterans Day
    '12-25', // Christmas
    // Add more holidays as needed
  ])

  private isBusinessHours(date: Date): boolean {
    const hour = date.getHours()
    return hour >= this.thresholds.businessHourStart && hour < this.thresholds.businessHourEnd
  }

  private isWeekend(date: Date): boolean {
    const day = date.getDay()
    return day === 0 || day === 6 // Sunday = 0, Saturday = 6
  }

  private isHoliday(date: Date): boolean {
    const monthDay = String(date.getMonth() + 1).padStart(2, '0') + '-' + 
                     String(date.getDate()).padStart(2, '0')
    return this.holidays.has(monthDay)
  }

  private getTimeCategory(date: Date): 'business_hours' | 'after_hours' | 'weekend' | 'holiday' {
    if (this.isHoliday(date)) return 'holiday'
    if (this.isWeekend(date)) return 'weekend'
    if (this.isBusinessHours(date)) return 'business_hours'
    return 'after_hours'
  }

  async analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = []
    const recentEvents = this.filterByTimeWindow(events)
    const successfulLogins = recentEvents.filter(event => event.status === 'Success')

    // Group by user
    const loginsByUser = this.groupBy(successfulLogins, event => 
      `${event.userName}@${event.domainName || 'unknown'}`
    )

    Object.entries(loginsByUser).forEach(([userKey, userLogins]) => {
      const userName = userLogins[0].userName
      if (!userName) return

      // Get user profile to check normal hours (if available)
      const userProfile = context.userProfiles?.find(p => 
        p.userName === userName && p.domain === (userLogins[0].domainName || '')
      )

      // Categorize logins by time
      const loginsByCategory = {
        business_hours: [] as AuthEvent[],
        after_hours: [] as AuthEvent[],
        weekend: [] as AuthEvent[],
        holiday: [] as AuthEvent[]
      }

      userLogins.forEach(login => {
        const category = this.getTimeCategory(login.timestamp)
        loginsByCategory[category].push(login)
      })

      // Check for off-hours activity
      const offHoursLogins = [
        ...loginsByCategory.after_hours,
        ...loginsByCategory.weekend,
        ...loginsByCategory.holiday
      ]

      if (offHoursLogins.length >= this.thresholds.minimumOffHoursLogins) {
        let confidence = 50

        // Increase confidence based on various factors
        if (loginsByCategory.holiday.length > 0) confidence += 20
        if (loginsByCategory.weekend.length > 0) confidence += 15
        if (loginsByCategory.after_hours.length > 5) confidence += 15

        // Check if user has privileged access (higher risk)
        if (userProfile?.privileged) confidence += 20

        // Check for unusual time patterns
        const lateNightLogins = offHoursLogins.filter(login => {
          const hour = login.timestamp.getHours()
          return hour >= 22 || hour <= 5 // 10 PM to 5 AM
        })
        if (lateNightLogins.length > 0) confidence += 10

        // Check for consistency (multiple days of off-hours access)
        const offHoursDays = new Set(offHoursLogins.map(login => 
          login.timestamp.toDateString()
        ))
        if (offHoursDays.size > 1) confidence += 10

        const anomaly = this.createAnomaly(
          userProfile?.privileged ? 'Privileged User Off-Hours Access' : 'Off-Hours Access Detected',
          `User ${userName} logged in ${offHoursLogins.length} times outside business hours` + 
          (loginsByCategory.holiday.length > 0 ? ` (including ${loginsByCategory.holiday.length} holiday logins)` : '') +
          (loginsByCategory.weekend.length > 0 ? ` (including ${loginsByCategory.weekend.length} weekend logins)` : ''),
          {
            userName,
            domain: userLogins[0].domainName,
            isPrivileged: userProfile?.privileged || false,
            department: userProfile?.department,
            totalOffHoursLogins: offHoursLogins.length,
            afterHoursLogins: loginsByCategory.after_hours.length,
            weekendLogins: loginsByCategory.weekend.length,
            holidayLogins: loginsByCategory.holiday.length,
            lateNightLogins: lateNightLogins.length,
            offHoursDays: offHoursDays.size,
            timeBreakdown: {
              businessHours: loginsByCategory.business_hours.length,
              afterHours: loginsByCategory.after_hours.length,
              weekend: loginsByCategory.weekend.length,
              holiday: loginsByCategory.holiday.length
            },
            loginDetails: offHoursLogins.map(login => ({
              timestamp: login.timestamp,
              hour: login.timestamp.getHours(),
              day: login.timestamp.toLocaleDateString('en-US', { weekday: 'long' }),
              category: this.getTimeCategory(login.timestamp),
              computer: login.computerName,
              sourceIp: login.sourceIp
            })),
            computers: Array.from(new Set(offHoursLogins.map(login => login.computerName).filter((c): c is string => c !== undefined))),
            sourceIps: Array.from(new Set(offHoursLogins.map(login => login.sourceIp).filter((ip): ip is string => ip !== undefined)))
          },
          confidence
        )

        anomalies.push(anomaly)
      }

      // Special check for unusual time patterns (e.g., user suddenly changing their login times)
      if (userProfile?.normalLoginHours && userLogins.length >= 5) {
        const normalStart = userProfile.normalLoginHours.start
        const normalEnd = userProfile.normalLoginHours.end

        const unusualTimeLogins = userLogins.filter(login => {
          const hour = login.timestamp.getHours()
          return hour < normalStart || hour > normalEnd
        })

        if (unusualTimeLogins.length >= 3 && unusualTimeLogins.length / userLogins.length > 0.5) {
          const anomaly = this.createAnomaly(
            'Unusual Login Time Pattern',
            `User ${userName} logged in ${unusualTimeLogins.length} times outside their normal hours (${normalStart}:00-${normalEnd}:00)`,
            {
              userName,
              domain: userLogins[0].domainName,
              normalHours: userProfile.normalLoginHours,
              unusualLogins: unusualTimeLogins.length,
              totalLogins: userLogins.length,
              percentageUnusual: Math.round((unusualTimeLogins.length / userLogins.length) * 100),
              unusualLoginTimes: unusualTimeLogins.map(login => ({
                timestamp: login.timestamp,
                hour: login.timestamp.getHours()
              }))
            },
            70
          )

          anomalies.push(anomaly)
        }
      }
    })

    return anomalies
  }
}
