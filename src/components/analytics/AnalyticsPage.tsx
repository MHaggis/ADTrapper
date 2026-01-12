'use client'

import React, { useState, useEffect } from 'react'
import { Brain, Target, MapPin, Shield, Clock, Sparkles, Info, X, Eye, Settings, AlertTriangle, TrendingUp } from 'lucide-react'
import { useAnalytics } from '@/hooks/useAnalytics'
import RuleConfigurationModal from './RuleConfigurationModal'

interface AnalyticsPageProps {
  anomalies: any[]
  cardClasses: string
  darkMode: boolean
}

interface RuleDetailsModalProps {
  rule: any
  isOpen: boolean
  onClose: () => void
  onConfigure?: (rule: any) => void
  darkMode: boolean
}

const RuleDetailsModal: React.FC<RuleDetailsModalProps> = ({ rule, isOpen, onClose, onConfigure, darkMode }) => {
  if (!isOpen || !rule) return null

  // Extended rule information with queries and detailed descriptions
  const getRuleDetails = (ruleId: string) => {
    const ruleDetails: Record<string, any> = {
      'brute_force_detection': {
        title: 'Brute Force Attack Detection',
        description: 'Detects potential brute force attacks based on multiple failed login attempts from the same source',
        detectionLogic: 'Monitors for patterns of repeated authentication failures within short time windows',
        falsePositives: 'May trigger on legitimate password recovery attempts or misconfigured applications',
        recommendedThresholds: {
          failedAttempts: 5,
          timeWindowMinutes: 10,
          uniqueSourceIps: 1
        },
        splunkQuery: '`wineventlog_security` EventCode=4625 | bucket span=5m _time | stats dc(TargetUserName) AS unique_accounts, values(TargetUserName) as tried_accounts by _time, IpAddress | where unique_accounts > 5',
        windowsEvents: ['4625 (Failed Logon)', '4624 (Successful Logon)'],
        mitigation: [
          'Implement account lockout policies',
          'Enable multi-factor authentication',
          'Monitor for unusual login patterns',
          'Use CAPTCHAs for repeated failures'
        ]
      },
      'geographic_anomaly_detection': {
        title: 'Geographic Anomaly Detection',
        description: 'Detects suspicious login patterns based on geographic locations and impossible travel scenarios',
        detectionLogic: 'Analyzes login locations and calculates travel feasibility between login attempts',
        falsePositives: 'VPN usage, mobile roaming, or legitimate travel may trigger false positives',
        recommendedThresholds: {
          maxCountries: 3,
          maxCitiesPerCountry: 5,
          impossibleTravelTimeHours: 2
        },
        splunkQuery: '`wineventlog_security` EventCode=4624 | iplocation IpAddress | stats values(Country) as countries, values(City) as cities by TargetUserName | where mvcount(countries) > 3',
        windowsEvents: ['4624 (Successful Logon)', '4648 (Explicit Credential Logon)'],
        mitigation: [
          'Implement location-based authentication policies',
          'Require additional verification for new locations',
          'Monitor for VPN usage patterns',
          'Set up geographic restrictions for high-risk accounts'
        ]
      },
      'off_hours_access_detection': {
        title: 'Off-Hours Access Detection',
        description: 'Monitors authentication attempts outside normal business hours',
        detectionLogic: 'Compares login timestamps against configured business hours and weekend policies',
        falsePositives: 'Emergency access, on-call work, or global teams may appear as false positives',
        recommendedThresholds: {
          businessHourStart: 8,
          businessHourEnd: 18,
          weekendAccess: 1,
          holidayAccess: 1
        },
        splunkQuery: '`wineventlog_security` EventCode=4624 | eval hour = strftime(_time, "%H") | where hour < 8 OR hour > 18 | stats count by TargetUserName, hour',
        windowsEvents: ['4624 (Successful Logon)', '4634 (Logoff)'],
        mitigation: [
          'Define and enforce business hours policies',
          'Implement time-based access controls',
          'Require approval for off-hours access',
          'Monitor and audit all off-hours activity'
        ]
      },
      'privileged_access_monitoring': {
        title: 'Privileged Access Monitoring',
        description: 'Monitors and detects suspicious privileged account activity and escalation attempts',
        detectionLogic: 'Tracks privileged account usage patterns and detects anomalous behavior',
        falsePositives: 'Legitimate administrative tasks may trigger monitoring',
        recommendedThresholds: {
          maxPrivilegedLogins: 5,
          maxTargetSystems: 3,
          dormantAccountDays: 30
        },
        splunkQuery: '`wineventlog_security` EventCode=4624 TargetUserName IN ("Administrator", "Domain Admins") | stats count by TargetUserName, Computer | where count > 10',
        windowsEvents: ['4624 (Successful Logon)', '4672 (Admin Logon)', '4742 (Computer Account Changed)'],
        mitigation: [
          'Implement just-in-time access controls',
          'Use separate admin accounts (not daily use accounts)',
          'Monitor privileged account usage patterns',
          'Implement session recording for privileged access'
        ]
      },
      'multiple_failures': {
        title: 'Multiple Authentication Failures',
        description: 'Detects multiple failed authentication attempts that could indicate brute force attacks or account compromise attempts',
        detectionLogic: 'Monitors clusters of failed authentication attempts within time windows',
        falsePositives: 'Password recovery, forgotten passwords, or application errors',
        recommendedThresholds: {
          failureCountThreshold: 5,
          timeWindowMinutes: 30,
          lockoutThreshold: 10
        },
        splunkQuery: '`wineventlog_security` EventCode=4625 | bucket span=30m _time | stats count by TargetUserName, IpAddress | where count > 5',
        windowsEvents: ['4625 (Failed Logon)', '4771 (Kerberos Pre-auth Failed)', '4776 (NTLM Auth Failed)'],
        mitigation: [
          'Implement progressive delays after failed attempts',
          'Enable account lockout policies',
          'Monitor for password spraying campaigns',
          'Implement anomaly detection for authentication patterns'
        ]
      },
      'unusual_logon': {
        title: 'Unusual Logon Patterns',
        description: 'Detects abnormal authentication patterns including impossible travel, concurrent sessions, and unusual timing',
        detectionLogic: 'Analyzes login patterns for anomalies using statistical methods and behavioral analysis',
        falsePositives: 'VPN usage, shared accounts, or legitimate concurrent access',
        recommendedThresholds: {
          impossibleTravelKmH: 800,
          concurrentSessionMinutes: 5,
          unusualHourThreshold: 0.1
        },
        splunkQuery: '`wineventlog_security` EventCode=4624 | stats count by TargetUserName, IpAddress | eventstats avg(count) as avg by TargetUserName | where count > avg * 2',
        windowsEvents: ['4624 (Successful Logon)', '4648 (Explicit Credential Logon)', '4778 (Session Reconnect)'],
        mitigation: [
          'Implement behavioral analytics for authentication',
          'Monitor for impossible travel scenarios',
          'Limit concurrent sessions per user',
          'Use risk-based authentication'
        ]
      },
      'user_activity': {
        title: 'User Authentication Activity',
        description: 'Tracks user authentication patterns and provides insights into login behavior',
        detectionLogic: 'Analyzes user login patterns, frequency, and consistency over time',
        falsePositives: 'Normal variations in user behavior',
        recommendedThresholds: {
          activityMonitoringPeriod: 30,
          unusualPatternThreshold: 0.2
        },
        splunkQuery: '`wineventlog_security` EventCode=4624 | stats count by TargetUserName, date_mday | eventstats avg(count) as avg by TargetUserName | eval deviation = abs(count - avg)',
        windowsEvents: ['4624 (Successful Logon)', '4634 (Logoff)', '4647 (User Logoff)'],
        mitigation: [
          'Establish baseline user behavior patterns',
          'Monitor for deviations from normal patterns',
          'Implement user behavior analytics',
          'Regular security awareness training'
        ]
      },
      'password_change': {
        title: 'Password Change Activity',
        description: 'Detects password changes and account management activities',
        detectionLogic: 'Monitors password change events and related account modifications',
        falsePositives: 'Legitimate password changes and resets',
        recommendedThresholds: {
          failedToSuccessGapMin: 1,
          failedToSuccessGapMax: 60,
          rapidActivityThreshold: 5
        },
        splunkQuery: '`wineventlog_security` EventCode=4723 OR EventCode=4724 | stats count by TargetUserName | where count > 1',
        windowsEvents: ['4723 (Password Change)', '4724 (Password Reset)', '4738 (User Changed)'],
        mitigation: [
          'Monitor password change frequency',
          'Implement password complexity requirements',
          'Require multi-factor authentication for password changes',
          'Audit password change events'
        ]
      },
      'ntlm_authentication_failures': {
        title: 'NTLM Authentication Failures',
        description: 'Detects multiple invalid users failing NTLM authentication from the same source',
        detectionLogic: 'Monitors NTLM authentication failures for patterns indicating enumeration or brute force attacks',
        falsePositives: 'Legacy application compatibility issues, misconfigured clients',
        recommendedThresholds: {
          uniqueAccountsThreshold: 30,
          invalidUserStatus: '0xc0000064',
          wrongPasswordStatus: '0xC000006A'
        },
        splunkQuery: '`wineventlog_security` EventCode=4776 TargetUserName!=*$ Status=0xc0000064 | bucket span=5m _time | stats dc(TargetUserName) AS unique_accounts by _time, Workstation | where unique_accounts > 30',
        windowsEvents: ['4776 (NTLM Authentication)'],
        mitigation: [
          'Disable NTLM where possible (prefer Kerberos)',
          'Implement NTLM auditing and blocking policies',
          'Monitor for NTLM relay attacks',
          'Upgrade legacy applications to use modern authentication'
        ]
      },
      'kerberos_authentication_failures': {
        title: 'Kerberos Authentication Failures',
        description: 'Detects unusual patterns of Kerberos authentication failures',
        detectionLogic: 'Analyzes Kerberos pre-authentication failures using statistical methods',
        falsePositives: 'Clock skew, expired tickets, or network issues',
        recommendedThresholds: {
          uniqueAccountsThreshold: 30,
          statisticalThreshold: 10,
          outlierMultiplier: 3
        },
        splunkQuery: '`wineventlog_security` EventCode=4771 TargetUserName!="$*" Status=0x18 | bucket span=5m _time | stats dc(TargetUserName) AS unique_accounts by _time, IpAddress | where unique_accounts > 10',
        windowsEvents: ['4771 (Kerberos Pre-auth Failed)', '4768 (Kerberos TGT Requested)', '4772 (Kerberos TGT Failed)'],
        mitigation: [
          'Ensure proper time synchronization across domain',
          'Monitor for Kerberos ticket attacks (Golden/Silver tickets)',
          'Implement Kerberos armoring',
          'Regular password policy enforcement'
        ]
      },
      'password_spray_detection': {
        title: 'Password Spray Attack Detection',
        description: 'Detects password spray attacks where one password is tried against multiple accounts',
        detectionLogic: 'Identifies low success rate authentication attempts across multiple accounts',
        falsePositives: 'Shared passwords or password synchronization issues',
        recommendedThresholds: {
          minTargetUsers: 10,
          successToFailureRatio: 0.25,
          minTotalAttempts: 20
        },
        splunkQuery: '| tstats `security_content_summariesonly` max(_time) as lastTime, min(_time) as firstTime, values(Authentication.user_category) as user_category by Authentication.action, Authentication.src, Authentication.user | where action="failure" | stats dc(user) as user_count, count as failure_count by src | where user_count > 10 AND failure_count > 50',
        windowsEvents: ['4624 (Successful Logon)', '4625 (Failed Logon)'],
        mitigation: [
          'Implement account lockout policies',
          'Enable multi-factor authentication',
          'Monitor for low-and-slow attack patterns',
          'Implement behavioral analytics'
        ]
      },
      'rdp_activity_monitoring': {
        title: 'RDP Activity Monitoring',
        description: 'Monitors Remote Desktop Protocol authentication events and patterns',
        detectionLogic: 'Analyzes RDP login patterns, geographic distribution, and session behavior',
        falsePositives: 'Legitimate remote work or technical support access',
        recommendedThresholds: {
          rdpLogonType: 10,
          suspiciousRDPSources: 1,
          multipleRDPSessions: 3
        },
        splunkQuery: '`wineventlog_security` EventCode=4624 LogonType=10 | stats count by IpAddress, TargetUserName | where count > 5',
        windowsEvents: ['4624 (Successful Logon with LogonType=10)', '4634 (Logoff)', '4778 (Session Reconnect)'],
        mitigation: [
          'Implement network-level authentication (NLA) for RDP',
          'Restrict RDP access to authorized IP ranges',
          'Enable RDP session recording and monitoring',
          'Use VPN for remote access instead of direct RDP'
        ]
      },
      'explicit_credentials_monitoring': {
        title: 'Explicit Credentials Usage',
        description: 'Monitors RunAs/explicit credential usage patterns',
        detectionLogic: 'Tracks explicit credential usage and identifies privilege escalation attempts',
        falsePositives: 'Legitimate administrative tasks using RunAs',
        recommendedThresholds: {
          uniqueTargetsThreshold: 30,
          minExplicitCredEvents: 5
        },
        splunkQuery: '`wineventlog_security` EventCode=4648 | bucket span=5m _time | stats dc(TargetUserName) AS unique_accounts by _time, Caller_User_Name | where unique_accounts > 30',
        windowsEvents: ['4648 (Explicit Credential Logon)'],
        mitigation: [
          'Monitor and audit explicit credential usage',
          'Implement least privilege principles',
          'Use dedicated service accounts for applications',
          'Regular review of explicit credential permissions'
        ]
      },
      'local_admin_credential_stuffing': {
        title: 'Local Administrator Credential Stuffing',
        description: 'Detects credential stuffing attacks targeting local administrator accounts',
        detectionLogic: 'Monitors authentication attempts against administrator accounts for stuffing patterns',
        falsePositives: 'Legitimate administrative access or management tools',
        recommendedThresholds: {
          uniqueTargetsThreshold: 30,
          minFailedAttempts: 10
        },
        splunkQuery: '`wineventlog_security` EventCode=4625 TargetUserName=Administrator | bucket span=5m _time | stats dc(Computer) AS unique_targets by _time, IpAddress | where unique_targets > 30',
        windowsEvents: ['4624 (Successful Logon)', '4625 (Failed Logon)'],
        mitigation: [
          'Rename default administrator accounts',
          'Disable local administrator accounts where possible',
          'Implement LAPS (Local Administrator Password Solution)',
          'Monitor for lateral movement patterns'
        ]
      },
      'anonymous_account_monitoring': {
        title: 'Anonymous Account Usage',
        description: 'Detects suspicious usage of anonymous or null session accounts',
        detectionLogic: 'Monitors anonymous account access patterns and reconnaissance activity',
        falsePositives: 'Legitimate anonymous access to public shares',
        recommendedThresholds: {
          anonymousLogonType: 3,
          suspiciousAnonymousEvents: 5,
          nullSessionUsername: 'ANONYMOUS LOGON'
        },
        splunkQuery: '`wineventlog_security` EventCode=4624 TargetUserName="ANONYMOUS LOGON" | stats count by IpAddress, Computer | where count > 10',
        windowsEvents: ['4624 (Successful Logon)', '4742 (Computer Account Changed)'],
        mitigation: [
          'Restrict anonymous access to necessary resources only',
          'Disable null session enumeration',
          'Monitor for reconnaissance patterns',
          'Implement network segmentation'
        ]
      }
    }

    return ruleDetails[ruleId] || {
      title: rule.name,
      description: rule.description,
      detectionLogic: typeof rule.detailedDescription === 'object' && rule.detailedDescription.detectionLogic
        ? rule.detailedDescription.detectionLogic
        : 'Advanced pattern recognition and anomaly detection',
      falsePositives: typeof rule.detailedDescription === 'object' && rule.detailedDescription.falsePositives
        ? rule.detailedDescription.falsePositives
        : 'May occur during legitimate system operations',
      recommendedThresholds: typeof rule.detailedDescription === 'object' && rule.detailedDescription.recommendedThresholds
        ? rule.detailedDescription.recommendedThresholds
        : {},
      splunkQuery: typeof rule.detailedDescription === 'object' && rule.detailedDescription.exampleQuery
        ? rule.detailedDescription.exampleQuery
        : 'Custom query based on rule configuration',
      windowsEvents: typeof rule.detailedDescription === 'object' && rule.detailedDescription.windowsEvents
        ? rule.detailedDescription.windowsEvents
        : ['4624', '4625', '4634'],
      mitigation: typeof rule.detailedDescription === 'object' && rule.detailedDescription.mitigation
        ? rule.detailedDescription.mitigation
        : ['Monitor system logs', 'Review security policies', 'Implement additional controls'],
      overview: typeof rule.detailedDescription === 'object' && rule.detailedDescription.overview
        ? rule.detailedDescription.overview
        : rule.description
    }
  }

  const ruleDetails = getRuleDetails(rule.id)

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className={`bg-white dark:bg-gray-800 rounded-2xl shadow-2xl max-w-4xl w-full max-h-[90vh] overflow-hidden ${darkMode ? 'dark' : ''}`}>
        {/* Modal Header */}
        <div className="p-6 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className={`w-12 h-12 rounded-lg flex items-center justify-center ${
                rule.severity === 'critical' ? 'bg-red-500/20 text-red-600' :
                rule.severity === 'high' ? 'bg-orange-500/20 text-orange-600' :
                rule.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-600' :
                'bg-blue-500/20 text-blue-600'
              }`}>
                {rule.category === 'authentication' ? <Target size={24} /> :
                 rule.category === 'behavior' ? <MapPin size={24} /> :
                 rule.category === 'privilege' ? <Shield size={24} /> :
                 rule.category === 'temporal' ? <Clock size={24} /> :
                 <Sparkles size={24} />}
              </div>
              <div>
                <h2
                  className="text-xl font-bold text-gray-900 dark:text-gray-100 cursor-pointer hover:text-blue-600 transition-colors"
                  onClick={() => {
                    onClose(); // Close the details modal
                    if (onConfigure) {
                      onConfigure(rule); // Open the configuration modal
                    }
                  }}
                >
                  {ruleDetails.title}
                </h2>
                <div className="flex items-center gap-2 mt-1">
                  <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                    rule.severity === 'critical' ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400' :
                    rule.severity === 'high' ? 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400' :
                    rule.severity === 'medium' ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400' :
                    'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400'
                  }`}>
                    {rule.severity.toUpperCase()}
                  </span>
                  <span className="text-sm text-gray-500">Category: {rule.category}</span>
                  <span className="text-sm text-gray-400">•</span>
                  <span className="text-sm text-gray-500">v{rule.version}</span>
                </div>
              </div>
            </div>
            <button
              onClick={onClose}
              className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
            >
              <X size={24} />
            </button>
          </div>
        </div>

        {/* Modal Content */}
        <div className="p-6 overflow-y-auto max-h-[calc(90vh-140px)]">
          <div className="space-y-6">
            {/* Overview */}
            <div>
              <h3 className="text-sm font-medium text-gray-500 uppercase tracking-wide mb-2">Overview</h3>
              <p className="text-gray-700 dark:text-gray-300 leading-relaxed">{ruleDetails.overview}</p>
            </div>

            {/* Detection Logic */}
            <div>
              <h3 className="text-sm font-medium text-gray-500 uppercase tracking-wide mb-2">Detection Logic</h3>
              <p className="text-gray-700 dark:text-gray-300 leading-relaxed">{ruleDetails.detectionLogic}</p>
            </div>

            {/* Recommended Thresholds */}
            {Object.keys(ruleDetails.recommendedThresholds).length > 0 && (
              <div>
                <h3 className="text-sm font-medium text-gray-500 uppercase tracking-wide mb-2">Recommended Thresholds</h3>
                <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
                  <div className="grid md:grid-cols-2 gap-4">
                                        {Object.entries(ruleDetails.recommendedThresholds).map(([key, value]) => (
                      <div key={key}>
                        <span className="text-sm text-gray-500 capitalize">{key.replace(/([A-Z])/g, ' $1').trim()}:</span>
                        <p className="font-medium text-gray-900 dark:text-gray-100">{String(value)}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* Windows Events */}
            <div>
              <h3 className="text-sm font-medium text-gray-500 uppercase tracking-wide mb-2">Windows Events Monitored</h3>
              <div className="flex flex-wrap gap-2">
                {ruleDetails.windowsEvents.map((event: string, index: number) => (
                  <span key={index} className="px-3 py-1 bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400 rounded-full text-sm">
                    {event}
                  </span>
                ))}
              </div>
            </div>

            {/* Splunk Query */}
            <div>
              <h3 className="text-sm font-medium text-gray-500 uppercase tracking-wide mb-2">Example Query</h3>
              <div className="bg-gray-900 text-gray-100 p-4 rounded-lg overflow-x-auto">
                <pre className="text-sm font-mono">{ruleDetails.splunkQuery}</pre>
              </div>
            </div>

            {/* False Positives */}
            <div>
              <h3 className="text-sm font-medium text-gray-500 uppercase tracking-wide mb-2">Potential False Positives</h3>
              <div className="bg-yellow-50 dark:bg-yellow-900/20 p-4 rounded-lg">
                <p className="text-yellow-800 dark:text-yellow-200">{ruleDetails.falsePositives}</p>
              </div>
            </div>

            {/* Mitigation Strategies */}
            <div>
              <h3 className="text-sm font-medium text-gray-500 uppercase tracking-wide mb-2">Mitigation Strategies</h3>
              <ul className="space-y-2">
                {ruleDetails.mitigation.map((strategy: string, index: number) => (
                  <li key={index} className="flex items-start gap-3">
                    <span className="text-green-500 mt-1">•</span>
                    <span className="text-gray-700 dark:text-gray-300">{strategy}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="p-6 border-t border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700">
          <div className="flex justify-end gap-3">
            <button
              onClick={onClose}
              className="px-4 py-2 text-gray-600 dark:text-gray-300 hover:text-gray-800 dark:hover:text-gray-100 transition-colors"
            >
              Close
            </button>
            <button
              onClick={() => {
                onClose(); // Close the details modal
                if (onConfigure) {
                  onConfigure(rule); // Open the configuration modal
                }
              }}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors flex items-center gap-2"
            >
              <Settings size={16} />
              Configure Rule
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

const AnalyticsPage: React.FC<AnalyticsPageProps> = ({
  anomalies,
  cardClasses,
  darkMode
}) => {
  const { userRuleConfigs, getStatistics, loadUserRuleConfigs } = useAnalytics()
  const [selectedRule, setSelectedRule] = useState<any>(null)
  const [ruleToConfigure, setRuleToConfigure] = useState<any>(null)
  const [isLoadingConfigs, setIsLoadingConfigs] = useState(true)

  const stats = getStatistics()
  const rules = userRuleConfigs.length > 0 ? userRuleConfigs : []

  // Load user rule configurations when component mounts
  useEffect(() => {
    const loadConfigs = async () => {
      setIsLoadingConfigs(true)
      try {
        await loadUserRuleConfigs()
      } catch (error) {
        console.error('Failed to load user rule configs:', error)
      } finally {
        setIsLoadingConfigs(false)
      }
    }

    loadConfigs()
  }, [loadUserRuleConfigs]) // Re-run when loadUserRuleConfigs function changes

  const handleRuleConfigSave = async (config: any) => {
    // Reload user configurations after saving
    await loadUserRuleConfigs()
  }

  return (
    <div className="max-w-6xl mx-auto">
      {/* Header */}
      <div className="mb-6">
        <h2 className="text-2xl font-bold mb-2 flex items-center gap-3">
          <Brain className="w-8 h-8 text-purple-500" />
          Analytics Engine
        </h2>
        <p className="text-gray-500">Rule-based security analysis with configurable detection engines</p>
      </div>

      {/* Analytics Engine Stats */}
      <div className={`${cardClasses} p-6 rounded-xl shadow-lg mb-6`}>
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <TrendingUp size={20} />
          Detection Engine Status
        </h3>
        <div className="grid md:grid-cols-4 gap-4">
          <div className="text-center">
            <div className="text-2xl font-bold text-blue-500">{stats.totalRules}</div>
            <div className="text-sm text-gray-500">Total Rules</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-green-500">{stats.enabledRules}</div>
            <div className="text-sm text-gray-500">Active Rules</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-purple-500">{Object.keys(stats.rulesByCategory).length}</div>
            <div className="text-sm text-gray-500">Categories</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-orange-500">{anomalies.length}</div>
            <div className="text-sm text-gray-500">Total Anomalies</div>
          </div>
        </div>
      </div>

      {/* Rule Categories Overview */}
      <div className={`${cardClasses} p-6 rounded-xl shadow-lg mb-6`}>
        <h3 className="text-lg font-semibold mb-4">Rule Categories</h3>
        <div className="grid md:grid-cols-3 lg:grid-cols-4 gap-4">
          {Object.entries(stats.rulesByCategory).map(([category, count]) => (
            <div key={category} className="bg-gray-50 dark:bg-gray-700 p-4 rounded-lg">
              <div className="text-xl font-bold text-blue-500">{count}</div>
              <div className="text-sm text-gray-500 capitalize">{category}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Available Detection Rules */}
      <div className={`${cardClasses} p-6 rounded-xl shadow-lg`}>
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <Shield size={20} />
          Available Detection Rules
        </h3>
        <p className="text-gray-500 mb-6">
          Click on any rule to view detailed information, configuration options, and detection logic.
        </p>
        {isLoadingConfigs ? (
          <div className="flex items-center justify-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
            <span className="ml-3 text-gray-600">Loading analytics rules...</span>
          </div>
        ) : rules.length === 0 ? (
          <div className={`${cardClasses} p-8 rounded-xl shadow-lg text-center`}>
            <Brain className="w-16 h-16 mx-auto text-gray-400 mb-4" />
            <h3 className="text-xl font-semibold mb-2">No Analytics Rules Found</h3>
            <p className="text-gray-500 mb-4">
              Unable to load analytics rules. Please try refreshing the page or contact support if the issue persists.
            </p>
            <button
              onClick={() => window.location.reload()}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
            >
              Refresh Page
            </button>
          </div>
        ) : (
          <div className="grid md:grid-cols-2 gap-4">
            {rules.map(rule => (
            <div
              key={rule.id}
              className="p-4 border border-gray-200 dark:border-gray-700 rounded-lg hover:shadow-md transition-all group"
            >
              <div className="flex items-start justify-between mb-2">
                <div className="flex items-center gap-2">
                  <div className={`w-3 h-3 rounded-full ${rule.enabled ? 'bg-green-500' : 'bg-gray-400'}`}></div>
                  <h4
                    className="font-medium group-hover:text-blue-500 transition-colors cursor-pointer"
                    onClick={() => setSelectedRule(rule)}
                  >
                    {rule.name}
                  </h4>
                  {rule.isCustomized && (
                    <span className="px-2 py-1 text-xs bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400 rounded-full">
                      Customized
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-2">
                  <span className={`px-2 py-1 rounded text-xs font-medium ${
                    rule.severity === 'critical' ? 'bg-red-100 text-red-700 dark:bg-red-900/20 dark:text-red-400' :
                    rule.severity === 'high' ? 'bg-orange-100 text-orange-700 dark:bg-orange-900/20 dark:text-orange-400' :
                    rule.severity === 'medium' ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/20 dark:text-yellow-400' :
                    'bg-blue-100 text-blue-700 dark:bg-blue-900/20 dark:text-blue-400'
                  }`}>
                    {rule.severity.toUpperCase()}
                  </span>
                </div>
              </div>
              <p className="text-sm text-gray-600 dark:text-gray-400 mb-3">{rule.description}</p>
              <div className="flex items-center justify-between">
                <div className="text-xs text-gray-500">
                  <span>Category: {rule.category}</span>
                  <span className="mx-2">•</span>
                  <span>v{rule.version}</span>
                  {rule.isCustomized && rule.customizedAt && (
                    <>
                      <span className="mx-2">•</span>
                      <span className="text-purple-600">Modified {new Date(rule.customizedAt).toLocaleDateString()}</span>
                    </>
                  )}
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setSelectedRule(rule)}
                    className="p-1 text-gray-400 hover:text-blue-500 transition-colors"
                    title="View rule details"
                  >
                    <Eye size={14} />
                  </button>
                  <button
                    onClick={() => setRuleToConfigure(rule)}
                    className="p-1 text-gray-400 hover:text-purple-500 transition-colors"
                    title="Configure rule"
                  >
                    <Settings size={14} />
                  </button>
                </div>
              </div>
            </div>
            ))}
          </div>
        )}
      </div>

      {/* Rule Details Modal */}
      <RuleDetailsModal
        rule={selectedRule}
        isOpen={!!selectedRule}
        onClose={() => setSelectedRule(null)}
        onConfigure={(rule) => {
          setSelectedRule(null); // Close details modal
          setRuleToConfigure(rule); // Open config modal
        }}
        darkMode={darkMode}
      />

      {/* Rule Configuration Modal */}
      <RuleConfigurationModal
        rule={ruleToConfigure}
        isOpen={!!ruleToConfigure}
        onClose={() => setRuleToConfigure(null)}
        onSave={handleRuleConfigSave}
      />
    </div>
  )
}

export default AnalyticsPage
