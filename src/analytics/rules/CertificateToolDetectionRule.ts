import { BaseRule } from '../BaseRule'
import { AuthEvent, Anomaly, AnalyticsContext, ESCDetectionResult, CertificateTools } from '../types'

export class CertificateToolDetectionRule extends BaseRule {
  constructor() {
    super({
      id: 'certificate_tool_detection',
      name: 'Certificate Tool Usage Detection',
      description: 'Detects usage of certificate-related attack tools via process creation events',
      category: 'security',
      severity: 'critical',
      timeWindow: 60, // 1 hour for tool usage analysis
      thresholds: {
        toolUsageThreshold: 1,
        highRiskToolsBonus: 2,
        suspiciousCommandsBonus: 1
      },
      version: '1.0.0',
      author: 'ADTrapper Security Team',
      detailedDescription: {
        overview: 'Detects usage of certificate-related attack tools and utilities that may indicate AD CS exploitation attempts. Monitors for execution of tools like Certipy, Mimikatz, Certify, and other certificate manipulation utilities that are commonly used in AD CS attacks.',
        detectionLogic: 'Analyzes process creation events (Event 4688) to identify execution of known certificate attack tools. Monitors command-line parameters for suspicious certificate operations like PFX export, certificate backup, and store manipulation. Correlates tool usage with user privileges and access patterns.',
        falsePositives: 'Legitimate certificate management tools, system administration utilities, automated certificate deployment scripts, or legitimate certificate maintenance operations. May also trigger during certificate lifecycle management or system administration tasks.',
        mitigation: [
          'Monitor and block execution of known certificate attack tools',
          'Implement application whitelisting and execution controls',
          'Enable enhanced process creation logging with command-line capture',
          'Monitor for suspicious certificate-related command-line parameters',
          'Implement network-level detection for certificate tool usage',
          'Use endpoint detection and response (EDR) for tool detection',
          'Regular security tool scanning and removal',
          'Implement behavioral analytics for certificate operations',
          'Monitor for unusual certificate export and manipulation activities',
          'Configure alerts for certificate tool execution'
        ],
        windowsEvents: ['4688 (Process Creation)', '4689 (Process Termination)', '4688 (Process Creation with Command Line)', '1 (Process Creation - Sysmon)', '3 (Network Connection - Sysmon)', '11 (File Creation - Sysmon)', '13 (Registry Event - Sysmon)'],
        exampleQuery: `index=windows EventCode=4688 ProcessName=*certipy* OR ProcessName=*certify* OR ProcessName=*mimikatz* | stats count by Computer, TargetUserName`,
        recommendedThresholds: {
          toolUsageThreshold: 1,
          highRiskToolsBonus: 2,
          suspiciousCommandsBonus: 1
        }
      }
    })
  }

  async analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = []

    // Look for certificate-related tool usage via process creation (Event 4688)
    const toolEvents = events.filter(event =>
      event.eventId === '4688' || // Process creation
      event.rawData?.operation === 'process_create'
    ).filter(event => {
      const processName = event.rawData?.processName || event.rawData?.newProcessName || ''
      return CertificateTools.some(tool =>
        processName.toLowerCase().includes(tool.toLowerCase())
      )
    })

    if (toolEvents.length >= this.thresholds.toolUsageThreshold) {
      // Group by user and tool
      const toolByUser = new Map<string, AuthEvent[]>()

      toolEvents.forEach(event => {
        const userKey = event.userName || event.rawData?.userName || 'unknown'
        if (!toolByUser.has(userKey)) {
          toolByUser.set(userKey, [])
        }
        toolByUser.get(userKey)!.push(event)
      })

      // Analyze each user's tool usage
      for (const [userName, userTools] of Array.from(toolByUser.entries())) {
        let riskScore = 4 // Base critical risk for certificate tool usage
        let confidence = 90

        // Check for specific high-risk tools
        const hasHighRiskTools = userTools.some(event => {
          const processName = event.rawData?.processName || ''
          return processName.toLowerCase().includes('certipy') ||
                 processName.toLowerCase().includes('mimikatz') ||
                 processName.toLowerCase().includes('certify')
        })

        if (hasHighRiskTools) {
          riskScore += this.thresholds.highRiskToolsBonus
          confidence += 20
        }

        // Check for certutil with suspicious parameters
        const certutilSuspicious = userTools.filter(event => {
          const commandLine = event.rawData?.commandLine || event.rawData?.processCommandLine || ''
          return commandLine.includes('-exportPFX') ||
                 commandLine.includes('-backup') ||
                 commandLine.includes('-store')
        })

        if (certutilSuspicious.length > 0) {
          riskScore += this.thresholds.suspiciousCommandsBonus
          confidence += 15
        }

        const detection: ESCDetectionResult = {
          vulnerability: 'Certificate Tool Usage' as any,
          severity: 'critical',
          confidence: Math.min(confidence, 100),
          affectedEntities: [
            {
              type: 'user',
              id: userName,
              name: userName
            }
          ],
          evidence: {
            toolUsages: userTools.length,
            hasHighRiskTools,
            certutilSuspicious: certutilSuspicious.length,
            toolsUsed: Array.from(new Set(userTools.map(event =>
              event.rawData?.processName || 'unknown'
            ))),
            toolDetails: userTools.map(event => ({
              timestamp: event.timestamp,
              toolName: event.rawData?.processName,
              commandLine: event.rawData?.commandLine,
              computer: event.computerName
            }))
          },
          remediation: [
            'URGENT: Investigate certificate tool usage',
            'Check for unauthorized certificate theft tools',
            'Review tool command parameters for malicious intent',
            'Monitor for additional suspicious process activity',
            'Consider system isolation if attack tools are confirmed',
            'Audit certificate-related operations'
          ]
        }

        const anomaly = this.createCertificateToolAnomaly(detection, context)
        anomalies.push(anomaly)
      }
    }

    return anomalies
  }

  private createCertificateToolAnomaly(
    detection: ESCDetectionResult,
    context: AnalyticsContext
  ): Anomaly {
    const title = `🚨 Certificate Tool Usage: ${detection.affectedEntities[0].name}`
    const description = `Certificate-related attack tools detected for user ${detection.affectedEntities[0].name}. ` +
      `This may indicate certificate theft or AD CS exploitation attempts.`

    return this.createAnomaly(
      title,
      description,
      {
        vulnerability: detection.vulnerability,
        severity: detection.severity,
        confidence: detection.confidence,
        affectedEntity: detection.affectedEntities[0].name,
        timeWindow: this.timeWindow,
        detectionMethod: 'certificate_tool_detection',
        evidence: detection.evidence
      },
      detection.confidence,
      {
        attackType: 'certificate_tool_usage',
        vulnerabilityType: detection.vulnerability,
        riskLevel: detection.severity
      }
    )
  }
}
