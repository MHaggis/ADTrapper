'use client'

import React, { useState, useEffect } from 'react'
import { Settings, X, Save, RotateCcw, AlertTriangle } from 'lucide-react'
import { supabase } from '@/lib/supabase'
// No auth needed in anonymous mode

interface RuleConfigurationModalProps {
  rule: any
  isOpen: boolean
  onClose: () => void
  onSave: (config: any) => void
  currentConfig?: any
}

interface RuleConfig {
  ruleId: string
  enabled: boolean
  thresholds: Record<string, number>
}

const RuleConfigurationModal: React.FC<RuleConfigurationModalProps> = ({
  rule,
  isOpen,
  onClose,
  onSave,
  currentConfig
}) => {
  // No user needed in anonymous mode
  const [config, setConfig] = useState<RuleConfig>({
    ruleId: rule?.id || '',
    enabled: rule?.enabled !== false,
    thresholds: rule?.thresholds ? { ...rule.thresholds } : {}
  })
  const [isSaving, setIsSaving] = useState(false)
  const [isLoading, setIsLoading] = useState(false)

  // Load existing configuration when modal opens
  useEffect(() => {
    if (isOpen && rule) {
      loadUserConfig()
    }
  }, [isOpen, rule])

  const loadUserConfig = async () => {
    if (!rule) return

    setIsLoading(true)
    // In anonymous mode, always use default rule configuration
    setConfig({
      ruleId: rule.id,
      enabled: rule.enabled !== false,
      thresholds: rule.thresholds ? { ...rule.thresholds } : {}
    })
    setIsLoading(false)
  }

  const saveConfig = async () => {
    if (!rule) return

    setIsSaving(true)
    // In anonymous mode, configurations are not persisted to database
    // Just update the local state and notify parent
    onSave(config)
    onClose()
    setIsSaving(false)
  }

  const resetToDefault = () => {
    setConfig({
      ruleId: rule.id,
      enabled: rule.enabled !== false,
      thresholds: rule.thresholds ? { ...rule.thresholds } : {}
    })
  }

  const updateThreshold = (key: string, value: string) => {
    const numValue = parseFloat(value)
    if (!isNaN(numValue)) {
      setConfig(prev => ({
        ...prev,
        thresholds: {
          ...prev.thresholds,
          [key]: numValue
        }
      }))
    }
  }

  if (!isOpen || !rule) return null

  // Get threshold descriptions for better UX
  const getThresholdDescription = (key: string): string => {
    const descriptions: Record<string, string> = {
      // Brute Force
      'failedAttempts': 'Number of failed login attempts to trigger alert',
      'timeWindowMinutes': 'Time window in minutes to count failures',
      'uniqueSourceIps': 'Minimum unique source IPs for distributed attack detection',

      // Geographic
      'maxCountries': 'Maximum countries allowed per user session',
      'maxCitiesPerCountry': 'Maximum cities per country',
      'impossibleTravelTimeHours': 'Minimum travel time to flag as impossible',

      // Off Hours
      'businessHourStart': 'Start hour for business hours (0-23)',
      'businessHourEnd': 'End hour for business hours (0-23)',

      // Privileged Access
      'maxPrivilegedLogins': 'Maximum privileged logins per hour',
      'maxTargetSystems': 'Maximum different systems accessed',
      'dormantAccountDays': 'Days of inactivity to flag dormant account',

      // Multiple Failures
      'failureCountThreshold': 'Number of failures to trigger alert',
      'lockoutThreshold': 'Failures indicating potential lockout attack',

      // Unusual Patterns
      'impossibleTravelKmH': 'Maximum travel speed in km/h',
      'concurrentSessionMinutes': 'Minutes between logins to consider concurrent',
      'unusualHourThreshold': 'Percentage threshold for unusual hours',

      // Password Spray
      'minTargetUsers': 'Minimum users targeted for password spray detection',
      'successToFailureRatio': 'Success to failure ratio threshold',
      'minTotalAttempts': 'Minimum total attempts for spray detection',

      // RDP
      'rdpLogonType': 'RDP logon type identifier',
      'suspiciousRDPSources': 'Flag suspicious RDP sources',
      'multipleRDPSessions': 'Multiple RDP sessions threshold',

      // Explicit Credentials
      'uniqueTargetsThreshold': 'Unique targets for explicit credential alerts',
      'minExplicitCredEvents': 'Minimum explicit credential events',

      // Local Admin
      'minFailedAttempts': 'Minimum failed attempts for admin attack detection',

      // Anonymous
      'nullSessionUsername': 'Username for anonymous/null sessions',
      'suspiciousAnonymousEvents': 'Threshold for suspicious anonymous activity'
    }

    return descriptions[key] || `Configure ${key.replace(/([A-Z])/g, ' $1').toLowerCase()}`
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-2xl max-w-2xl w-full max-h-[90vh] overflow-hidden">
        {/* Modal Header */}
        <div className="p-6 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 bg-blue-500/20 rounded-lg flex items-center justify-center">
                <Settings size={24} className="text-blue-600" />
              </div>
              <div>
                <h2 className="text-xl font-bold text-gray-900 dark:text-gray-100">
                  Configure {rule.name}
                </h2>
                <p className="text-sm text-gray-500">Customize rule settings for your environment</p>
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
          {isLoading ? (
            <div className="flex items-center justify-center py-8">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
              <span className="ml-2 text-gray-600">Loading configuration...</span>
            </div>
          ) : (
            <div className="space-y-6">
              {/* Rule Status */}
              <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="font-medium text-gray-900 dark:text-gray-100">Rule Status</h3>
                    <p className="text-sm text-gray-500">Enable or disable this rule</p>
                  </div>
                  <label className="flex items-center cursor-pointer">
                    <input
                      type="checkbox"
                      checked={config.enabled}
                      onChange={(e) => setConfig(prev => ({ ...prev, enabled: e.target.checked }))}
                      className="sr-only"
                    />
                    <div className={`relative inline-block w-10 h-6 rounded-full transition-colors ${
                      config.enabled ? 'bg-blue-500' : 'bg-gray-300'
                    }`}>
                      <div className={`absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform ${
                        config.enabled ? 'translate-x-4' : 'translate-x-0'
                      }`}></div>
                    </div>
                  </label>
                </div>
              </div>

              {/* Thresholds Configuration */}
              {Object.keys(config.thresholds).length > 0 && (
                <div>
                  <h3 className="text-lg font-semibold mb-4 text-gray-900 dark:text-gray-100">
                    Threshold Configuration
                  </h3>
                  <div className="space-y-4">
                    {Object.entries(config.thresholds).map(([key, value]) => (
                      <div key={key} className="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
                        <div className="flex items-center justify-between mb-2">
                          <div>
                            <label className="font-medium text-gray-900 dark:text-gray-100 capitalize">
                              {key.replace(/([A-Z])/g, ' $1').trim()}
                            </label>
                            <p className="text-sm text-gray-500">{getThresholdDescription(key)}</p>
                          </div>
                        </div>
                        <div className="flex items-center gap-3">
                          <input
                            type="number"
                            value={value}
                            onChange={(e) => updateThreshold(key, e.target.value)}
                            className="flex-1 px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                            step="0.1"
                          />
                          <div className="text-sm text-gray-500">
                            Current: {rule.thresholds[key] || 'default'}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Warning for Critical Rules */}
              {rule.severity === 'critical' && (
                <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-4">
                  <div className="flex items-start gap-3">
                    <AlertTriangle size={20} className="text-yellow-600 mt-1 flex-shrink-0" />
                    <div>
                      <h4 className="font-medium text-yellow-800 dark:text-yellow-200">Critical Security Rule</h4>
                      <p className="text-sm text-yellow-700 dark:text-yellow-300 mt-1">
                        This is a critical security rule. Only modify thresholds if you understand the security implications.
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {/* Configuration Summary */}
              <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4">
                <h4 className="font-medium text-blue-800 dark:text-blue-200 mb-2">Configuration Summary</h4>
                <div className="text-sm text-blue-700 dark:text-blue-300 space-y-1">
                  <p><strong>Status:</strong> {config.enabled ? 'Enabled' : 'Disabled'}</p>
                  <p><strong>Custom Thresholds:</strong> {Object.keys(config.thresholds).length}</p>
                  <p><strong>Last Updated:</strong> {new Date().toLocaleString()}</p>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="p-6 border-t border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700">
          <div className="flex justify-between items-center">
            <button
              onClick={resetToDefault}
              className="px-4 py-2 text-gray-600 dark:text-gray-300 hover:text-gray-800 dark:hover:text-gray-100 flex items-center gap-2 transition-colors"
              disabled={isSaving}
            >
              <RotateCcw size={16} />
              Reset to Default
            </button>

            <div className="flex gap-3">
              <button
                onClick={onClose}
                className="px-4 py-2 text-gray-600 dark:text-gray-300 hover:text-gray-800 dark:hover:text-gray-100 transition-colors"
                disabled={isSaving}
              >
                Cancel
              </button>
              <button
                onClick={saveConfig}
                disabled={isSaving}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 transition-colors"
              >
                {isSaving ? (
                  <>
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                    Saving...
                  </>
                ) : (
                  <>
                    <Save size={16} />
                    Save Configuration
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default RuleConfigurationModal
