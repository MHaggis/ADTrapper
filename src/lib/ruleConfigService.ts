import { supabase } from './supabase'

export interface UserRuleConfig {
  id: string
  user_id: string
  rule_id: string
  enabled: boolean
  thresholds: Record<string, number>
  created_at: string
  updated_at: string
}

export class RuleConfigService {
  /**
   * Get all rule configurations for a user (anonymous mode - return empty array)
   */
  static async getUserRuleConfigs(userId: string): Promise<UserRuleConfig[]> {
    // In anonymous mode, no user-specific configurations
    return []
  }

  /**
   * Get a specific rule configuration for a user (anonymous mode - return null)
   */
  static async getUserRuleConfig(userId: string, ruleId: string): Promise<UserRuleConfig | null> {
    // In anonymous mode, no user-specific configurations
    return null
  }

  /**
   * Save or update a rule configuration for a user (anonymous mode - no-op)
   */
  static async saveUserRuleConfig(
    userId: string,
    ruleId: string,
    enabled: boolean,
    thresholds: Record<string, number>
  ): Promise<UserRuleConfig | null> {
    // In anonymous mode, configurations are not persisted
    console.warn('Rule configuration not saved in anonymous mode')
    return null
  }

  /**
   * Delete a rule configuration (anonymous mode - no-op)
   */
  static async deleteUserRuleConfig(userId: string, ruleId: string): Promise<boolean> {
    // In anonymous mode, nothing to delete
    return true
  }

  /**
   * Get merged rule configuration (user config + defaults)
   */
  static mergeRuleConfig(
    defaultRule: any,
    userConfig: UserRuleConfig | null
  ): any {
    if (!userConfig) {
      // Return the original rule instance with customization flag
      return Object.assign(defaultRule, {
        isCustomized: false
      })
    }

    // Update the rule instance with user configuration
    const updatedRule = Object.assign(defaultRule, {
      enabled: userConfig.enabled,
      thresholds: {
        ...defaultRule.thresholds,
        ...userConfig.thresholds
      },
      isCustomized: true,
      customizedAt: userConfig.updated_at
    })

    return updatedRule
  }

  /**
   * Get all rules with user configurations applied
   */
  static async getRulesWithUserConfig(userId: string, defaultRules: any[]): Promise<any[]> {
    try {
      const userConfigs = await this.getUserRuleConfigs(userId)

      // Create a map of user configs by rule_id
      const userConfigMap = new Map(
        userConfigs.map(config => [config.rule_id, config])
      )

      // Merge user configs with default rules
      return defaultRules.map(defaultRule => {
        const userConfig = userConfigMap.get(defaultRule.id) || null
        return this.mergeRuleConfig(defaultRule, userConfig)
      })
    } catch (error) {
      console.error('Error getting rules with user config:', error)
      // Return default rules if there's an error
      return defaultRules.map(rule => ({
        ...rule,
        isCustomized: false
      }))
    }
  }
}
