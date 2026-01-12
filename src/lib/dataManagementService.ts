import { supabase } from './supabase'
import { UploadedSession } from './fileUploadService'

export interface DataRetentionSettings {
  retentionDays: number
  autoDeleteOldSessions: boolean
  lastModified: Date
}

export interface ExportData {
  sessions: UploadedSession[]
  exportDate: string
  totalSessions: number
  totalEvents: number
  totalAnomalies: number
}

export class DataManagementService {

  /**
   * Get data retention settings (stored locally for anonymous users)
   */
  static async getDataRetentionSettings(): Promise<DataRetentionSettings> {
    // For anonymous mode, store settings in localStorage
    const stored = localStorage.getItem('adtRetentionSettings')
    if (stored) {
      try {
        const settings = JSON.parse(stored)
        return { ...settings, lastModified: new Date(settings.lastModified) }
      } catch (e) {
        console.warn('Failed to parse stored retention settings:', e)
      }
    }

    // Default settings if none exist
    const defaultSettings: DataRetentionSettings = {
      retentionDays: 90,
      autoDeleteOldSessions: false,
      lastModified: new Date()
    }

    return defaultSettings
  }

  /**
   * Update data retention settings (stored locally for anonymous users)
   */
  static async updateDataRetentionSettings(settings: Partial<DataRetentionSettings>): Promise<void> {
    const currentSettings = await this.getDataRetentionSettings()
    const updatedSettings: DataRetentionSettings = {
      ...currentSettings,
      ...settings,
      lastModified: new Date()
    }

    // Store in localStorage for anonymous mode
    localStorage.setItem('adtRetentionSettings', JSON.stringify(updatedSettings))

    // If auto-delete is enabled, clean up old sessions
    if (updatedSettings.autoDeleteOldSessions) {
      await this.cleanupOldSessions(updatedSettings.retentionDays)
    }
  }

  /**
   * Clean up sessions older than the retention period
   */
  static async cleanupOldSessions(retentionDays: number): Promise<number> {
    const cutoffDate = new Date()
    cutoffDate.setDate(cutoffDate.getDate() - retentionDays)

    // Get sessions to delete
    const { data: sessionsToDelete, error: fetchError } = await supabase
      .from('analysis_sessions')
      .select('id, storage_path')
      .lt('uploaded_at', cutoffDate.toISOString())

    if (fetchError) {
      throw new Error(`Failed to fetch old sessions: ${fetchError.message}`)
    }

    if (!sessionsToDelete || sessionsToDelete.length === 0) {
      return 0
    }

    // Delete files from storage (skip welcome session)
    const storagePaths = sessionsToDelete
      .filter((s: any) => s.storage_path !== '/welcome')
      .map((s: any) => s.storage_path)

    if (storagePaths.length > 0) {
      const { error: storageError } = await supabase.storage
        .from('analysis-data')
        .remove(storagePaths)

      if (storageError) {
        console.warn('Failed to delete some files from storage:', storageError.message)
      }
    }

    // Delete database records (skip welcome session)
    const { error: dbError } = await supabase
      .from('analysis_sessions')
      .delete()
      .neq('storage_path', '/welcome')  // Don't delete the welcome session
      .lt('uploaded_at', cutoffDate.toISOString())

    if (dbError) {
      throw new Error(`Failed to delete old sessions: ${dbError.message}`)
    }

    return sessionsToDelete.filter((s: any) => s.storage_path !== '/welcome').length
  }

  /**
   * Export all data (anonymous mode)
   */
  static async exportAllData(): Promise<ExportData> {
    // Get all sessions (excluding welcome session)
    const { data: sessions, error: sessionsError } = await supabase
      .from('analysis_sessions')
      .select('*')
      .neq('storage_path', '/welcome')
      .order('uploaded_at', { ascending: false })

    if (sessionsError) {
      throw new Error(`Failed to get sessions: ${sessionsError.message}`)
    }

    // Calculate totals
    const totalEvents = sessions?.reduce((sum: number, session: any) => sum + (session.event_count || 0), 0) || 0
    const totalAnomalies = sessions?.reduce((sum: number, session: any) => sum + (session.anomaly_count || 0), 0) || 0

    return {
      sessions: sessions || [],
      exportDate: new Date().toISOString(),
      totalSessions: sessions?.length || 0,
      totalEvents,
      totalAnomalies
    }
  }

  /**
   * Download export data as JSON file
   */
  static downloadExportData(data: ExportData, filename?: string): void {
    const dataStr = JSON.stringify(data, null, 2)
    const dataBlob = new Blob([dataStr], { type: 'application/json' })

    const url = URL.createObjectURL(dataBlob)
    const link = document.createElement('a')
    link.href = url
    link.download = filename || `adtrapper_export_${new Date().toISOString().split('T')[0]}.json`
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    URL.revokeObjectURL(url)
  }

  /**
   * Delete all data (anonymous mode - clears all sessions)
   */
  static async deleteAccount(): Promise<void> {
    // Get all sessions (excluding welcome session)
    const { data: sessions, error: sessionsError } = await supabase
      .from('analysis_sessions')
      .select('storage_path')
      .neq('storage_path', '/welcome')

    if (sessionsError) {
      throw new Error(`Failed to get sessions: ${sessionsError.message}`)
    }

    // Delete all files from storage
    if (sessions && sessions.length > 0) {
      const storagePaths = sessions.map((s: any) => s.storage_path).filter(Boolean)
      if (storagePaths.length > 0) {
        const { error: storageError } = await supabase.storage
          .from('analysis-data')
          .remove(storagePaths)

        if (storageError) {
          console.warn('Failed to delete some files from storage:', storageError.message)
        }
      }
    }

    // Delete all database records (excluding welcome session)
    const { error: dbError } = await supabase
      .from('analysis_sessions')
      .delete()
      .neq('storage_path', '/welcome')

    if (dbError) {
      throw new Error(`Failed to delete sessions: ${dbError.message}`)
    }

    // Clear local storage settings
    localStorage.removeItem('adtRetentionSettings')
    localStorage.removeItem('adtSplunkHEC')

    // Note: In anonymous mode, we can't sign out users, but we clear all their data
    console.log('All data cleared successfully')
  }

  /**
   * Get current logs for Splunk integration
   * Returns the most recent events from the most recent session
   */
  static async getCurrentLogs(): Promise<any[]> {
    try {
      // Get the most recent analysis session (excluding welcome session)
      const { data: session, error: sessionError } = await supabase
        .from('analysis_sessions')
        .select('storage_path, created_at')
        .neq('storage_path', '/welcome')
        .order('created_at', { ascending: false })
        .limit(1)
        .single()

      if (sessionError || !session) {
        console.log('No analysis sessions found')
        return []
      }

      // Download the session data from storage
      const { data: fileData, error: downloadError } = await supabase.storage
        .from('analysis-data')
        .download(session.storage_path)

      if (downloadError || !fileData) {
        console.error('Failed to download session data:', downloadError)
        return []
      }

      // Parse the JSON data
      const text = await fileData.text()
      const sessionData = JSON.parse(text)

      // Extract events from the session data
      // The structure may vary, so we'll try to find events in common locations
      let events: any[] = []

      if (sessionData.events && Array.isArray(sessionData.events)) {
        events = sessionData.events
      } else if (sessionData.data && sessionData.data.rawLogs && Array.isArray(sessionData.data.rawLogs)) {
        events = sessionData.data.rawLogs
      } else if (sessionData.rawLogs && Array.isArray(sessionData.rawLogs)) {
        events = sessionData.rawLogs
      }

      // If no events found, try to look for events in nested structures
      if (events.length === 0 && sessionData.data) {
        const findEvents = (obj: any): any[] => {
          if (Array.isArray(obj) && obj.length > 0 && typeof obj[0] === 'object' && obj[0].timestamp) {
            return obj
          }
          if (typeof obj === 'object' && obj !== null) {
            for (const key in obj) {
              const result = findEvents(obj[key])
              if (result.length > 0) {
                return result
              }
            }
          }
          return []
        }

        events = findEvents(sessionData)
      }

      console.log(`Found ${events.length} events in current session`)
      return events

    } catch (error) {
      console.error('Error getting current logs:', error)
      return []
    }
  }
}
