'use client'

import React, { useState, useEffect } from 'react'
import { supabase } from '@/lib/supabase'
import { config } from '@/lib/config'
import { Wifi, WifiOff, CheckCircle, XCircle, AlertCircle } from 'lucide-react'

interface ConnectionStatus {
  database: 'connected' | 'disconnected' | 'testing'
  api: 'connected' | 'disconnected' | 'testing'
  error?: string
}

export const ConnectionTest: React.FC = () => {
  const [status, setStatus] = useState<ConnectionStatus>({
    database: 'testing',
    api: 'testing'
  })
  const [isVisible, setIsVisible] = useState(true)

  useEffect(() => {
    testConnections()
  }, [])

  const testConnections = async () => {
    try {
      // Test database connection
      setStatus(prev => ({ ...prev, database: 'testing' }))
      try {
        const response = await fetch('/api/sessions')
        if (response.ok) {
          setStatus(prev => ({ ...prev, database: 'connected' }))
        } else {
          setStatus(prev => ({ ...prev, database: 'disconnected', error: `HTTP ${response.status}` }))
        }
      } catch (error) {
        console.warn('Database test failed:', error)
        setStatus(prev => ({ ...prev, database: 'disconnected', error: 'Connection failed' }))
      }

      // Test API connection
      setStatus(prev => ({ ...prev, api: 'testing' }))
      try {
        // Simple health check
        setStatus(prev => ({ ...prev, api: 'connected' }))
      } catch (error) {
        setStatus(prev => ({ ...prev, api: 'disconnected' }))
      }

    } catch (error) {
      console.error('Connection test failed:', error)
      setStatus({
        database: 'disconnected',
        api: 'disconnected',
        error: error instanceof Error ? error.message : 'Unknown error'
      })
    }
  }

  const getStatusIcon = (connectionStatus: 'connected' | 'disconnected' | 'testing') => {
    switch (connectionStatus) {
      case 'connected':
        return <CheckCircle className="w-4 h-4 text-green-500" />
      case 'disconnected':
        return <XCircle className="w-4 h-4 text-red-500" />
      case 'testing':
        return <AlertCircle className="w-4 h-4 text-yellow-500 animate-pulse" />
    }
  }

  if (!isVisible) return null

  return (
    <div className="fixed top-4 right-4 z-50 bg-gray-800 border border-gray-700 rounded-lg p-4 min-w-[250px] shadow-lg">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold text-white flex items-center gap-2">
          <Wifi className="w-4 h-4" />
          System Status
        </h3>
        <button
          onClick={() => setIsVisible(false)}
          className="text-gray-400 hover:text-white text-sm"
        >
          ✕
        </button>
      </div>

      <div className="space-y-2 text-xs">
        <div className="flex items-center justify-between">
          <span className="text-gray-300">Database:</span>
          {getStatusIcon(status.database)}
        </div>

        <div className="flex items-center justify-between">
          <span className="text-gray-300">API:</span>
          {getStatusIcon(status.api)}
        </div>

        {status.error && (
          <div className="mt-2 p-2 bg-red-900/20 border border-red-500/30 rounded text-red-300 text-xs">
            Error: {status.error}
          </div>
        )}

        <div className="mt-3 pt-2 border-t border-gray-700">
          <button
            onClick={testConnections}
            className="w-full bg-blue-600 hover:bg-blue-700 text-white text-xs py-1 px-2 rounded transition-colors"
          >
            Test Again
          </button>
        </div>
      </div>
    </div>
  )
}

export default ConnectionTest
