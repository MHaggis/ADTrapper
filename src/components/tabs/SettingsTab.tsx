import React, { useState, useEffect } from 'react';
import { Settings, Save, Server, Database, Key, Zap, TestTube, AlertCircle, CheckCircle, Upload } from 'lucide-react';
import SplunkHECService from '@/lib/splunkHECService';

interface SplunkHECConfig {
  enabled: boolean;
  endpoint: string;
  token: string;
  index?: string;
  sourcetype: string;
  source?: string;
  autoSend: boolean;
  sendAllEvents?: boolean;
  sendAnomalies?: boolean;
  sendSessionData?: boolean;
  ignoreSslErrors?: boolean;
}

interface SettingsTabProps {
  darkMode: boolean;
  setDarkMode: (dark: boolean) => void;
}

export const SettingsTab: React.FC<SettingsTabProps> = ({
  darkMode,
  setDarkMode
}) => {
  const [apiKey, setApiKey] = useState('');
  const [autoAnalysis, setAutoAnalysis] = useState(true);
  const [databaseUrl, setDatabaseUrl] = useState('');
  const [splunkConfig, setSplunkConfig] = useState<SplunkHECConfig>({
    enabled: false,
    endpoint: '',
    token: '',
    index: '',
    sourcetype: 'adtrapper:events',
    source: '',
    autoSend: true,
    sendAllEvents: false,
    sendAnomalies: true,
    sendSessionData: false,
    ignoreSslErrors: false
  });
  const [testingConnection, setTestingConnection] = useState(false);
  const [connectionTestResult, setConnectionTestResult] = useState<any>(null);

  // Load existing settings on component mount
  useEffect(() => {
    const savedSettings = localStorage.getItem('adtrapper-settings');
    if (savedSettings) {
      try {
        const settings = JSON.parse(savedSettings);
        setApiKey(settings.apiKey || '');
        setAutoAnalysis(settings.autoAnalysis !== undefined ? settings.autoAnalysis : true);
        setDatabaseUrl(settings.databaseUrl || 'postgresql://postgres:postgres@localhost:54325/postgres');
      } catch (error) {
        console.error('Failed to load settings:', error);
      }
    }

    // Load Splunk HEC configuration
    const splunkSettings = SplunkHECService.getConfig();
    if (splunkSettings) {
      setSplunkConfig(splunkSettings);
    }
  }, []);

  const cardClasses = darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200';
  const inputClasses = darkMode 
    ? 'bg-gray-700 border-gray-600 text-white placeholder-gray-400' 
    : 'bg-white border-gray-300 text-gray-900 placeholder-gray-500';

  const handleSave = () => {
    // Save general settings to localStorage
    localStorage.setItem('adtrapper-settings', JSON.stringify({
      apiKey,
      autoAnalysis,
      darkMode,
      databaseUrl
    }));

    // Save Splunk HEC configuration
    SplunkHECService.saveConfig(splunkConfig);

    alert('Settings saved successfully!');
  };

  const testDatabaseConnection = async () => {
    // Mock database connection test - always succeeds for now
    alert('Database connection test: Using direct PostgreSQL connection. All operations will use the upload API.');
  };

  const testSplunkConnection = async () => {
    if (!splunkConfig.endpoint || !splunkConfig.token) {
      alert('Please configure Splunk endpoint and token first');
      return;
    }

    setTestingConnection(true);
    setConnectionTestResult(null);

    try {
      const success = await SplunkHECService.testConnection(
        splunkConfig.endpoint,
        splunkConfig.token,
        splunkConfig.ignoreSslErrors
      );

      const result = {
        success,
        message: success ? 'Connection successful' : 'Connection failed'
      };

      setConnectionTestResult(result);

      if (success) {
        alert('Splunk HEC connection successful!');
      } else {
        alert('Splunk HEC connection failed. Check console for details.');
      }
    } catch (error) {
      const errorResult = {
        success: false,
        message: 'Connection test failed',
        error: error instanceof Error ? error.message : 'Unknown error'
      };
      setConnectionTestResult(errorResult);
      alert(`Splunk HEC connection failed: ${errorResult.error}`);
    } finally {
      setTestingConnection(false);
    }
  };

  const updateSplunkConfig = (field: keyof SplunkHECConfig, value: any) => {
    setSplunkConfig(prev => ({
      ...prev,
      [field]: value
    }));
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3 mb-6">
        <Settings className="w-6 h-6 text-blue-500" />
        <h2 className="text-2xl font-bold">Settings</h2>
      </div>

      {/* Appearance Settings */}
      <div className={`border rounded-xl p-6 ${cardClasses}`}>
        <div className="flex items-center gap-3 mb-4">
          <Zap className="w-5 h-5 text-purple-500" />
          <h3 className="text-lg font-semibold">Appearance</h3>
        </div>
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <label className="text-sm font-medium">Dark Mode</label>
            <button
              onClick={() => setDarkMode(!darkMode)}
              className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                darkMode ? 'bg-blue-600' : 'bg-gray-300'
              }`}
            >
              <span
                className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                  darkMode ? 'translate-x-6' : 'translate-x-1'
                }`}
              />
            </button>
          </div>
        </div>
      </div>

      {/* Splunk HEC Settings */}
      <div className={`border rounded-xl p-6 ${cardClasses}`}>
        <div className="flex items-center gap-3 mb-4">
          <Server className="w-5 h-5 text-orange-500" />
          <h3 className="text-lg font-semibold">Splunk HEC Configuration</h3>
        </div>
        
        {/* Enable/Disable Toggle */}
        <div className="flex items-center justify-between mb-4 p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
          <div>
            <label className="text-sm font-medium">Enable Splunk HEC</label>
            <p className="text-xs text-gray-500">Send logs to Splunk HTTP Event Collector</p>
          </div>
          <button
            onClick={() => updateSplunkConfig('enabled', !splunkConfig.enabled)}
            className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
              splunkConfig.enabled ? 'bg-blue-600' : 'bg-gray-300'
            }`}
          >
            <span
              className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                splunkConfig.enabled ? 'translate-x-6' : 'translate-x-1'
              }`}
            />
          </button>
        </div>

        <div className="space-y-4">
          {/* Basic Configuration */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium mb-2">Splunk HEC URL</label>
              <input
                type="url"
                value={splunkConfig.endpoint}
                onChange={(e) => updateSplunkConfig('endpoint', e.target.value)}
                placeholder="https://your-splunk-instance.com:8088"
                className={`w-full px-3 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent ${inputClasses}`}
              />
              <p className="text-xs text-gray-500 mt-1">The /services/collector path will be added automatically</p>
            </div>
            <div>
              <label className="block text-sm font-medium mb-2">HEC Token</label>
              <input
                type="password"
                value={splunkConfig.token}
                onChange={(e) => updateSplunkConfig('token', e.target.value)}
                placeholder="Enter your HEC token (UUID format)"
                className={`w-full px-3 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent ${inputClasses}`}
              />
            </div>
          </div>

          {/* Advanced Configuration */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-sm font-medium mb-2">Index</label>
              <input
                type="text"
                value={splunkConfig.index || ''}
                onChange={(e) => updateSplunkConfig('index', e.target.value)}
                placeholder="adtrapper"
                className={`w-full px-3 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent ${inputClasses}`}
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-2">Sourcetype</label>
              <input
                type="text"
                value={splunkConfig.sourcetype}
                onChange={(e) => updateSplunkConfig('sourcetype', e.target.value)}
                placeholder="adtrapper:json"
                className={`w-full px-3 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent ${inputClasses}`}
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-2">Source</label>
              <input
                type="text"
                value={splunkConfig.source || ''}
                onChange={(e) => updateSplunkConfig('source', e.target.value)}
                placeholder="adtrapper:events"
                className={`w-full px-3 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent ${inputClasses}`}
              />
            </div>
          </div>

          {/* Sending Options */}
          <div className="space-y-3">
            <h4 className="font-medium text-gray-900 dark:text-gray-100">Sending Options</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <label className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  checked={splunkConfig.autoSend}
                  onChange={(e) => updateSplunkConfig('autoSend', e.target.checked)}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="text-sm">Auto-send events</span>
              </label>
              <label className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  checked={splunkConfig.sendAnomalies}
                  onChange={(e) => updateSplunkConfig('sendAnomalies', e.target.checked)}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="text-sm">Send anomalies</span>
              </label>
              <label className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  checked={splunkConfig.sendSessionData}
                  onChange={(e) => updateSplunkConfig('sendSessionData', e.target.checked)}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="text-sm">Send session metadata</span>
              </label>
              <label className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  checked={splunkConfig.ignoreSslErrors}
                  onChange={(e) => updateSplunkConfig('ignoreSslErrors', e.target.checked)}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="text-sm">Ignore SSL errors</span>
              </label>
            </div>
          </div>

          {/* Test Connection */}
          <div className="flex justify-between items-center pt-4 border-t border-gray-200 dark:border-gray-600">
            <div>
              {connectionTestResult && (
                <div className={`flex items-center gap-2 text-sm ${
                  connectionTestResult.success ? 'text-green-600' : 'text-red-600'
                }`}>
                  {connectionTestResult.success ? 
                    <CheckCircle className="w-4 h-4" /> : 
                    <AlertCircle className="w-4 h-4" />
                  }
                  <span>{connectionTestResult.message}</span>
                  {connectionTestResult.responseTime && (
                    <span className="text-gray-500">({connectionTestResult.responseTime}ms)</span>
                  )}
                </div>
              )}
            </div>
            <button
              onClick={testSplunkConnection}
              disabled={testingConnection || !splunkConfig.endpoint || !splunkConfig.token}
              className="flex items-center gap-2 px-4 py-2 bg-orange-600 text-white rounded-lg hover:bg-orange-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {testingConnection ? (
                <>
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                  Testing...
                </>
              ) : (
                <>
                  <TestTube className="w-4 h-4" />
                  Test Connection
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Database Configuration */}
      <div className={`border rounded-xl p-6 ${cardClasses}`}>
        <div className="flex items-center gap-3 mb-4">
          <Database className="w-5 h-5 text-blue-500" />
          <h3 className="text-lg font-semibold">Database Configuration</h3>
        </div>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-2">PostgREST URL</label>
            <input
              type="url"
              value={databaseUrl || 'postgresql://postgres:postgres@localhost:54325/postgres'}
              onChange={(e) => setDatabaseUrl(e.target.value)}
              placeholder="http://localhost:3001"
              className={`w-full px-3 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent ${inputClasses}`}
            />
            <p className="text-xs text-gray-500 mt-1">Local PostgREST API endpoint</p>
          </div>
          <div className="flex justify-end">
            <button
              onClick={testDatabaseConnection}
              className="flex items-center gap-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors"
            >
              <TestTube className="w-4 h-4" />
              Test Connection
            </button>
          </div>
        </div>
      </div>

      {/* API Settings */}
      <div className={`border rounded-xl p-6 ${cardClasses}`}>
        <div className="flex items-center gap-3 mb-4">
          <Key className="w-5 h-5 text-green-500" />
          <h3 className="text-lg font-semibold">API Configuration</h3>
        </div>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-2">API Key</label>
            <input
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="Enter your API key"
              className={`w-full px-3 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent ${inputClasses}`}
            />
          </div>
        </div>
      </div>

      {/* Analysis Settings */}
      <div className={`border rounded-xl p-6 ${cardClasses}`}>
        <div className="flex items-center gap-3 mb-4">
          <Database className="w-5 h-5 text-blue-500" />
          <h3 className="text-lg font-semibold">Analysis Settings</h3>
        </div>
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <label className="text-sm font-medium">Auto-run Analytics</label>
              <p className="text-xs text-gray-500">Automatically analyze uploaded files</p>
            </div>
            <button
              onClick={() => setAutoAnalysis(!autoAnalysis)}
              className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                autoAnalysis ? 'bg-blue-600' : 'bg-gray-300'
              }`}
            >
              <span
                className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                  autoAnalysis ? 'translate-x-6' : 'translate-x-1'
                }`}
              />
            </button>
          </div>
        </div>
      </div>

      {/* Save Button */}
      <div className="flex justify-end">
        <button
          onClick={handleSave}
          className="flex items-center gap-2 px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
        >
          <Save className="w-4 h-4" />
          Save Settings
        </button>
      </div>
    </div>
  );
};
