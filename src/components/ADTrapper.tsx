'use client'

import React, { useState, useEffect } from 'react';
import { Download, Upload, AlertTriangle, Activity, Database, Settings, Brain, Layers, Bell, Users, X, Shield } from 'lucide-react';
import { useAnalytics } from '@/hooks/useAnalytics';
import DashboardStats from '@/components/dashboard/DashboardStats';
import AlertsManagement from '@/components/alerts/AlertsManagement';

// Extracted components and hooks
import { ADTrapperHeader } from './ui/ADTrapperHeader';
import { TabNavigation } from './ui/TabNavigation';
import { OfflineBanner } from './ui/OfflineBanner';
import { UserMenu } from './ui/UserMenu';
import { useADTrapperData } from './hooks/useADTrapperData';
import { useSupabaseConnection } from './hooks/useSupabaseConnection';
import { useGraphCanvas } from './hooks/useGraphCanvas';
import { useFileUpload } from './hooks/useFileUpload';

// Tab components
import { DashboardTab } from './tabs/DashboardTab';
import { GraphTab } from './tabs/GraphTab';
import { AlertsTab } from './tabs/AlertsTab';
import { AnalyticsTab } from './tabs/AnalyticsTab';
import { SessionsTab } from './tabs/SessionsTab';
import { UploadTab } from './tabs/UploadTab';
// ProfileTab removed for anonymous mode
import { SettingsTab } from './tabs/SettingsTab';
import { AssetsIdentitiesTab } from './tabs/AssetsIdentitiesTab';

// Types and constants
import { UserMenuPosition } from './types/adtrapper.types';
import { tabConfig } from './constants/sampleData';

const ADTrapper = () => {
  // UI State
  const [activeTab, setActiveTab] = useState('dashboard');
  const [darkMode, setDarkMode] = useState(true);
  const [showUserMenu, setShowUserMenu] = useState(false);
  const [dropdownPosition, setDropdownPosition] = useState<UserMenuPosition>({ top: 0, right: 0 });
  const [selectedNode, setSelectedNode] = useState<any>(null);
  const [selectedAnomaly, setSelectedAnomaly] = useState<any>(null);
  const [alertSortBy, setAlertSortBy] = useState<'severity' | 'time' | 'confidence'>('severity');
  const [alertFilter, setAlertFilter] = useState('all');
  const [staticMode, setStaticMode] = useState(true);
  const [isAdmin, setIsAdmin] = useState(false);

  // Alert-to-graph state
  const [alertGraphMode, setAlertGraphMode] = useState(false);
  const [alertGraphData, setAlertGraphData] = useState<{
    alert: any;
    relatedEvents: any[];
    affectedEntities: Array<{
      type: 'user' | 'computer' | 'ip';
      id: string;
      name: string;
    }>;
  } | null>(null);

  // Analytics Hooks (no auth needed)
  const { analyzeEvents, processSampleData, getAnomalyStats, getRules, getStatistics, isAnalyzing: analyticsRunning } = useAnalytics();

  // Anomalies state
  const [anomalies, setAnomalies] = useState<any[]>([]);

  // No admin status needed in anonymous mode

  // Handle alert-to-graph navigation
  const handleGraphAlert = (anomaly: any, relatedEvents: any[], affectedEntities: any[]) => {
    // Set alert graph data
    setAlertGraphData({
      alert: anomaly,
      relatedEvents: relatedEvents,
      affectedEntities: affectedEntities
    });

    // Enable alert graph mode
    setAlertGraphMode(true);

    // Navigate to graph tab
    setActiveTab('graph');

    console.log('Navigating to graph with alert data:', anomaly.title);
  };

  // Handle exiting alert graph mode
  const handleExitAlertGraph = () => {
    setAlertGraphMode(false);
    setAlertGraphData(null);
  };

  // Custom Hooks
  const {
    data,
    filteredData,
    filters,
    stats,
    updateData,
    setFilters,
    isProcessingAnalytics,
    processingProgress
  } = useADTrapperData(null, setAnomalies); // No user needed in anonymous mode

  const {
    supabaseConnected,
    userSessions,
    currentSession,
    setCurrentSession,
    loadUserSessions,
    loadSessionData,
    deleteSession,
    updateSessionAnalysis
  } = useSupabaseConnection(null); // No user needed in anonymous mode

  const { canvasRef, particlesRef, handleCanvasClick } = useGraphCanvas({
    data: filteredData,
    darkMode,
    onNodeClick: setSelectedNode
  });

  const { uploadProgress, isAnalyzing, handleFileUpload, clearFileInput } = useFileUpload({
    supabaseConnected,
    onDataUpdate: updateData,
    onSessionUpdate: setCurrentSession,
    onSessionsRefresh: loadUserSessions
  });

  // No auth handlers needed in anonymous mode

  // Download PowerShell script
  const downloadPowerShellScript = () => {
    const scriptUrl = '/capture.ps1';
    const link = document.createElement('a');
    link.href = scriptUrl;
    link.download = 'adtrapper-capture.ps1';
    link.click();
  };

  // Handler functions for menu actions
  const handleProfileClick = () => setActiveTab('profile');
  const handleSessionsClick = () => setActiveTab('sessions');
  const handleSettingsClick = () => setActiveTab('settings');

  const themeClasses = darkMode 
    ? 'bg-gray-900 text-white' 
    : 'bg-gray-50 text-gray-900';

  return (
    <div className={`w-full h-screen ${themeClasses} transition-all duration-300 relative overflow-hidden`}>
      {/* Particles Background */}
      {darkMode && (
        <canvas
          ref={particlesRef}
          className="absolute inset-0 pointer-events-none"
          style={{ zIndex: 0 }}
        />
      )}

      {/* Offline Banner */}
      <OfflineBanner supabaseConnected={supabaseConnected} />

      {/* Analytics Processing Banner */}
      {isProcessingAnalytics && (
        <div className="bg-blue-500 dark:bg-blue-600 text-white px-4 py-3 relative z-10">
          <div className="container mx-auto flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white"></div>
              <span className="font-medium">
                Processing Analytics... 
                {processingProgress.total > 0 && (
                  <span className="ml-2">
                    Batch {processingProgress.current} of {processingProgress.total}
                  </span>
                )}
              </span>
            </div>
            {processingProgress.total > 0 && (
              <div className="flex items-center space-x-2">
                <div className="w-32 bg-blue-400 rounded-full h-2">
                  <div 
                    className="bg-white h-2 rounded-full transition-all duration-300" 
                    style={{ width: `${(processingProgress.current / processingProgress.total) * 100}%` }}
                  ></div>
                </div>
                <span className="text-sm">
                  {Math.round((processingProgress.current / processingProgress.total) * 100)}%
                </span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Header */}
      <ADTrapperHeader
        darkMode={darkMode}
        setDarkMode={setDarkMode}
        stats={stats}
        onSessionsClick={() => setActiveTab('sessions')}
      />
                
      {/* No user menu needed in anonymous mode */}

      {/* Tab Navigation */}
      <TabNavigation
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        tabs={[
          ...tabConfig.map(tab => ({
            ...tab,
            icon: tab.icon === 'Activity' ? Activity :
                  tab.icon === 'Layers' ? Layers :
                  tab.icon === 'Bell' ? Bell :
                  tab.icon === 'Users' ? Users :
                  tab.icon === 'Brain' ? Brain :
                  tab.icon === 'Database' ? Database :
                  tab.icon === 'Settings' ? Settings :
                  tab.icon === 'Upload' ? Upload :
                  Activity, // Default fallback
            badge: tab.id === 'alerts' ? anomalies.length :
                   tab.id === 'sessions' ? userSessions.length : undefined
          })),
          ...(isAdmin ? [{
            id: 'admin',
            label: 'Admin Panel',
            icon: Shield,
            badge: undefined
          }] : [])
        ]}
        darkMode={darkMode}
      />

      {/* Tab Content */}
      <div className="flex-1 p-6 relative z-10 overflow-y-auto" style={{ maxHeight: 'calc(100vh - 200px)' }}>
        {activeTab === 'dashboard' && (
          <DashboardTab
            data={data}
            anomalies={anomalies}
            darkMode={darkMode}
            setActiveTab={setActiveTab}
          />
        )}

        {activeTab === 'graph' && (
          <GraphTab
            data={data}
            filteredData={filteredData}
            selectedNode={selectedNode}
            filters={filters}
            darkMode={darkMode}
            isStaticMode={staticMode}
            setSelectedNode={setSelectedNode}
            setFilters={setFilters}
            setStaticMode={setStaticMode}
            handleCanvasClick={handleCanvasClick}
            alertMode={alertGraphMode}
            alertData={alertGraphData}
            onExitAlertMode={handleExitAlertGraph}
          />
        )}

        {activeTab === 'alerts' && (
          <AlertsTab
            anomalies={anomalies}
            supabaseConnected={supabaseConnected}
            darkMode={darkMode}
            onGraphAlert={handleGraphAlert}
          />
        )}

        {activeTab === 'assets' && (
          <AssetsIdentitiesTab
            anomalies={anomalies}
            darkMode={darkMode}
            events={data.rawLogs || []}
          />
        )}

        {activeTab === 'anomalies' && (
          <AnalyticsTab
            anomalies={anomalies}
            darkMode={darkMode}
          />
        )}

        {activeTab === 'upload' && (
          <UploadTab
            darkMode={darkMode}
            uploadProgress={uploadProgress}
            isAnalyzing={isAnalyzing}
            handleFileUpload={handleFileUpload}
          />
        )}

        {activeTab === 'sessions' && (
          <SessionsTab
            darkMode={darkMode}
            userSessions={userSessions}
            currentSession={currentSession}
            setActiveTab={setActiveTab}
            loadSessionData={loadSessionData}
            deleteSession={deleteSession}
            updateData={updateData}
          />
        )}

        {activeTab === 'settings' && (
          <SettingsTab
            darkMode={darkMode}
            setDarkMode={setDarkMode}
          />
        )}
      </div>

      {/* No auth modal needed in anonymous mode */}

      {/* Anomaly Details Modal */}
      {selectedAnomaly && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-2xl max-w-4xl w-full max-h-[90vh] overflow-hidden">
            <div className="p-6 border-b border-gray-200 dark:border-gray-700">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <div className="text-xl font-bold">Anomaly Details</div>
                </div>
                <button
                  onClick={() => setSelectedAnomaly(null)}
                  className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                >
                  <X size={24} />
                </button>
              </div>
            </div>
            <div className="p-6">
              <p className="text-gray-700 dark:text-gray-300">Anomaly details modal content preserved in extracted components</p>
                </div>
                      </div>
        </div>
      )}
    </div>
  );
};

export default ADTrapper;
