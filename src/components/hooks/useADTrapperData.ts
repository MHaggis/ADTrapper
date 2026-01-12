import { useState, useEffect, useMemo } from 'react';
import { GraphData, FilterState, Stats } from '../types/adtrapper.types';
import { normalizeData, extractAvailableFilters, applyFilters, calculateStats } from '../utils/adtrapper.utils';
import { sampleData, defaultFilters, emptyGraphData } from '../constants/sampleData';
import { useAnalytics } from '@/hooks/useAnalytics';
import { Anomaly } from '@/analytics/types';

export const useADTrapperData = (user: any, onAnomaliesUpdate?: (anomalies: Anomaly[]) => void) => {
  const [data, setData] = useState<GraphData>(emptyGraphData);
  const [filteredData, setFilteredData] = useState<GraphData>(emptyGraphData);
  const [filters, setFilters] = useState<FilterState>(defaultFilters);
  const [isProcessingAnalytics, setIsProcessingAnalytics] = useState(false);
  const [processingProgress, setProcessingProgress] = useState({ current: 0, total: 0 });
  const { analyzeEvents, processSampleData } = useAnalytics();

  // Initialize with sample data when not logged in
  useEffect(() => {
    if (!user && (!data.nodes || data.nodes.length === 0)) {
      const normalizedSampleData = normalizeData(sampleData);
      setData(normalizedSampleData);
      setFilteredData(normalizedSampleData);
    }
    // Only clear data if user logs in AND we have confirmed they have no sessions
    // Don't clear immediately when user logs in, wait to check for sessions first
  }, [user, data.nodes]);

  // Apply filters whenever data or filters change
  useEffect(() => {
    const filtered = applyFilters(data, filters);
    setFilteredData(filtered);
  }, [data, filters]);

  // Update available filters when data changes
  useEffect(() => {
    const { availableIPs, availableHostnames } = extractAvailableFilters(data.nodes);

    setFilters(prev => ({
      ...prev,
      availableIPs,
      availableHostnames,
      // Auto-select all if none are selected initially
      selectedIPs: prev.selectedIPs.length === 0 ? availableIPs : prev.selectedIPs,
      selectedHostnames: prev.selectedHostnames.length === 0 ? availableHostnames : prev.selectedHostnames
    }));
  }, [data.nodes]);

  // Calculate stats from current data
  const stats = useMemo(() => calculateStats(data), [data]);

  // Run analytics on data with batch processing for large datasets
  const runAnalytics = async (graphData: GraphData) => {
    try {
      console.log('Running real analytics on graph data...');
      setIsProcessingAnalytics(true);
      
      if (graphData.rawLogs && Array.isArray(graphData.rawLogs) && graphData.rawLogs.length > 0) {
        const totalEvents = graphData.rawLogs.length;
        console.log(`Converting ${totalEvents} events for analytics...`);
        
        // For large datasets (>50k events), use batch processing to prevent stack overflow
        const BATCH_SIZE = 10000; // Process 10k events at a time
        const shouldBatch = totalEvents > 50000;
        
        if (shouldBatch) {
          console.log(`🔄 Large dataset detected (${totalEvents} events). Using batch processing with ${BATCH_SIZE} events per batch...`);
          setProcessingProgress({ current: 0, total: Math.ceil(totalEvents / BATCH_SIZE) });
          await runBatchedAnalytics(graphData, BATCH_SIZE, onAnomaliesUpdate);
        } else {
          console.log(`📊 Standard processing for ${totalEvents} events...`);
          setProcessingProgress({ current: 0, total: 1 });
          await runStandardAnalytics(graphData, onAnomaliesUpdate);
        }
      } else {
        console.log('No raw logs found in graph data, cannot run analytics');
        if (onAnomaliesUpdate) onAnomaliesUpdate([]);
      }
    } catch (error) {
      console.error('Analytics failed:', error);
      if (onAnomaliesUpdate) onAnomaliesUpdate([]);
    } finally {
      setIsProcessingAnalytics(false);
      setProcessingProgress({ current: 0, total: 0 });
    }
  };

  // Standard analytics processing for smaller datasets
  const runStandardAnalytics = async (graphData: GraphData, onAnomaliesUpdate?: (anomalies: Anomaly[]) => void) => {
    if (!graphData.rawLogs) return;
    
    const authEvents = convertRawLogsToAuthEvents(graphData.rawLogs);
    const context = createAnalyticsContext(graphData, authEvents);
    
    console.log(`Running analytics on ${authEvents.length} events with ${context.userProfiles?.length} users and ${context.ipIntelligence?.length} IPs...`);
    
    const result = await analyzeEvents(authEvents, context);
    handleAnalyticsResult(result, onAnomaliesUpdate);
  };

  // Batched analytics processing for large datasets
  const runBatchedAnalytics = async (graphData: GraphData, batchSize: number, onAnomaliesUpdate?: (anomalies: Anomaly[]) => void) => {
    if (!graphData.rawLogs) return;
    
    const allEvents = graphData.rawLogs;
    const totalBatches = Math.ceil(allEvents.length / batchSize);
    const allAnomalies: Anomaly[] = [];
    let processedEvents = 0;

    console.log(`📦 Processing ${allEvents.length} events in ${totalBatches} batches...`);

    for (let i = 0; i < totalBatches; i++) {
      const startIdx = i * batchSize;
      const endIdx = Math.min(startIdx + batchSize, allEvents.length);
      const batchEvents = allEvents.slice(startIdx, endIdx);
      
      console.log(`🔄 Processing batch ${i + 1}/${totalBatches} (${batchEvents.length} events)...`);
      
      try {
        const authEvents = convertRawLogsToAuthEvents(batchEvents);
        const context = createAnalyticsContext(graphData, authEvents, `batch_${i + 1}`);
        
        const result = await analyzeEvents(authEvents, context);
        
        if (result && result.anomalies) {
          allAnomalies.push(...result.anomalies);
          console.log(`✅ Batch ${i + 1} completed: ${result.anomalies.length} anomalies found`);
        }
        
        processedEvents += batchEvents.length;
        setProcessingProgress({ current: i + 1, total: totalBatches });
        
        // Small delay to prevent overwhelming the browser
        if (i < totalBatches - 1) {
          await new Promise(resolve => setTimeout(resolve, 100));
        }
      } catch (batchError) {
        console.error(`❌ Error processing batch ${i + 1}:`, batchError);
        // Continue with next batch
      }
    }

    console.log(`🎯 Batch processing completed! Total: ${allAnomalies.length} anomalies from ${processedEvents} events`);
    
    if (onAnomaliesUpdate) {
      onAnomaliesUpdate(allAnomalies);
    }
  };

  // Helper function to convert raw logs to AuthEvent format
  const convertRawLogsToAuthEvents = (rawLogs: any[]) => {
    return rawLogs.map((event: any, index: number) => ({
      id: event.id || `event_${index}`,
      timestamp: new Date(event.timestamp),
      eventId: event.eventId || '4624',
      computerName: event.computerName,
      userName: event.userName,
      domainName: event.domainName || 'COMPANY',
      sourceIp: event.sourceIp,
      logonType: event.logonType || 'Interactive',
      status: event.status || 'Success',
      failureReason: event.failureReason,
      authenticationPackage: event.authenticationPackage,
      logonProcess: event.logonProcess,
      workstationName: event.workstationName,
      rawData: event
    }));
  };

  // Helper function to create analytics context
  const createAnalyticsContext = (graphData: GraphData, authEvents: any[], sessionSuffix = '') => {
    // Check if this is SharpHound data
    const isSharpHound = authEvents.some(event =>
      event.rawData?.sharpHoundUser || event.rawData?.sharpHoundComputer
    );

    // Extract SharpHound data if present
    let sharpHoundData = undefined;
    if (isSharpHound) {
      // For SharpHound data, we need to reconstruct the SharpHound structure
      // from the synthetic events. This is a simplified reconstruction.
      const users = authEvents
        .filter(event => event.rawData?.sharpHoundUser)
        .map(event => ({
          Properties: event.rawData.properties,
          AllowedToDelegate: event.rawData.delegation || [],
          PrimaryGroupSID: event.rawData.properties?.primarygroupsid || '',
          HasSIDHistory: event.rawData.properties?.sidhistory || [],
          SPNTargets: event.rawData.properties?.spntargets || [],
          Aces: event.rawData.aces || []
        }));

      const computers = authEvents
        .filter(event => event.rawData?.sharpHoundComputer)
        .map(event => ({
          Properties: event.rawData.properties,
          AllowedToDelegate: event.rawData.delegation || [],
          PrimaryGroupSID: event.rawData.properties?.primarygroupsid || '',
          AllowedToAct: event.rawData.properties?.allowedtoact || [],
          Aces: event.rawData.aces || []
        }));

      sharpHoundData = {
        users: users.filter((u, i, arr) => arr.findIndex(x => x.Properties?.samaccountname === u.Properties?.samaccountname) === i),
        computers: computers.filter((c, i, arr) => arr.findIndex(x => x.Properties?.samaccountname === c.Properties?.samaccountname) === i),
        groups: [],
        domains: [],
        ous: [],
        gpos: [],
        containers: [],
        certificates: []
      };
    }

    return {
      sessionId: `session_${Date.now()}${sessionSuffix}`,
      organizationId: 'uploaded_data',
      timeRange: {
        start: new Date(Math.min(...authEvents.map((e: any) => e.timestamp.getTime()))),
        end: new Date(Math.max(...authEvents.map((e: any) => e.timestamp.getTime())))
      },
      dataType: (isSharpHound ? 'sharphound' : 'auth-logs') as 'auth-logs' | 'sharphound',
      sharpHoundData,
      userProfiles: graphData.nodes
        .filter(node => node.type === 'user')
        .map(node => ({
          userName: node.label,
          domain: 'COMPANY',
          department: node.department || 'Unknown',
          privileged: node.privileged || false,
          enabled: node.enabled !== false,
          groups: node.privileged ? ['Domain Admins'] : ['Domain Users'],
          normalLoginHours: { start: 8, end: 17 }
        })),
      ipIntelligence: graphData.nodes
        .filter(node => node.type === 'ip')
        .map(node => ({
          ip: node.label,
          country: node.country || 'Unknown',
          city: node.city || 'Unknown',
          isVpn: false,
          isTor: node.tor || false,
          isMalicious: node.riskScore > 90,
          riskScore: node.riskScore || 0
        }))
    };
  };

  // Helper function to handle analytics results
  const handleAnalyticsResult = (result: any, onAnomaliesUpdate?: (anomalies: Anomaly[]) => void) => {
    if (result && result.anomalies && onAnomaliesUpdate) {
      console.log(`🎯 Analytics completed! Found ${result.anomalies.length} anomalies from ${result.summary.totalRulesExecuted} rules`);
      console.log('📊 Rule execution results:', result.ruleResults.map((r: any) => ({ 
        rule: r.ruleName, 
        executed: r.executed, 
        anomalies: r.anomaliesFound,
        error: r.error 
      })));
      console.log('🚨 Anomalies found:', result.anomalies.slice(0, 10).map((a: any) => ({ 
        rule: a.ruleName, 
        severity: a.severity, 
        title: a.title 
      })), result.anomalies.length > 10 ? `... and ${result.anomalies.length - 10} more` : '');
      onAnomaliesUpdate(result.anomalies);
    } else {
      console.log('❌ No analytics result or anomalies found');
      if (onAnomaliesUpdate) onAnomaliesUpdate([]);
    }
  };

  const updateData = (newData: GraphData) => {
    const normalized = normalizeData(newData);
    console.log('Updating data in useADTrapperData:', normalized);
    setData(normalized);

    // Run analytics on the new data
    if (normalized.nodes.length > 0) {
      runAnalytics(normalized);
    }
  };

  const resetToSampleData = () => {
    const normalized = normalizeData(sampleData);
    setData(normalized);
  };

  const clearData = () => {
    setData(emptyGraphData);
  };

  return {
    data,
    filteredData,
    filters,
    stats,
    updateData,
    setFilters,
    resetToSampleData,
    clearData,
    isProcessingAnalytics,
    processingProgress
  };
};
