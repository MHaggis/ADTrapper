import { useState } from 'react';
import { FileUploadService } from '@/lib/fileUploadService';
import { useAnalytics } from '@/hooks/useAnalytics';
import { SharpHoundService } from '@/lib/sharpHoundService';
import { GraphData, ParsedData } from '../types/adtrapper.types';
import { parseUploadedFile, convertEventsToGraphFormat } from '../utils/adtrapper.utils';
import { geoIpService } from '@/lib/geoIpService';
import { AnalyticsContext } from '@/analytics/types';

interface UseFileUploadProps {
  supabaseConnected: boolean;
  onDataUpdate: (data: GraphData) => void;
  onSessionUpdate: (session: any) => void;
  onSessionsRefresh: () => void;
}

export const useFileUpload = ({
  supabaseConnected,
  onDataUpdate,
  onSessionUpdate,
  onSessionsRefresh
}: UseFileUploadProps) => {
  const [uploadProgress, setUploadProgress] = useState(0);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const { analyzeEvents } = useAnalytics();

  // Function to enrich analytics context with IP intelligence
  const enrichContextWithIpIntelligence = async (events: any[], baseContext: AnalyticsContext): Promise<AnalyticsContext> => {
    try {
      // Extract unique IPs from events
      const uniqueIps = new Set<string>();
      events.forEach(event => {
        if (event.sourceIp && event.sourceIp !== '::1' && event.sourceIp !== '127.0.0.1') {
          // Convert IPv4-mapped IPv6 to IPv4 for geo lookup
          let cleanIp = event.sourceIp;
          if (cleanIp.startsWith('::ffff:')) {
            cleanIp = cleanIp.replace('::ffff:', '');
          }
          uniqueIps.add(cleanIp);
        }
      });

      // Get geo IP data for unique IPs
      const ipIntelligence = await geoIpService.getBatchGeoIpData(Array.from(uniqueIps));

      // Convert to the expected format for analytics
      const ipIntelligenceArray = Array.from(ipIntelligence.values()).map(geoData => ({
        ip: geoData.ip,
        country: geoData.country || 'Unknown',
        region: geoData.region || 'Unknown',
        city: geoData.city || 'Unknown',
        isVpn: geoData.isVpn,
        isTor: geoData.isTor,
        isMalicious: geoData.isMalicious,
        riskScore: geoData.riskScore
      }));

      return {
        ...baseContext,
        ipIntelligence: ipIntelligenceArray
      };
    } catch (error) {
      console.warn('Failed to enrich context with IP intelligence:', error);
      return baseContext; // Return base context if enrichment fails
    }
  };

  // Function to run SharpHound analytics
  const runSharpHoundAnalytics = async (collection: any) => {
    try {
      console.log('🔍 Starting SharpHound analytics...');

      // Import analytics engine
      const { AnalyticsEngine } = await import('../../analytics/AnalyticsEngine');
      const { FileUploadService } = await import('../../lib/fileUploadService');

      // Convert SharpHound data to ADTrapper format
      const parsedData = FileUploadService.convertSharpHoundToADTrapper(collection);
      console.log('📊 Converted SharpHound data:', {
        events: parsedData.events?.length || 0,
        hasContext: !!parsedData.context
      });

      if (!parsedData.events || parsedData.events.length === 0) {
        console.warn('⚠️ No events found in SharpHound data');
        return { anomalies: [], eventCount: 0 };
      }

      // Create analytics context
      const context = {
        sessionId: `sharphound-${collection.id}`,
        organizationId: 'sharphound-upload',
        timeRange: {
          start: new Date(collection.created_at),
          end: new Date(collection.created_at)
        },
        dataType: 'sharphound' as const,
        sharpHoundData: parsedData.context?.sharpHoundData
      };

      console.log('🎯 Created analytics context:', {
        dataType: context.dataType,
        hasSharpHoundData: !!context.sharpHoundData
      });

      // Initialize analytics engine and run analysis
      const engine = new AnalyticsEngine();
      console.log('🚀 Running analytics with', parsedData.events.length, 'events...');

      const result = await engine.analyze(parsedData.events, context);
      console.log('✅ Analytics completed:', {
        totalRules: result.summary.totalRulesExecuted,
        anomalies: result.anomalies.length
      });

      return {
        anomalies: result.anomalies,
        eventCount: parsedData.events.length
      };

    } catch (error) {
      console.error('❌ SharpHound analytics failed:', error);
      return { anomalies: [], eventCount: 0 };
    }
  };

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = event.target.files;
    if (!files || files.length === 0) return;

    // No authentication required - anonymous uploads allowed

    if (!supabaseConnected) {
      alert('Upload functionality is not available in offline mode. Please check your connection.');
      event.target.value = '';
      return;
    }

    setIsAnalyzing(true);
    setUploadProgress(0);

    try {
      // Check if this is a SharpHound collection
      const isSharpHound = await detectSharpHoundFiles(files);

      if (isSharpHound) {
        await processSharpHoundFiles(files);
      } else {
        // Process as regular authentication logs
        const file = files[0]; // Use first file for backward compatibility
        const text = await file.text();
        const parsedData = parseUploadedFile(file, text);

        setUploadProgress(25);

        // Store the file in Supabase first
        setUploadProgress(30);
        console.log('Starting file storage to Supabase...');
        console.log('Parsed data events count:', parsedData.events?.length || 0);
        console.log('File type:', file.type);
        console.log('File size:', file.size);

        // Create a progress callback that updates the UI during chunked uploads
        const progressCallback = (progress: number) => {
          setUploadProgress(progress);
        };

        const session = await FileUploadService.storeUploadedFile(
          file,
          parsedData,
          `${file.name.split('.')[0]} - ${new Date().toLocaleDateString()}`,
          progressCallback
        );

        console.log('File stored successfully:', session);
        // Set progress to at least 70% after file storage (chunking may have already updated it higher)
        setUploadProgress(prev => Math.max(prev, 70));

        // Continue with the rest of the upload process...
        await processUploadedData(session, parsedData);
      }

    } catch (error) {
      console.error('Upload failed:', error);
      setIsAnalyzing(false);
      setUploadProgress(0);
      alert(`Upload failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    } finally {
      // Always clear the file input
      event.target.value = '';
    }
  };

  const processUploadedData = async (session: any, parsedData: ParsedData) => {
    try {
      // Process events in chunks for large files
      const eventCount = parsedData.events.length;
      console.log(`Processing ${eventCount} events with analytics engine...`);

      // Create base context
      const baseContext: AnalyticsContext = parsedData.context || {
        sessionId: session?.id || 'upload-session',
        organizationId: 'default',
        timeRange: {
          start: new Date(Date.now() - 24 * 60 * 60 * 1000),
          end: new Date()
        }
      };

      // Enrich context with IP intelligence
      const enrichedContext = await enrichContextWithIpIntelligence(parsedData.events, baseContext);

      console.log(`Enriched context with ${enrichedContext.ipIntelligence?.length || 0} IP intelligence records`);

      const result = await analyzeEvents(parsedData.events, enrichedContext);

      console.log('Setting progress to 80%');
      setUploadProgress(80);

      if (result && result.anomalies) {
        console.log(`Analytics complete: Found ${result.anomalies.length} anomalies`);

        // Update session with anomaly count
        try {
          console.log('Updating session analysis...');
          await FileUploadService.updateSessionAnalysis(session.id, result.anomalies.length);
          console.log('Session analysis updated successfully');
        } catch (updateError) {
          console.warn('Could not update session analysis:', updateError);
        }

        console.log('Setting progress to 90%');
        setUploadProgress(90);

        // Convert to graph format for visualization (limit for performance)
        console.log(`Converting ${Math.min(eventCount, 1000)} events to graph format...`);
        try {
          const limitedEvents = eventCount > 1000 ? parsedData.events.slice(0, 1000) : parsedData.events;
          const graphData = convertEventsToGraphFormat(limitedEvents, enrichedContext);
          console.log('Graph conversion complete, updating data...');

          onDataUpdate(graphData);
          onSessionUpdate(session);
          console.log('Data and session updated');
        } catch (graphError) {
          console.error('Error converting events to graph format:', graphError);
          // Continue with empty graph data if conversion fails
          onDataUpdate({ nodes: [], edges: [], metadata: { eventCount: 0, timeRange: '', generatedAt: new Date() } });
          onSessionUpdate(session);
          console.log('Continued with empty graph data due to conversion error');
        }

        // Refresh sessions list
        try {
          console.log('Refreshing sessions list...');
          await onSessionsRefresh();
          console.log('Sessions refreshed successfully');
        } catch (loadError) {
          console.warn('Could not refresh sessions:', loadError);
        }

        if (eventCount > 1000) {
          console.log(`Note: Visualization limited to first 1000 events for performance. All ${eventCount} events were analyzed.`);
        }

        console.log('Setting progress to 100%');
        setUploadProgress(100);

        // Show success message with analysis results
        const successMessage = `✅ Analysis complete! Processed ${eventCount} events and found ${result.anomalies.length} anomalies. Results saved to your account.`;
        console.log(successMessage);
        alert(successMessage);

        console.log('Clearing analyzing state...');
        setTimeout(() => {
          setIsAnalyzing(false);
          setUploadProgress(0);
          console.log('Upload process completed successfully');
        }, 500);
      } else {
        console.error('Analytics result is null or undefined');
        setIsAnalyzing(false);
        setUploadProgress(0);
        alert('Analysis failed - no results returned');
      }

    } catch (error) {
      console.error('Error processing uploaded data:', error);
      setIsAnalyzing(false);
      setUploadProgress(0);
      throw error; // Re-throw so the calling function can handle it
    }
  };

  const detectSharpHoundFiles = async (files: FileList): Promise<boolean> => {
    // Check if any file has SharpHound characteristics
    for (let i = 0; i < files.length; i++) {
      const file = files[i];

      // Check file extension
      if (file.name.toLowerCase().includes('sharphound') ||
          file.name.endsWith('.zip') ||
          file.name.match(/\d{8}\d{6}_.*\.json$/)) {
        return true;
      }

      // Check file content for SharpHound markers
      if (file.name.endsWith('.json') && file.size < 1024 * 1024) { // Only check small files
        try {
          const content = await file.text();
          const data = JSON.parse(content);

          // Look for SharpHound-specific structure
          if (data.data && Array.isArray(data.data) &&
              data.data.length > 0 &&
              data.data[0].Properties &&
              (data.data[0].Properties.samaccountname ||
               data.data[0].Properties.distinguishedname)) {
            return true;
          }
        } catch (e) {
          // Not valid JSON or not SharpHound format
        }
      }
    }

    return false;
  };

  const processSharpHoundFiles = async (files: FileList) => {
    try {
      setUploadProgress(10);
      console.log('Processing SharpHound files...');

      let collection;

      // Check if we have a ZIP file or multiple JSON files
      if (files.length === 1 && files[0].name.endsWith('.zip')) {
        console.log('Processing SharpHound ZIP file...');
        collection = await SharpHoundService.processSharpHoundZip(files[0]);
      } else {
        console.log('Processing SharpHound JSON files...');
        collection = await SharpHoundService.processSharpHoundFiles(files);
      }

      setUploadProgress(30);
      console.log(`Created SharpHound collection with ${collection.files.length} files`);

      // Save collection to database
      setUploadProgress(50);
      const sessionId = await SharpHoundService.saveCollection(collection, 'anonymous');
      console.log('SharpHound collection saved with session ID:', sessionId);

      setUploadProgress(60);

      // Run SharpHound analytics immediately after saving
      console.log('Running SharpHound analytics...');
      const { anomalies, eventCount } = await runSharpHoundAnalytics(collection);

      setUploadProgress(80);

      // For now, create a basic visualization from SharpHound data
      // This is a simplified version - you might want to create more sophisticated analytics
      const graphData = convertSharpHoundToGraph(collection);
      onDataUpdate(graphData);

      // Create a session object for consistency
      const session = {
        id: sessionId,
        session_name: collection.name,
        uploaded_at: collection.created_at,
        file_name: `sharphound-collection-${collection.id}`,
        event_count: eventCount,
        anomaly_count: anomalies.length,
        storage_path: `sharphound/${collection.id}`,
        is_public: false
      };

      onSessionUpdate(session);

      // Refresh sessions list
      try {
        await onSessionsRefresh();
      } catch (loadError) {
        console.warn('Could not refresh sessions:', loadError);
      }

      setUploadProgress(100);

      const successMessage = `✅ SharpHound collection uploaded successfully! Processed ${collection.files.length} files with ${eventCount} total objects. Found ${anomalies.length} security anomalies.`;
      console.log(successMessage);
      alert(successMessage);

      setTimeout(() => {
        setIsAnalyzing(false);
        setUploadProgress(0);
      }, 500);

    } catch (error) {
      console.error('SharpHound processing failed:', error);
      setIsAnalyzing(false);
      setUploadProgress(0);
      throw error;
    }
  };

  const convertSharpHoundToGraph = (collection: any): GraphData => {
    const nodes: any[] = [];
    const edges: any[] = [];

    // Process users
    const usersFile = collection.files.find((f: any) => f.type === 'users');
    if (usersFile) {
      usersFile.data.forEach((user: any) => {
        nodes.push({
          id: user.Properties.samaccountname || user.Properties.distinguishedname,
          label: user.Properties.samaccountname || user.Properties.name,
          type: 'user',
          department: 'Unknown',
          enabled: user.Properties.enabled,
          privileged: user.Properties.admincount,
          lastSeen: user.Properties.lastlogon ? new Date(user.Properties.lastlogon * 1000) : new Date(),
          riskScore: user.Properties.admincount ? 95 : 20,
          domain: user.Properties.domain
        });
      });
    }

    // Process computers
    const computersFile = collection.files.find((f: any) => f.type === 'computers');
    if (computersFile) {
      computersFile.data.forEach((computer: any) => {
        nodes.push({
          id: computer.Properties.samaccountname || computer.Properties.distinguishedname,
          label: computer.Properties.samaccountname || computer.Properties.name,
          type: 'computer',
          os: computer.Properties.operatingsystem || 'Unknown',
          riskScore: computer.Properties.isdc ? 80 : 30,
          domain: computer.Properties.domain,
          enabled: computer.Properties.enabled
        });
      });
    }

    // Process groups
    const groupsFile = collection.files.find((f: any) => f.type === 'groups');
    if (groupsFile) {
      groupsFile.data.forEach((group: any) => {
        nodes.push({
          id: group.Properties.samaccountname || group.Properties.distinguishedname,
          label: group.Properties.samaccountname || group.Properties.name,
          type: 'group',
          riskScore: group.Properties.admincount ? 90 : 40,
          domain: group.Properties.domain
        });
      });
    }

    return {
      nodes: nodes.slice(0, 1000), // Limit for performance
      edges: edges.slice(0, 1000),
      metadata: {
        eventCount: nodes.length,
        timeRange: 'SharpHound Collection',
        generatedAt: new Date(),
        anomalyCount: 0
      },
      rawLogs: []
    };
  };

  const clearFileInput = (event: React.ChangeEvent<HTMLInputElement>) => {
    event.target.value = '';
  };

  return {
    uploadProgress,
    isAnalyzing,
    handleFileUpload,
    clearFileInput
  };
};
