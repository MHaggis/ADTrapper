import { supabase } from './supabase'
import { AuthEvent, AnalyticsContext } from '@/analytics/types'

export interface UploadedSession {
  id: string
  user_id: string
  session_name: string
  uploaded_at: string
  file_name: string | null
  file_size_bytes: number | null
  event_count: number | null
  anomaly_count: number | null
  time_range_start: string | null
  time_range_end: string | null
  storage_path: string
  is_public: boolean
}

export interface ParsedUploadData {
  events: AuthEvent[]
  context?: AnalyticsContext
  metadata?: {
    generatedAt?: string
    generatedBy?: string
    eventCount?: number
    timeRangeHours?: number
    uniqueUsers?: number
    uniqueIps?: number
  }
}

export class FileUploadService {
  
  /**
   * Normalize timestamps in events to ensure they're Date objects
   */
  static normalizeEventTimestamps(events: any[]): any[] {
    return events.map(event => {
      if (event.timestamp) {
        // If timestamp is a string, convert to Date
        if (typeof event.timestamp === 'string') {
          try {
            event.timestamp = new Date(event.timestamp);
          } catch (error) {
            console.warn('Failed to parse timestamp:', event.timestamp, error);
            // Keep original timestamp if parsing fails
          }
        }
        // If timestamp is already a Date object, keep it as is
        else if (event.timestamp instanceof Date) {
          // Already a Date object, no conversion needed
        }
        // If timestamp is a number (Unix timestamp), convert to Date
        else if (typeof event.timestamp === 'number') {
          try {
            event.timestamp = new Date(event.timestamp);
          } catch (error) {
            console.warn('Failed to convert Unix timestamp:', event.timestamp, error);
          }
        }
      }
      return event;
    });
  }

  /**
   * Parse uploaded JSON data into structured format
   */
  static parseUploadedData(jsonData: any): ParsedUploadData {
    let events: any[] = [];

    // Handle both structured JSON (from our PowerShell script) and plain arrays
    if (Array.isArray(jsonData)) {
      // Plain array of events
      events = jsonData;
    } else if (jsonData.events && Array.isArray(jsonData.events)) {
      // Structured format from our PowerShell script
      events = jsonData.events;
    } else {
      throw new Error('Invalid JSON format. Expected array of events or structured format with events property.');
    }

    // Normalize timestamps to ensure they're Date objects
    const normalizedEvents = this.normalizeEventTimestamps(events);

    if (Array.isArray(jsonData)) {
      // Plain array of events
      return {
        events: normalizedEvents,
        metadata: {
          eventCount: normalizedEvents.length,
          generatedAt: new Date().toISOString(),
          generatedBy: 'Manual Upload'
        }
      }
    } else {
      // Structured format from our PowerShell script
      return {
        events: normalizedEvents,
        context: jsonData.context,
        metadata: jsonData.metadata
      }
    }
  }
  
  /**
   * Split large data into chunks for upload
   */
  static splitDataIntoChunks(data: any, chunkSize: number = 10000): any[] {
    const events = data.events || [];
    const chunks = [];

    for (let i = 0; i < events.length; i += chunkSize) {
      chunks.push({
        events: events.slice(i, i + chunkSize),
        context: data.context,
        metadata: {
          ...data.metadata,
          chunkIndex: Math.floor(i / chunkSize),
          totalChunks: Math.ceil(events.length / chunkSize),
          originalEventCount: events.length,
          isChunk: true
        }
      });
    }

    return chunks;
  }

  /**
   * Store large files in chunks to overcome Supabase upload limits
   */
  static async storeFileInChunks(
    file: File,
    parsedData: ParsedUploadData,
    sessionName: string,
    userId: string,
    useServiceRole: boolean = false,
    onProgress?: (progress: number) => void
  ): Promise<UploadedSession> {

    console.log('FileUploadService: Starting chunked upload for file:', file.name, 'Size:', file.size);

    // Get the appropriate Supabase client
    // For local instance, we don't need service role - just use the regular client
    const supabaseClient = supabase;

    const eventCount = parsedData.events.length;
    const chunks = this.splitDataIntoChunks(parsedData, 5000); // Reduced to 5k events per chunk for better memory management
    const timestamp = Date.now();

    console.log(`FileUploadService: Created ${chunks.length} chunks for ${eventCount} events`);


    // Upload chunks sequentially to avoid overwhelming Supabase and provide progress
    const uploadedChunks: any[] = [];
    let completedChunks = 0;

    for (let i = 0; i < chunks.length; i++) {
      const chunk = chunks[i];
      const chunkFileName = `${sessionName}_chunk_${i}.json`;
      const chunkStoragePath = `user-uploads/${userId}/${timestamp}-${chunkFileName}`;

      try {
        console.log(`FileUploadService: Uploading chunk ${i + 1}/${chunks.length} (${chunk.events.length} events)`);

        // Convert chunk to blob for upload
        const chunkBlob = new Blob([JSON.stringify(chunk)], { type: 'application/json' });

        const { data: uploadData, error: uploadError } = await supabaseClient.storage
          .from('analysis-data')
          .upload(chunkStoragePath, chunkBlob, {
            cacheControl: '3600',
            upsert: false
          });

        if (uploadError) {
          console.error(`FileUploadService: Failed to upload chunk ${i}:`, uploadError);
          throw new Error(`Failed to upload chunk ${i}: ${uploadError.message}`);
        }

        uploadedChunks.push({
          chunkIndex: i,
          storagePath: chunkStoragePath,
          eventCount: chunk.events.length,
          uploadedAt: new Date().toISOString()
        });

        completedChunks++;
        const progressPercent = 30 + Math.round((completedChunks / chunks.length) * 40); // Progress from 30% to 70%
        if (onProgress) {
          onProgress(progressPercent);
        }

        console.log(`FileUploadService: Completed chunk ${i + 1}/${chunks.length}, progress: ${progressPercent}%`);

      } catch (chunkError) {
        console.error(`FileUploadService: Error uploading chunk ${i}:`, chunkError);
        throw chunkError;
      }
    }

    try {
      // Calculate time range from events for chunked upload
      const eventTimestamps = parsedData.events
        .map(e => e.timestamp instanceof Date ? e.timestamp : new Date(e.timestamp))
        .filter(d => !isNaN(d.getTime()))
        .sort((a, b) => a.getTime() - b.getTime());

      const timeRangeStart = eventTimestamps.length > 0 ? eventTimestamps[0].toISOString() : null;
      const timeRangeEnd = eventTimestamps.length > 0 ? eventTimestamps[eventTimestamps.length - 1].toISOString() : null;

      // Create session record with chunk information first (before uploading chunks)
      const { data: sessionData, error: sessionError } = await supabaseClient
        .from('analysis_sessions')
        .insert({
          session_name: sessionName,
          file_name: file.name,
          file_size_bytes: file.size,
          event_count: eventCount,
          anomaly_count: 0,
          time_range_start: timeRangeStart,
          time_range_end: timeRangeEnd,
          storage_path: `chunked:${timestamp}` // Special marker for chunked files
        })
        .select()
        .single();

      if (sessionError) {
        console.error('FileUploadService: Failed to create session record:', sessionError);
        throw new Error(`Failed to create session: ${sessionError.message}`);
      }

      console.log('FileUploadService: Session created, now uploading chunks...');

      // Store initial chunk metadata (in case upload fails partway through)
      const initialMetadata = {
        sessionId: sessionData.id,
        totalChunks: chunks.length,
        totalEvents: eventCount,
        chunks: [],
        uploadedAt: new Date().toISOString(),
        status: 'uploading'
      };

      const metadataPath = `user-uploads/${userId}/${timestamp}-metadata.json`;
      const metadataBlob = new Blob([JSON.stringify(initialMetadata)], { type: 'application/json' });

      const { error: metadataError } = await supabaseClient.storage
        .from('analysis-data')
        .upload(metadataPath, metadataBlob, { upsert: true });

      if (metadataError) {
        console.warn('FileUploadService: Failed to upload initial chunk metadata:', metadataError);
      }

      // Update final metadata with all uploaded chunks
      const finalMetadata = {
        sessionId: sessionData.id,
        totalChunks: chunks.length,
        totalEvents: eventCount,
        chunks: uploadedChunks,
        uploadedAt: new Date().toISOString(),
        status: 'completed'
      };

      const finalMetadataBlob = new Blob([JSON.stringify(finalMetadata)], { type: 'application/json' });
      const { error: finalMetadataError } = await supabaseClient.storage
        .from('analysis-data')
        .update(metadataPath, finalMetadataBlob);

      if (finalMetadataError) {
        console.warn('FileUploadService: Failed to upload final chunk metadata:', finalMetadataError);
      }

      console.log(`FileUploadService: All ${chunks.length} chunks uploaded successfully`);
      return sessionData;

    } catch (error) {
      console.error('FileUploadService: Chunked upload failed:', error);
      throw error;
    }
  }

  /**
   * Load chunked data from storage
   */
  static async loadChunkedData(session: UploadedSession): Promise<ParsedUploadData> {
    if (!session.storage_path.startsWith('chunked:')) {
      throw new Error('Session is not a chunked upload');
    }

    const timestamp = session.storage_path.replace('chunked:', '');
    const userId = session.user_id;
    const metadataPath = `user-uploads/${userId}/${timestamp}-metadata.json`;

    // For local instance, we don't need service role - just use the regular client
    const supabaseClient = supabase;

    // Load chunk metadata
    const { data: metadataBlob, error: metadataError } = await supabaseClient.storage
      .from('analysis-data')
      .download(metadataPath);

    if (metadataError) {
      throw new Error(`Failed to load chunk metadata: ${metadataError.message}`);
    }

    const metadataText = await metadataBlob.text();
    const metadata = JSON.parse(metadataText);



    // Load all chunks
    const chunkPromises = metadata.chunks.map(async (chunk: any) => {
      const { data: chunkBlob, error: chunkError } = await supabaseClient.storage
        .from('analysis-data')
        .download(chunk.storagePath);

      if (chunkError) {
        console.error(`Failed to load chunk ${chunk.chunkIndex}:`, chunkError);
        return null;
      }

      const chunkText = await chunkBlob.text();
      return JSON.parse(chunkText);
    });

    const chunks = await Promise.all(chunkPromises);
    const validChunks = chunks.filter(chunk => chunk !== null);

    // Combine all chunks
    const allEvents = validChunks.reduce((acc: any[], chunk: any) => acc.concat(chunk.events), []);
    const context = validChunks[0]?.context || {};
    const combinedMetadata = {
      ...validChunks[0]?.metadata,
      chunked: true,
      totalChunks: metadata.totalChunks,
      loadedChunks: validChunks.length
    };



    return {
      events: allEvents,
      context,
      metadata: combinedMetadata
    };
  }

  /**
   * Store uploaded file data and create session record
   * Now supports chunking for large files
   */
  static async storeUploadedFile(
    file: File,
    parsedData: ParsedUploadData,
    sessionName?: string,
    onProgress?: (progress: number) => void
  ): Promise<UploadedSession> {


    // Anonymous mode - no authentication required
    const user = { id: 'anonymous' }


    const eventCount = parsedData.events.length;
    const fileSizeMB = file.size / (1024 * 1024);



    // For local instance, just store directly in database - no need for chunking
    console.log(`FileUploadService: Storing ${eventCount} events directly in local database (${fileSizeMB}MB)`);
    if (onProgress) onProgress(50); // Update progress


    // Calculate time range from events
    const eventTimestamps = parsedData.events
      .map(e => new Date(e.timestamp))
      .filter(d => !isNaN(d.getTime()))
      .sort((a, b) => a.getTime() - b.getTime())
    
    const timeRangeStart = eventTimestamps.length > 0 ? eventTimestamps[0].toISOString() : null
    const timeRangeEnd = eventTimestamps.length > 0 ? eventTimestamps[eventTimestamps.length - 1].toISOString() : null

    // For local instance, just use a simple path reference - no actual file storage needed
    const timestamp = Date.now()
    const storagePath = `local-db-${timestamp}-${file.name}`
    
    console.log('FileUploadService: Storing events directly in local database (no file storage)');
    if (onProgress) onProgress(75); // Update progress

    
    // Create session record using direct API
    const sessionData = {
      session_name: sessionName || `Analysis ${new Date().toLocaleDateString()}`,
      file_name: file.name,
      file_size_bytes: file.size,
      event_count: parsedData.events.length,
      anomaly_count: 0, // Will be updated after analysis
      time_range_start: timeRangeStart,
      time_range_end: timeRangeEnd,
      storage_path: storagePath
    }
    
    // Store ALL the actual event data in the event_data table
    // We'll store all events so users can view the complete dataset
    const eventDataToStore = {
      session_id: null, // Will be set after session creation
      event_type: 'bulk_upload',
      event_data: {
        total_events: parsedData.events.length,
        all_events: parsedData.events, // Store ALL events, not just samples
        sample_events: parsedData.events.slice(0, 10), // Keep samples for quick preview
        metadata: parsedData.metadata
      },
      timestamp: new Date().toISOString(),
      source_ip: 'local_upload',
      destination_ip: 'local_database',
      username: 'anonymous',
      computer_name: 'local_instance',
      event_id: 0
    };

    // Use direct API to bypass Supabase/PostgREST issues
    const response = await fetch('/api/upload-direct', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        sessionData,
        eventData: eventDataToStore
      })
    });

    if (!response.ok) {
      const errorResult = await response.json();
      console.error('FileUploadService: Direct API error:', errorResult);
      throw new Error(`Failed to create session record: ${errorResult.error || 'Unknown error'}`)
    }

    const result = await response.json();
    const session = result.session;
    
    if (!session) {
      throw new Error('Failed to create session record: No session returned')
    }

    console.log('FileUploadService: Successfully stored session and event data');
    if (onProgress) onProgress(100); // Update progress

    // Return the session in the expected format
    return {
      id: session.id,
      user_id: 'anonymous',
      session_name: session.session_name,
      uploaded_at: session.uploaded_at,
      file_name: session.file_name,
      file_size_bytes: session.file_size_bytes,
      event_count: session.event_count,
      anomaly_count: session.anomaly_count,
      time_range_start: session.time_range_start,
      time_range_end: session.time_range_end,
      storage_path: session.storage_path,
      is_public: true
    };
  }
  
  /**
   * Get user's uploaded sessions
   */
  static async getUserSessions(): Promise<UploadedSession[]> {
    // Use API route for server-side database queries to avoid client-side pg import issues
    try {
      const response = await fetch('/api/sessions', {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        console.error('API error:', response.status, response.statusText);
        return [];
      }

      const result = await response.json();
      return result.sessions || [];
    } catch (error) {
      console.error('Error fetching sessions:', error);
      return [];
    }
  }
  
  /**
   * Get sample data for welcome/demo sessions
   */
  static getSampleData(): ParsedUploadData {
    return {
      events: [],
      metadata: {
        eventCount: 0,
        generatedAt: new Date().toISOString(),
        generatedBy: 'Welcome Session'
      }
    };
  }

  /**
   * Load session data from database
   */
  static async loadSessionData(session: UploadedSession): Promise<ParsedUploadData> {
    console.log(`Loading session data for: ${session.id}`);

    // Check if this is a welcome session (no real data)
    if (session.storage_path === '/welcome') {
      console.log('Welcome session detected, returning sample data');
      return this.getSampleData();
    }

    try {
      // Load event data directly from the database
      const response = await fetch(`/api/session-data/${session.id}`);
      if (!response.ok) {
        throw new Error(`Failed to load session data: ${response.status}`);
      }

      const result = await response.json();

      if (!result.events || !Array.isArray(result.events)) {
        throw new Error('Invalid session data format');
      }

      return {
        events: result.events,
        metadata: {
          eventCount: result.events.length,
          generatedAt: new Date().toISOString(),
          generatedBy: 'Database Load'
        }
      };
    } catch (error) {
      console.error('Error loading session data:', error);
      throw new Error(`Failed to load session data: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Load SharpHound collection data
   */
  static async loadSharpHoundData(session: UploadedSession): Promise<ParsedUploadData> {
    const sharpHoundPath = `${session.storage_path}/data.json`;

    const { data, error } = await supabase.storage
      .from('analysis-data')
      .download(sharpHoundPath)

    if (error) {
      throw new Error(`Failed to load SharpHound data: ${error.message}`)
    }

    const text = await data.text()
    const sharpHoundCollection = JSON.parse(text)

    // Convert SharpHound data to ADTrapper format for analysis
    return this.convertSharpHoundToADTrapper(sharpHoundCollection)
  }

  /**
   * Convert SharpHound collection to ADTrapper ParsedUploadData format
   */
  static convertSharpHoundToADTrapper(collection: any): ParsedUploadData {
    const events: AuthEvent[] = []

    // Convert SharpHound users to synthetic auth events for analysis
    if (collection.files) {
      collection.files.forEach((file: any) => {
        switch (file.type) {
          case 'users':
            file.data.forEach((user: any) => {
              // Create synthetic login events based on user properties
              if (user.Properties.lastlogon && user.Properties.lastlogon > 0) {
                events.push({
                  id: `user-${user.Properties.samaccountname}-${user.Properties.lastlogon}`,
                  timestamp: new Date(user.Properties.lastlogon * 1000),
                  eventId: '4624', // Successful logon
                  userName: user.Properties.samaccountname,
                  domainName: user.Properties.domain,
                  computerName: user.Properties.domain.toUpperCase() + '-DC',
                  status: 'Success',
                  logonType: user.Properties.admincount ? 'RemoteInteractive' : 'Interactive',
                  rawData: {
                    sharpHoundUser: true,
                    properties: user.Properties,
                    delegation: user.AllowedToDelegate,
                    aces: user.Aces
                  }
                })
              }
            })
            break

          case 'computers':
            file.data.forEach((computer: any) => {
              // Create synthetic computer events
              if (computer.Properties.lastlogon && computer.Properties.lastlogon > 0) {
                events.push({
                  id: `computer-${computer.Properties.samaccountname}-${computer.Properties.lastlogon}`,
                  timestamp: new Date(computer.Properties.lastlogon * 1000),
                  eventId: '4624',
                  computerName: computer.Properties.samaccountname,
                  domainName: computer.Properties.domain,
                  status: 'Success',
                  logonType: 'Network',
                  rawData: {
                    sharpHoundComputer: true,
                    properties: computer.Properties,
                    delegation: computer.AllowedToDelegate,
                    aces: computer.Aces
                  }
                })
              }
            })
            break
        }
      })
    }

    return {
      events,
      metadata: {
        eventCount: events.length,
        generatedAt: new Date().toISOString(),
        generatedBy: 'SharpHound',
        timeRangeHours: 0 // Static collection, no time range
      },
      context: {
        sessionId: `sharphound-${collection.id}`,
        organizationId: collection.metadata?.domain || 'unknown',
        timeRange: {
          start: new Date(collection.created_at),
          end: new Date(collection.created_at)
        },
        dataType: 'sharphound',
        sharpHoundData: collection.files ? this.extractSharpHoundData(collection.files) : undefined
      }
    }
  }

  /**
   * Extract SharpHound data from collection files
   */
  static extractSharpHoundData(files: any[]): any {
    const data: any = {}

    files.forEach(file => {
      switch (file.type) {
        case 'users':
          data.users = file.data
          break
        case 'computers':
          data.computers = file.data
          break
        case 'groups':
          data.groups = file.data
          break
        case 'domains':
          data.domains = file.data
          break
        case 'ous':
          data.ous = file.data
          break
        case 'gpos':
          data.gpos = file.data
          break
        case 'containers':
          data.containers = file.data
          break
        case 'certificates':
          data.certificates = file.data
          break
      }
    })

    return data
  }
  
  /**
   * Sanitize filename for storage (remove invalid characters)
   */
  static sanitizeFilename(filename: string): string {
    return filename
      .replace(/[^\w\s-_.]/g, '') // Remove special characters except word chars, spaces, hyphens, underscores, dots
      .replace(/\s+/g, '_') // Replace spaces with underscores
      .substring(0, 100); // Limit length
  }

  /**
   * Process API upload (used by API route) - Uses existing chunked upload system
   */
  static async processApiUpload(
    files: Array<{ name: string; content: ArrayBuffer; size: number; type: string }>,
    userId: string,
    sessionName: string
  ): Promise<{
    sessionId: string
    totalEvents: number
    anomaliesFound: number
  }> {
    try {
      // For API uploads, we'll process the first file only (simplified approach)
      const file = files[0];
      if (!file) {
        throw new Error('No files provided');
      }

      // Parse the JSON content
      const text = new TextDecoder().decode(file.content);
      const parsedData = this.parseUploadedData(JSON.parse(text));

      // Create a mock file object for the existing upload system
      const mockFile = {
        name: file.name,
        size: file.size,
        type: file.type,
        arrayBuffer: () => Promise.resolve(file.content)
      } as File;

      // Use the simplified database-only upload
      const session = await this.storeUploadedFile(mockFile, parsedData, sessionName);

      return {
        sessionId: session.id,
        totalEvents: parsedData.events.length,
        anomaliesFound: 0 // Will be updated by analytics processing
      };



      return {
        sessionId: session.id,
        totalEvents: parsedData.events.length,
        anomaliesFound: 0 // Will be updated by analytics processing
      }
    } catch (error) {
      console.error('API upload processing error:', error);
      throw error;
    }
  }

  /**
   * Delete a session and all associated data
   */
  static async deleteSession(sessionId: string): Promise<void> {
    console.log(`Deleting session: ${sessionId}`);

    try {
      // Use direct API call to delete session (bypasses Supabase mock issues)
      const response = await fetch(`/api/session-delete/${sessionId}`, {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(`Failed to delete session: ${errorData.error || response.statusText}`);
      }

      const result = await response.json();

      if (!result.success) {
        throw new Error(`Failed to delete session: ${result.message}`);
      }

      console.log(`Successfully deleted session: ${sessionId}`);

    } catch (error) {
      console.error('Error in deleteSession:', error);
      throw error;
    }
  }
  
  /**
   * Update session with analysis results
   */
  static async updateSessionAnalysis(sessionId: string, anomalyCount: number): Promise<void> {
    try {
      const response = await fetch('/api/session-analysis', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          sessionId,
          anomalyCount
        })
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(`Failed to update session analysis: ${errorData.error || response.statusText}`);
      }

      const result = await response.json();
      console.log('Session analysis updated successfully:', result);
    } catch (error) {
      console.error('Error updating session analysis:', error);
      throw error;
    }
  }
}
