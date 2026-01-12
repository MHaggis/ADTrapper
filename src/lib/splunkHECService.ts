// Splunk HTTP Event Collector (HEC) Service
// Handles sending logs to Splunk HEC endpoint

interface SplunkHECConfig {
  enabled: boolean;
  endpoint: string;
  token: string;
  index?: string;
  sourcetype: string;
  autoSend: boolean;
  sendAllEvents?: boolean;
  sendAnomalies?: boolean;
  ignoreSslErrors?: boolean;
}

interface SplunkEvent {
  event: any;
  time?: number;
  host?: string;
  source?: string;
  sourcetype?: string;
  index?: string;
}

class SplunkHECService {
  private static instance: SplunkHECService;

  public static getInstance(): SplunkHECService {
    if (!SplunkHECService.instance) {
      SplunkHECService.instance = new SplunkHECService();
    }
    return SplunkHECService.instance;
  }

  // Test connection to Splunk HEC via API proxy
  static async testConnection(endpoint: string, token: string, ignoreSslErrors: boolean = true): Promise<boolean> {
    try {
      console.log('Testing Splunk HEC connection via API proxy to:', endpoint);
      
      const response = await fetch('/api/splunk-hec', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          action: 'test',
          endpoint: endpoint,
          token: token,
          ignoreSslErrors: ignoreSslErrors
        })
      });

      const result = await response.json();
      
      if (result.success) {
        console.log('Splunk HEC connection test successful:', result.message);
        return true;
      } else {
        console.error('Splunk HEC connection test failed:', result.error);
        if (result.details) {
          console.error('Details:', result.details);
        }
        return false;
      }
    } catch (error) {
      console.error('Error testing Splunk HEC connection:', error);
      return false;
    }
  }

  // Normalize endpoint URL to ensure proper HEC collector path
  static normalizeEndpoint(endpoint: string): string {
    if (!endpoint) return '';
    
    // Remove trailing slashes
    let normalizedEndpoint = endpoint.replace(/\/+$/, '');
    
    // If endpoint doesn't include the collector path, add it
    if (!normalizedEndpoint.includes('/services/collector')) {
      normalizedEndpoint += '/services/collector';
    }
    
    return normalizedEndpoint;
  }

  // Validate endpoint format
  static validateEndpoint(endpoint: string): { isValid: boolean; message: string } {
    if (!endpoint) {
      return { isValid: false, message: 'Endpoint URL is required' };
    }

    try {
      const url = new URL(endpoint);
      
      // Check protocol
      if (!['http:', 'https:'].includes(url.protocol)) {
        return { isValid: false, message: 'Endpoint must use HTTP or HTTPS protocol' };
      }
      
      // Check for common HEC port
      if (url.port && !['8088', '443', '80', '8000'].includes(url.port)) {
        return { isValid: false, message: 'Unusual port detected. Splunk HEC typically uses port 8088' };
      }
      
      return { isValid: true, message: 'Valid endpoint format' };
    } catch (error) {
      return { isValid: false, message: 'Invalid URL format' };
    }
  }

  // Send logs to Splunk HEC via API proxy
  static async sendLogs(logs: any[], config: SplunkHECConfig): Promise<boolean> {
    if (!config.enabled || !config.endpoint || !config.token) {
      console.error('Splunk HEC not properly configured');
      return false;
    }

    try {
      // Convert ADTrapper logs to Splunk events
      const splunkEvents = SplunkHECService.convertToSplunkEvents(logs, config);

      // Send events to Splunk HEC via API proxy
      const response = await fetch('/api/splunk-hec', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          action: 'send',
          endpoint: config.endpoint,
          token: config.token,
          data: splunkEvents,
          ignoreSslErrors: config.ignoreSslErrors ?? true
        })
      });

      const result = await response.json();
      
      if (result.success) {
        console.log(`Successfully sent ${logs.length} logs to Splunk:`, result.message);
        return true;
      } else {
        console.error('Failed to send logs to Splunk:', result.error);
        if (result.details) {
          console.error('Details:', result.details);
        }
        return false;
      }
    } catch (error) {
      console.error('Error sending logs to Splunk:', error);
      return false;
    }
  }

  // Convert ADTrapper logs to Splunk event format
  private static convertToSplunkEvents(logs: any[], config: SplunkHECConfig): SplunkEvent | SplunkEvent[] {
    const events = logs.map(log => ({
      event: {
        ...log,
        // Add ADTrapper metadata
        adtrapper: {
          version: '1.0.0',
          processed_at: new Date().toISOString(),
          source: 'adtrapper-ui'
        }
      },
      time: log.timestamp ? new Date(log.timestamp).getTime() / 1000 : Math.floor(Date.now() / 1000),
      host: log.computerName || log.host || 'adtrapper',
      source: 'adtrapper:events',
      sourcetype: config.sourcetype,
      ...(config.index && { index: config.index })
    }));

    // Return single event for single log, array for multiple logs
    return events.length === 1 ? events[0] : events;
  }

  // Send single event to Splunk (for automatic sending)
  async sendEvent(event: any, config: SplunkHECConfig): Promise<boolean> {
    if (!config.enabled || !config.autoSend) {
      return true; // Not an error if auto-send is disabled
    }

    return SplunkHECService.sendLogs([event], config);
  }

  // Get configuration from localStorage
  static getConfig(): SplunkHECConfig | null {
    try {
      const saved = localStorage.getItem('adtSplunkHEC');
      return saved ? JSON.parse(saved) : null;
    } catch (error) {
      console.error('Error loading Splunk HEC config:', error);
      return null;
    }
  }

  // Save configuration to localStorage
  static saveConfig(config: SplunkHECConfig): void {
    try {
      localStorage.setItem('adtSplunkHEC', JSON.stringify(config));
    } catch (error) {
      console.error('Error saving Splunk HEC config:', error);
    }
  }
}

export default SplunkHECService;
