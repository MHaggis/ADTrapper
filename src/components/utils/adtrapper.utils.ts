import { GraphData, Alert, Stats, FilterState, GraphNode, GraphEdge, ParsedData } from '../types/adtrapper.types';
import { AuthEvent } from '@/analytics/types';

// Helper function to ensure data has proper structure
export const normalizeData = (data: any): GraphData => {
  if (!data) return {
    nodes: [],
    edges: [],
    metadata: { eventCount: 0, timeRange: '', generatedAt: new Date() },
    rawLogs: []
  };

  return {
    nodes: Array.isArray(data.nodes) ? data.nodes : [],
    edges: Array.isArray(data.edges) ? data.edges : [],
    metadata: data.metadata || { eventCount: 0, timeRange: '', generatedAt: new Date() },
    rawLogs: Array.isArray(data.rawLogs) ? data.rawLogs : []
  };
};

export const generateAlerts = (logData: any): Alert[] => {
  return [
    {
      id: 1,
      type: 'critical',
      title: 'Potential Security Breach',
      message: 'Multiple failed logins from external IP followed by successful login',
      timestamp: new Date(),
      read: false
    },
    {
      id: 2,
      type: 'warning',
      title: 'Unusual Geographic Activity',
      message: 'User logged in from 3 different countries within 1 hour',
      timestamp: new Date(Date.now() - 300000),
      read: false
    },
    {
      id: 3,
      type: 'info',
      title: 'New Device Registered',
      message: 'Unknown computer "LAPTOP-XYZ123" connected to domain',
      timestamp: new Date(Date.now() - 600000),
      read: true
    }
  ];
};

// Extract available IPs and hostnames from data
export const extractAvailableFilters = (nodes: GraphNode[]): { availableIPs: string[], availableHostnames: string[] } => {
  const ips = new Set<string>();
  const hostnames = new Set<string>();

  nodes.forEach((node: GraphNode) => {
    if (node.type === 'ip' && node.label) {
      ips.add(node.label);
    }
    if (node.type === 'computer' && node.label) {
      hostnames.add(node.label);
    }
  });

  return {
    availableIPs: Array.from(ips).sort(),
    availableHostnames: Array.from(hostnames).sort()
  };
};

// Apply filters to graph data
export const applyFilters = (data: GraphData, filters: FilterState): GraphData => {
  // Ensure data has proper structure with fallback to empty arrays
  const safeData = {
    nodes: Array.isArray(data.nodes) ? data.nodes : [],
    edges: Array.isArray(data.edges) ? data.edges : []
  };

  let filtered = { nodes: [...safeData.nodes], edges: [...safeData.edges] };

  // Filter nodes
  filtered.nodes = filtered.nodes.filter((node: GraphNode) => {
    // Type filters
    if (node.type === 'user' && !filters.showUsers) return false;
    if (node.type === 'computer' && !filters.showComputers) return false;
    if (node.type === 'ip' && !filters.showIPs) return false;

    // IP and hostname filters
    if (node.type === 'ip' && filters.selectedIPs.length > 0) {
      return filters.selectedIPs.includes(node.label);
    }
    if (node.type === 'computer' && filters.selectedHostnames.length > 0) {
      return filters.selectedHostnames.includes(node.label);
    }

    return true;
  });

  // Filter edges
  filtered.edges = filtered.edges.filter((edge: GraphEdge) => {
    if (edge.status === 'Failed' && !filters.showFailed) return false;
    if (edge.status === 'Success' && !filters.showSuccess) return false;
    if (edge.anomaly && !filters.showAnomalies) return false;
    return true;
  });

  return {
    ...data,
    nodes: filtered.nodes,
    edges: filtered.edges
  };
};

// Calculate statistics from graph data
export const calculateStats = (data: GraphData): Stats => {
  // Add null checks to prevent errors when data is undefined
  if (!data || !data.nodes || !data.edges) {
    return { totalUsers: 0, privilegedUsers: 0, failedLogins: 0, externalIPs: 0, highRiskNodes: 0, anomalyEdges: 0 };
  }

  const totalUsers = data.nodes.filter((n: GraphNode) => n.type === 'user').length;
  const privilegedUsers = data.nodes.filter((n: GraphNode) => n.type === 'user' && n.privileged).length;
  const failedLogins = data.edges.filter((e: GraphEdge) => e.status === 'Failed').length;
  const externalIPs = data.nodes.filter((n: GraphNode) => n.type === 'ip' && n.country && n.country !== 'USA').length;
  const highRiskNodes = data.nodes.filter((n: GraphNode) => n.riskScore > 80).length;
  const anomalyEdges = data.edges.filter((e: GraphEdge) => e.anomaly).length;

  return { totalUsers, privilegedUsers, failedLogins, externalIPs, highRiskNodes, anomalyEdges };
};

// Convert events to graph format for visualization
export const convertEventsToGraphFormat = (events: AuthEvent[], context?: any): GraphData => {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const nodeIds = new Set<string>();

  events.forEach(event => {
    // Add user nodes
    if (event.userName && !nodeIds.has(`user_${event.userName}`)) {
      const userProfile = context?.userProfiles?.find((p: any) => p.userName === event.userName);
      nodes.push({
        id: `user_${event.userName}`,
        label: event.userName,
        type: 'user',
        department: userProfile?.department,
        privileged: userProfile?.privileged || false,
        enabled: userProfile?.enabled !== false,
        riskScore: userProfile?.privileged ? 75 : 20
      });
      nodeIds.add(`user_${event.userName}`);
    }

    // Add computer nodes
    if (event.computerName && !nodeIds.has(`computer_${event.computerName}`)) {
      nodes.push({
        id: `computer_${event.computerName}`,
        label: event.computerName,
        type: 'computer',
        riskScore: 30
      });
      nodeIds.add(`computer_${event.computerName}`);
    }

    // Add IP nodes
    if (event.sourceIp && !nodeIds.has(`ip_${event.sourceIp}`)) {
      const ipInfo = context?.ipIntelligence?.find((ip: any) => ip.ip === event.sourceIp);
      nodes.push({
        id: `ip_${event.sourceIp}`,
        label: event.sourceIp,
        type: 'ip',
        country: ipInfo?.country,
        city: ipInfo?.city,
        tor: ipInfo?.isTor || false,
        riskScore: ipInfo?.riskScore || 10
      });
      nodeIds.add(`ip_${event.sourceIp}`);
    }

          // Add edges - map Logoff to Success for GraphAnalysis compatibility
      if (event.userName && event.computerName) {
        edges.push({
          source: `user_${event.userName}`,
          target: `computer_${event.computerName}`,
          type: 'login',
          status: event.status === 'Logoff' ? 'Success' : event.status,
          logonType: event.logonType,
          timestamp: new Date(event.timestamp),
          anomaly: false
        });
      }

      if (event.sourceIp && event.computerName) {
        edges.push({
          source: `ip_${event.sourceIp}`,
          target: `computer_${event.computerName}`,
          type: 'connection',
          status: event.status === 'Logoff' ? 'Success' : event.status,
          timestamp: new Date(event.timestamp),
          anomaly: false
        });
      }
  });

  return {
    nodes,
    edges,
    metadata: {
      eventCount: events.length,
      timeRange: '24 hours',
      generatedAt: new Date()
    },
    rawLogs: events // Preserve the original events for analytics
  };
};

// Parse uploaded file content
export const parseUploadedFile = (file: File, text: string): ParsedData => {
  if (file.name.endsWith('.json')) {
    const jsonData = JSON.parse(text);

    // Handle PowerShell ConvertTo-Json output (array of objects)
    if (Array.isArray(jsonData)) {
      console.log(`Parsed PowerShell JSON array with ${jsonData.length} events`);

      // Convert PowerShell event objects to ADTrapper format
      const events: AuthEvent[] = jsonData.map((psEvent: any, index: number) => {
        try {
          // Parse PowerShell timestamp (usually ISO string)
          const timestamp = psEvent.TimeCreated ? new Date(psEvent.TimeCreated) : new Date();

          // Extract event details from PowerShell object
          const eventDetails = parsePowerShellEvent(psEvent);

          return {
            id: `ps_event_${index}_${Date.now()}`,
            timestamp: timestamp,
            eventId: psEvent.Id?.toString() || '0',
            eventType: "Authentication", // Default for security events
            computerName: psEvent.Computer || psEvent.MachineName || 'Unknown',
            userName: eventDetails.userName,
            // Extract domain from computer name if domain is missing
            domainName: (() => {
              let domainName = eventDetails.domainName;
              if (!domainName || domainName === 'COMPANY') {
                if (eventDetails.computerName) {
                  domainName = extractDomainFromComputerName(eventDetails.computerName) || 'COMPANY';
                }
              }
              return domainName;
            })(),
            sourceIp: eventDetails.sourceIp,
            logonType: eventDetails.logonType || 'Interactive',
            status: mapEventIdToStatus(psEvent.Id?.toString() || '0') as 'Success' | 'Failed' | 'Logoff'
          };
        } catch (error) {
          console.warn(`Error parsing PowerShell event ${index}:`, error);
          return null;
        }
      }).filter(event => event !== null) as AuthEvent[];

      return {
        events: events,
        metadata: {
          eventCount: events.length,
          generatedAt: new Date().toISOString(),
          generatedBy: 'PowerShell JSON Export',
          jsonFormat: 'powershell'
        },
        context: {
          sessionId: 'powershell-session',
          organizationId: 'unknown',
          timeRange: {
            start: new Date(Date.now() - 24 * 60 * 60 * 1000), // Last 24 hours
            end: new Date()
          },
          userProfiles: [] // Empty array for PowerShell data - no user profile info available
        }
      };
    }

    // Handle structured JSON format (from our tools)
    const events = (jsonData.events || []).map((event: any) => {
      // Extract domain from computer name if domain is missing
      if (event.computerName && (!event.domainName || event.domainName === 'COMPANY')) {
        const extractedDomain = extractDomainFromComputerName(event.computerName);
        if (extractedDomain) {
          return { ...event, domainName: extractedDomain };
        }
      }
      return event;
    });

    return {
      events: events,
      metadata: jsonData.metadata || { eventCount: 0 },
      context: jsonData.context
    };
  } else if (file.name.endsWith('.csv')) {
    // Handle PowerShell CSV export format
    const lines = text.split('\n').filter(line => line.trim());

    if (lines.length === 0) {
      throw new Error('CSV file appears to be empty');
    }

    // Check if it has headers (PowerShell exports usually do)
    const hasHeaders = lines[0].includes('TimeCreated') || lines[0].includes('Id') || lines[0].includes('Message');
    const dataLines = hasHeaders ? lines.slice(1) : lines;

    const csvData: AuthEvent[] = dataLines
      .filter(line => line.trim()) // Skip empty lines
      .map((line, index) => {
        try {
          // Handle CSV parsing more carefully (PowerShell might quote fields)
          const values = parseCSVLine(line);

          if (values.length < 3) {
            console.warn(`Skipping malformed CSV line ${index + 1}: insufficient columns`);
            return null;
          }

          // PowerShell CSV format: TimeCreated, Id, Message
          const timeCreated = values[0]?.trim();
          const eventId = values[1]?.trim();
          const message = values[2]?.trim();

          // Parse the Message field to extract event details
          const eventDetails = parseEventMessage(message);

          // Extract domain from computer name if domain is missing
          let domainName = eventDetails.domainName;
          if (!domainName || domainName === 'COMPANY') {
            if (eventDetails.computerName) {
              domainName = extractDomainFromComputerName(eventDetails.computerName) || 'COMPANY';
            }
          }

          return {
            id: `event_${index}`,
            timestamp: parseCSVDate(timeCreated),
            eventId: eventId,
            eventType: "Authentication", // Based on event ID range
            computerName: eventDetails.computerName || 'Unknown',
            userName: eventDetails.userName,
            domainName: domainName,
            sourceIp: eventDetails.sourceIp,
            logonType: eventDetails.logonType || 'Interactive',
            status: mapEventIdToStatus(eventId) as 'Success' | 'Failed' | 'Logoff'
          };
        } catch (error) {
          console.warn(`Error parsing CSV line ${index + 1}:`, error);
          return null;
        }
      })
      .filter(event => event !== null) as AuthEvent[];

    console.log(`Parsed ${csvData.length} events from CSV (${dataLines.length} lines processed)`);

    return {
      events: csvData,
      metadata: {
        eventCount: csvData.length,
        generatedAt: new Date().toISOString(),
        generatedBy: 'PowerShell CSV Export',
        csvFormat: 'powershell'
      },
      context: {
        sessionId: 'powershell-csv-session',
        organizationId: 'unknown',
        timeRange: {
          start: new Date(Date.now() - 24 * 60 * 60 * 1000), // Last 24 hours
          end: new Date()
        },
        userProfiles: [] // Empty array for PowerShell CSV data - no user profile info available
      }
    };
  } else {
    throw new Error('Unsupported file format. Supported: JSON, CSV');
  }
};

// Helper function to parse CSV line more carefully
function parseCSVLine(line: string): string[] {
  const values: string[] = [];
  let current = '';
  let inQuotes = false;
  let i = 0;

  while (i < line.length) {
    const char = line[i];

    if (char === '"') {
      if (inQuotes && line[i + 1] === '"') {
        // Escaped quote
        current += '"';
        i += 2;
      } else {
        // Toggle quote state
        inQuotes = !inQuotes;
        i++;
      }
    } else if (char === ',' && !inQuotes) {
      // Field separator
      values.push(current.trim());
      current = '';
      i++;
    } else {
      current += char;
      i++;
    }
  }

  // Add the last field
  values.push(current.trim());

  return values;
}

// Extract domain from computer name (e.g., "host.domain.com" -> "domain.com")
function extractDomainFromComputerName(computerName: string): string | null {
  if (!computerName || typeof computerName !== 'string') return null;

  // Remove protocol prefixes if any
  computerName = computerName.replace(/^https?:\/\//, '');

  // Split by dots and extract domain
  const parts = computerName.split('.');
  if (parts.length >= 2) {
    // Take last 2 parts for domain (e.g., domain.com)
    const domain = parts.slice(-2).join('.').toUpperCase();

    // Skip invalid domains
    if (domain.length > 3 && !domain.includes('LOCALHOST') && !domain.includes('INVALID')) {
      return domain;
    }
  }

  return null;
}

// Parse event message to extract details
function parseEventMessage(message: string): any {
  if (!message) return {};

  const details: any = {};

  // Extract common patterns from Windows Event Log messages
  const patterns = {
    userName: /Account Name:\s*([^\r\n]+)/i,
    domainName: /Account Domain:\s*([^\r\n]+)/i,
    computerName: /Computer:\s*([^\r\n]+)/i,
    sourceIp: /Source Network Address:\s*([^\r\n]+)/i,
    logonType: /Logon Type:\s*(\d+)/i
  };

  // Additional domain extraction patterns
  const domainPatterns = [
    /Account Domain:\s*([^\r\n]+)/i,
    /Domain:\s*([^\r\n]+)/i,
    /Domain Name:\s*([^\r\n]+)/i,
    /Logon Domain:\s*([^\r\n]+)/i,
    /Authentication Package:\s*([^\r\n]+)/i, // Sometimes domain is in auth package
    // Try to extract domain from user@domain format
    /([^\s\\@]+)@([^\s]+)/, // user@domain
    // Extract from computer name (often computer.domain.com)
    /([^\.]+)\.([^\.]+(?:\.[^\.]+)*)/ // computer.domain.local
  ];

  for (const [key, pattern] of Object.entries(patterns)) {
    const match = message.match(pattern);
    if (match && match[1] && match[1] !== '-' && match[1] !== 'N/A') {
      if (key === 'logonType') {
        // Convert logon type number to string
        const typeMap: { [key: string]: string } = {
          '2': 'Interactive',
          '3': 'Network',
          '4': 'Batch',
          '5': 'Service',
          '7': 'Unlock',
          '8': 'NetworkCleartext',
          '9': 'NewCredentials',
          '10': 'RemoteInteractive',
          '11': 'CachedInteractive'
        };
        details[key] = typeMap[match[1]] || 'Interactive';
      } else {
        details[key] = match[1].trim();
      }
    }
  }

  // Enhanced domain extraction if primary pattern didn't work
  if (!details.domainName || details.domainName === 'COMPANY') {
    for (const pattern of domainPatterns) {
      const match = message.match(pattern);
      if (match && match[1] && match[1] !== '-' && match[1] !== 'N/A') {
        let extractedDomain = match[1].trim();

        // Clean up extracted domain
        extractedDomain = extractedDomain.toUpperCase();

        // Skip common false positives
        if (!['MICROSOFT', 'NT AUTHORITY', 'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'ANONYMOUS LOGON'].includes(extractedDomain)) {
          // For user@domain pattern, take the domain part
          if (pattern.source.includes('@') && match[2]) {
            extractedDomain = match[2].toUpperCase();
          }
          // For computer.domain pattern, extract domain
          else if (pattern.source.includes('\\.') && match[2]) {
            // Extract domain from computer.name.domain format
            const parts = match[2].split('.');
            if (parts.length >= 2) {
              extractedDomain = parts.slice(-2).join('.').toUpperCase();
            }
          }

          // Only use if it looks like a domain (contains dot or is not a common username)
          if (extractedDomain.includes('.') || !['ADMIN', 'USER', 'GUEST', 'TEST'].includes(extractedDomain)) {
            details.domainName = extractedDomain;
            break; // Use first valid match
          }
        }
      }
    }
  }

  return details;
}

// Parse CSV date format
function parseCSVDate(dateStr: string): Date {
  if (!dateStr) return new Date();

  try {
    // PowerShell CSV dates are usually in ISO format or localized
    const date = new Date(dateStr);
    if (!isNaN(date.getTime())) {
      return date;
    }

    // Try parsing common formats
    const formats = [
      /^(\d{2})\/(\d{2})\/(\d{4})\s+(\d{2}):(\d{2}):(\d{2})$/, // MM/dd/yyyy HH:mm:ss
      /^(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})$/, // yyyy-MM-dd HH:mm:ss
    ];

    for (const format of formats) {
      const match = dateStr.match(format);
      if (match) {
        const [, ...parts] = match;
        if (format === formats[0]) {
          // MM/dd/yyyy format
          return new Date(parseInt(parts[2]), parseInt(parts[0]) - 1, parseInt(parts[1]),
                         parseInt(parts[3]), parseInt(parts[4]), parseInt(parts[5]));
        } else {
          // yyyy-MM-dd format
          return new Date(parseInt(parts[0]), parseInt(parts[1]) - 1, parseInt(parts[2]),
                         parseInt(parts[3]), parseInt(parts[4]), parseInt(parts[5]));
        }
      }
    }

    console.warn(`Could not parse date: ${dateStr}`);
    return new Date();
  } catch (error) {
    console.warn(`Error parsing date ${dateStr}:`, error);
    return new Date();
  }
}

// Parse PowerShell event object to extract event details
function parsePowerShellEvent(psEvent: any): any {
  if (!psEvent) return {};

  const details: any = {};

  // PowerShell events have a Message property with formatted text
  const message = psEvent.Message || '';

  if (message) {
    // Extract common patterns from Windows Event Log messages
    const patterns = {
      userName: /Account Name:\s*([^\r\n]+)/i,
      domainName: /Account Domain:\s*([^\r\n]+)/i,
      computerName: /Computer:\s*([^\r\n]+)/i,
      sourceIp: /Source Network Address:\s*([^\r\n]+)/i,
      logonType: /Logon Type:\s*(\d+)/i
    };

    for (const [key, pattern] of Object.entries(patterns)) {
      const match = message.match(pattern);
      if (match && match[1] && match[1] !== '-' && match[1] !== 'N/A') {
        if (key === 'logonType') {
          // Convert logon type number to string
          const typeMap: { [key: string]: string } = {
            '2': 'Interactive',
            '3': 'Network',
            '4': 'Batch',
            '5': 'Service',
            '7': 'Unlock',
            '8': 'NetworkCleartext',
            '9': 'NewCredentials',
            '10': 'RemoteInteractive',
            '11': 'CachedInteractive'
          };
          details[key] = typeMap[match[1]] || 'Interactive';
        } else {
          details[key] = match[1].trim();
        }
      }
    }
  }

  return details;
}

// Map event ID to status
function mapEventIdToStatus(eventId: string): string {
  const successIds = ['4624', '4647', '4648', '4740', '4742', '4768', '4778', '4779', '5140'];
  const failureIds = ['4625', '4769', '4771', '4776'];
  const logoffIds = ['4634'];

  if (successIds.includes(eventId)) return 'Success';
  if (failureIds.includes(eventId)) return 'Failed';
  if (logoffIds.includes(eventId)) return 'Logoff';

  return 'Success'; // Default
}

// Get theme classes based on dark mode
export const getThemeClasses = (darkMode: boolean) => ({
  themeClasses: darkMode
    ? 'bg-gray-900 text-white'
    : 'bg-gray-50 text-gray-900',
  cardClasses: darkMode
    ? 'bg-gray-800 border-gray-700'
    : 'bg-white border-gray-200'
});
