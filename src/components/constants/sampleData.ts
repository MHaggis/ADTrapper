import { GraphData } from '../types/adtrapper.types';

// Enhanced sample data with more sophisticated patterns
export const sampleData: GraphData = {
  nodes: [
    { id: 'user_admin', label: 'admin', type: 'user', department: 'IT', enabled: true, privileged: true, lastSeen: new Date(), riskScore: 95 },
    { id: 'user_john.doe', label: 'john.doe', type: 'user', department: 'IT', enabled: true, privileged: true, lastSeen: new Date(), riskScore: 75 },
    { id: 'user_jane.smith', label: 'jane.smith', type: 'user', department: 'Finance', enabled: true, privileged: false, lastSeen: new Date(), riskScore: 20 },
    { id: 'user_temp.account', label: 'temp.account', type: 'user', department: 'Unknown', enabled: false, privileged: false, lastSeen: new Date(), riskScore: 85 },
    { id: 'computer_DC01', label: 'DC01', type: 'computer', os: 'Windows Server 2022', riskScore: 60 },
    { id: 'computer_WS001', label: 'WS001', type: 'computer', os: 'Windows 11', riskScore: 30 },
    { id: 'computer_SUSPICIOUS', label: 'UNKNOWN-PC', type: 'computer', os: 'Unknown', riskScore: 90 },
    { id: 'ip_192.168.1.100', label: '192.168.1.100', type: 'ip', country: 'USA', city: 'New York', riskScore: 10 },
    { id: 'ip_203.45.67.89', label: '203.45.67.89', type: 'ip', country: 'China', city: 'Beijing', riskScore: 95 },
    { id: 'ip_185.220.101.42', label: '185.220.101.42', type: 'ip', country: 'Russia', city: 'Moscow', riskScore: 98, tor: true },
  ],
  edges: [
    { source: 'user_admin', target: 'computer_DC01', type: 'login', status: 'Success', logonType: 'RemoteInteractive', timestamp: new Date(), anomaly: false },
    { source: 'user_john.doe', target: 'computer_WS001', type: 'login', status: 'Success', logonType: 'Interactive', timestamp: new Date(), anomaly: false },
    { source: 'user_jane.smith', target: 'computer_WS001', type: 'login', status: 'Failed', logonType: 'Interactive', timestamp: new Date(), anomaly: true },
    { source: 'user_temp.account', target: 'computer_DC01', type: 'login', status: 'Failed', logonType: 'Network', timestamp: new Date(), anomaly: true },
    { source: 'ip_192.168.1.100', target: 'computer_WS001', type: 'connection', status: 'Success', timestamp: new Date(), anomaly: false },
    { source: 'ip_203.45.67.89', target: 'computer_DC01', type: 'connection', status: 'Failed', timestamp: new Date(), anomaly: true },
    { source: 'ip_185.220.101.42', target: 'computer_SUSPICIOUS', type: 'connection', status: 'Success', timestamp: new Date(), anomaly: true },
  ],
  metadata: {
    eventCount: 15847,
    timeRange: '24 hours',
    generatedAt: new Date(),
    anomalyCount: 23
  },
  rawLogs: []
};

// Default filter state
export const defaultFilters = {
  showUsers: true,
  showComputers: true,
  showIPs: true,
  showFailed: true,
  showSuccess: true,
  showAnomalies: true,
  timeRange: 'all',
  selectedIPs: [] as string[],
  selectedHostnames: [] as string[],
  availableIPs: [] as string[],
  availableHostnames: [] as string[]
};

// Tab configuration
export const tabConfig = [
  { id: 'dashboard', label: 'Dashboard', icon: 'Activity' },
  { id: 'graph', label: 'Graph Analysis', icon: 'Layers' },
  { id: 'alerts', label: 'Alerts', icon: 'Bell' },
  { id: 'assets', label: 'Assets & Identities', icon: 'Users' },
  { id: 'anomalies', label: 'Analytics', icon: 'Brain' },
  { id: 'sessions', label: 'My Data', icon: 'Database' },
  { id: 'upload', label: 'Data Upload', icon: 'Upload' },
  { id: 'settings', label: 'Settings', icon: 'Settings' }
];

// Alert severity colors mapping
export const severityColors = {
  critical: { bg: 'bg-red-500/20', text: 'text-red-600', border: 'border-red-500' },
  high: { bg: 'bg-orange-500/20', text: 'text-orange-600', border: 'border-orange-500' },
  medium: { bg: 'bg-yellow-500/20', text: 'text-yellow-600', border: 'border-yellow-500' },
  low: { bg: 'bg-blue-500/20', text: 'text-blue-600', border: 'border-blue-500' },
  info: { bg: 'bg-gray-500/20', text: 'text-gray-600', border: 'border-gray-500' }
};

// Node type colors mapping
export const nodeTypeColors = {
  user: '#3b82f6',
  computer: '#10b981',
  ip: '#6b7280'
};

// Node type icons mapping
export const nodeTypeIcons = {
  user: '👤',
  computer: '💻',
  ip: '🌐'
};

// Default empty graph data structure
export const emptyGraphData: GraphData = {
  nodes: [],
  edges: [],
  metadata: {
    eventCount: 0,
    timeRange: '',
    generatedAt: new Date()
  },
  rawLogs: []
};
