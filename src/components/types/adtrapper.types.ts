// Types for ADTrapper component and related functionality

import { Anomaly, AuthEvent, AnalyticsContext } from '@/analytics/types';

export interface GraphNode {
  id: string;
  label: string;
  type: 'user' | 'computer' | 'ip';
  x?: number;
  y?: number;
  vx?: number;
  vy?: number;
  department?: string;
  enabled?: boolean;
  privileged?: boolean;
  lastSeen?: Date;
  riskScore: number;
  os?: string;
  country?: string;
  city?: string;
  tor?: boolean;
}

export interface GraphEdge {
  source: string;
  target: string;
  type: 'login' | 'connection';
  status: 'Success' | 'Failed';
  logonType?: string;
  timestamp: Date;
  anomaly?: boolean;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  metadata: {
    eventCount: number;
    timeRange: string;
    generatedAt: Date;
    anomalyCount?: number;
  };
  rawLogs?: any[];
}

export interface Alert {
  id: number;
  type: 'critical' | 'warning' | 'info';
  title: string;
  message: string;
  timestamp: Date;
  read: boolean;
}

export interface FilterState {
  showUsers: boolean;
  showComputers: boolean;
  showIPs: boolean;
  showFailed: boolean;
  showSuccess: boolean;
  showAnomalies: boolean;
  timeRange: string;
  selectedIPs: string[];
  selectedHostnames: string[];
  availableIPs: string[];
  availableHostnames: string[];
}

export interface Stats {
  totalUsers: number;
  privilegedUsers: number;
  failedLogins: number;
  externalIPs: number;
  highRiskNodes: number;
  anomalyEdges: number;
}

export interface TabConfig {
  id: string;
  label: string;
  icon: any;
  badge?: number;
}

export interface UserMenuPosition {
  top: number;
  right: number;
}

export interface ParsedData {
  events: AuthEvent[];
  metadata: {
    eventCount: number;
    timeRange?: string;
    [key: string]: any;
  };
  context?: AnalyticsContext;
}

export interface UploadProgress {
  stage: 'uploading' | 'processing' | 'analyzing' | 'complete';
  progress: number;
  message: string;
}

export type AlertSortBy = 'severity' | 'time' | 'confidence';
export type AlertFilter = 'all' | 'critical' | 'high' | 'medium';

export interface ADTrapperState {
  // UI State
  activeTab: string;
  showAuthModal: boolean;
  authMode: 'signin' | 'signup';
  darkMode: boolean;
  showUserMenu: boolean;
  dropdownPosition: UserMenuPosition;
  staticMode: boolean;

  // Data State
  data: GraphData;
  filteredData: GraphData;
  alerts: Alert[];
  anomalies: Anomaly[];
  selectedNode: GraphNode | null;
  selectedAnomaly: Anomaly | null;
  searchTerm: string;
  filters: FilterState;

  // Upload State
  uploadProgress: number;
  isAnalyzing: boolean;
  userSessions: any[];
  currentSession: any | null;

  // Sort/Filter State
  alertSortBy: AlertSortBy;
  alertFilter: AlertFilter;

  // Connection State
  supabaseConnected: boolean;
}
