'use client'

import React, { useState } from 'react';
import {
  AlertTriangle, Shield, Bell, Activity, Brain, Target, MapPin, Clock,
  Sparkles, Eye, Info, Lock, Unlock, User, Monitor, Globe, TrendingUp, X,
  ChevronDown, ChevronRight, Zap
} from 'lucide-react';

interface Anomaly {
  id: string;
  ruleId: string;
  ruleName: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  category: 'authentication' | 'network' | 'behavior' | 'privilege' | 'temporal' | 'informational' | 'security' | 'behavioral' | 'correlation';
  confidence: number;
  evidence?: Record<string, any>;
  affectedEntities?: Array<{
    type: 'user' | 'computer' | 'ip';
    id: string;
    name: string;
  }>;
  timeWindow?: {
    start: Date;
    end: Date;
  };
  metadata?: Record<string, any>;
  timestamp: Date;
  detectedAt: Date;
  recommendations?: string[];
  context?: Record<string, any>;
}

interface AlertGroup {
  id: string;
  title: string;
  ruleName: string;
  ruleId: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  count: number;
  alerts: Anomaly[];
  avgConfidence: number;
  latestTimestamp: Date;
  isExpanded: boolean;
  isCorrelation: boolean;
  allReviewed?: boolean;
  someReviewed?: boolean;
}

interface AlertsManagementProps {
  anomalies: Anomaly[];
  supabaseConnected: boolean;
  cardClasses: string;
  onAnomalySelect?: (anomaly: Anomaly) => void;
  onGraphAlert?: (anomaly: Anomaly, relatedEvents: any[], affectedEntities: any[]) => void;
}

const AlertsManagement: React.FC<AlertsManagementProps> = ({
  anomalies,
  supabaseConnected,
  cardClasses,
  onAnomalySelect,
  onGraphAlert
}) => {
  const [alertSortBy, setAlertSortBy] = useState<'severity' | 'time' | 'confidence'>('severity');
  const [alertFilter, setAlertFilter] = useState<'all' | 'critical' | 'high' | 'medium'>('all');
  const [selectedAnomaly, setSelectedAnomaly] = useState<Anomaly | null>(null);
  const [alertGroups, setAlertGroups] = useState<AlertGroup[]>([]);
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set());
  const [reviewedAlerts, setReviewedAlerts] = useState<Set<string>>(new Set());

  // Load reviewed alerts from localStorage on mount
  React.useEffect(() => {
    const saved = localStorage.getItem('adtReviewedAlerts');
    if (saved) {
      try {
        const reviewedIds = JSON.parse(saved);
        setReviewedAlerts(new Set(reviewedIds));
      } catch (e) {
        console.error('Error loading reviewed alerts:', e);
      }
    }
  }, []);

  // Save reviewed alerts to localStorage
  const saveReviewedAlerts = (reviewed: Set<string>) => {
    localStorage.setItem('adtReviewedAlerts', JSON.stringify(Array.from(reviewed)));
  };

  // Mark alert as reviewed
  const markAlertAsReviewed = (alertId: string) => {
    const newReviewed = new Set(reviewedAlerts);
    newReviewed.add(alertId);
    setReviewedAlerts(newReviewed);
    saveReviewedAlerts(newReviewed);

    // Close modal if it's open
    if (selectedAnomaly && selectedAnomaly.id === alertId) {
      setSelectedAnomaly(null);
    }
  };

  // Mark alert group as reviewed
  const markGroupAsReviewed = (group: AlertGroup) => {
    const newReviewed = new Set(reviewedAlerts);
    group.alerts.forEach(alert => newReviewed.add(alert.id));
    setReviewedAlerts(newReviewed);
    saveReviewedAlerts(newReviewed);
  };

  // Group similar alerts together
  const groupAlerts = (alerts: Anomaly[]): AlertGroup[] => {
    const groups: { [key: string]: Anomaly[] } = {};

    alerts.forEach(alert => {
      // For correlation alerts, don't group them - show individually at top
      if (alert.category === 'correlation') {
        const correlationKey = `correlation-${alert.id}`;
        groups[correlationKey] = [alert];
        return;
      }

      // Extract pattern from title (remove specific entity names)
      const titlePattern = alert.title
        .replace(/:\s*[^:]+$/, '') // Remove everything after last colon
        .replace(/\s+\([^)]+\)$/, '') // Remove parenthetical expressions
        .trim();

      // Create group key
      const groupKey = `${alert.ruleId}-${titlePattern}-${alert.severity}`;

      if (!groups[groupKey]) {
        groups[groupKey] = [];
      }
      groups[groupKey].push(alert);
    });

    return Object.entries(groups).map(([key, groupAlerts]) => {
      const firstAlert = groupAlerts[0];
      const isCorrelation = firstAlert.category === 'correlation';

      // Check if all alerts in group are reviewed
      const allReviewed = groupAlerts.every(alert => reviewedAlerts.has(alert.id));
      const someReviewed = groupAlerts.some(alert => reviewedAlerts.has(alert.id));

      return {
        id: key,
        title: isCorrelation ? firstAlert.title : `${firstAlert.title.split(':')[0]} (${groupAlerts.length} instances)`,
        ruleName: firstAlert.ruleName,
        ruleId: firstAlert.ruleId,
        severity: firstAlert.severity,
        category: firstAlert.category,
        count: groupAlerts.length,
        alerts: groupAlerts,
        avgConfidence: groupAlerts.reduce((sum, alert) => sum + alert.confidence, 0) / groupAlerts.length,
        latestTimestamp: new Date(Math.max(...groupAlerts.map(alert => new Date(alert.detectedAt).getTime()))),
        isExpanded: expandedGroups.has(key),
        isCorrelation,
        allReviewed,
        someReviewed
      };
    });
  };

  // Update groups when anomalies or expandedGroups change
  React.useEffect(() => {
    const filtered = anomalies.filter(anomaly => {
      if (alertFilter === 'all') return true;
      if (alertFilter === 'critical') return anomaly.severity === 'critical';
      if (alertFilter === 'high') return anomaly.severity === 'critical' || anomaly.severity === 'high';
      if (alertFilter === 'medium') return ['critical', 'high', 'medium'].includes(anomaly.severity);
      return true;
    });

    const groups = groupAlerts(filtered);
    setAlertGroups(groups);
  }, [anomalies, alertFilter, expandedGroups]);

  const filteredAnomalies = anomalies.filter(anomaly => {
    if (alertFilter === 'all') return true;
    if (alertFilter === 'critical') return anomaly.severity === 'critical';
    if (alertFilter === 'high') return anomaly.severity === 'critical' || anomaly.severity === 'high';
    if (alertFilter === 'medium') return ['critical', 'high', 'medium'].includes(anomaly.severity);
    return true;
  }).sort((a, b) => {
    if (alertSortBy === 'severity') {
      const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
      return (severityOrder[b.severity as keyof typeof severityOrder] || 0) - (severityOrder[a.severity as keyof typeof severityOrder] || 0);
    } else if (alertSortBy === 'time') {
      return new Date(b.detectedAt).getTime() - new Date(a.detectedAt).getTime();
    } else if (alertSortBy === 'confidence') {
      return b.confidence - a.confidence;
    }
    return 0;
  });

  const handleAnomalyClick = (anomaly: Anomaly) => {
    setSelectedAnomaly(anomaly);
    onAnomalySelect?.(anomaly);
  };

  const toggleGroupExpansion = (groupId: string) => {
    const newExpanded = new Set(expandedGroups);
    if (newExpanded.has(groupId)) {
      newExpanded.delete(groupId);
    } else {
      newExpanded.add(groupId);
    }
    setExpandedGroups(newExpanded);
  };

  // Sort groups - put reviewed alerts at bottom
  const sortedGroups = [...alertGroups].sort((a, b) => {
    // Always put correlations at the top
    if (a.isCorrelation && !b.isCorrelation) return -1;
    if (!a.isCorrelation && b.isCorrelation) return 1;

    // Put reviewed alerts at the bottom
    if (a.allReviewed && !b.allReviewed) return 1;
    if (!a.allReviewed && b.allReviewed) return -1;

    if (alertSortBy === 'severity') {
      const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
      return (severityOrder[b.severity as keyof typeof severityOrder] || 0) - (severityOrder[a.severity as keyof typeof severityOrder] || 0);
    } else if (alertSortBy === 'time') {
      return new Date(b.latestTimestamp).getTime() - new Date(a.latestTimestamp).getTime();
    } else if (alertSortBy === 'confidence') {
      return b.avgConfidence - a.avgConfidence;
    }
    return 0;
  });

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-3xl font-bold mb-2 bg-gradient-to-r from-red-500 to-orange-600 bg-clip-text text-transparent">
              🚨 Security Alerts
            </h2>
            <p className="text-gray-500">Real-time security threats and anomalies detected by ADTrapper</p>
          </div>
          <div className="flex items-center gap-4">
                          <div className="flex items-center gap-2 px-4 py-2 bg-red-500/10 border border-red-500/20 rounded-lg">
              <div className="w-2 h-2 bg-red-500 rounded-full animate-pulse"></div>
              <span className="text-sm font-medium text-red-600">{sortedGroups.filter(g => g.severity === 'critical').length} Critical Groups</span>
            </div>
            <div className="flex items-center gap-2 px-4 py-2 bg-orange-500/10 border border-orange-500/20 rounded-lg">
              <div className="w-2 h-2 bg-orange-500 rounded-full"></div>
              <span className="text-sm font-medium text-orange-600">{sortedGroups.filter(g => g.severity === 'high').length} High Groups</span>
            </div>
            <div className="flex items-center gap-2 px-4 py-2 bg-yellow-500/10 border border-yellow-500/20 rounded-lg">
              <div className="w-2 h-2 bg-yellow-500 rounded-full"></div>
              <span className="text-sm font-medium text-yellow-600">{sortedGroups.filter(g => g.severity === 'medium').length} Medium Groups</span>
            </div>
            <div className="flex items-center gap-2 px-4 py-2 bg-green-500/10 border border-green-500/20 rounded-lg">
              <div className="w-2 h-2 bg-green-500 rounded-full"></div>
              <span className="text-sm font-medium text-green-600">{reviewedAlerts.size} Reviewed</span>
            </div>
            <div className="flex items-center gap-2 px-4 py-2 bg-purple-500/10 border border-purple-500/20 rounded-lg">
              <div className="w-2 h-2 bg-purple-500 rounded-full"></div>
              <span className="text-sm font-medium text-purple-600">{sortedGroups.filter(g => g.isCorrelation).length} Correlations</span>
            </div>
          </div>
        </div>
      </div>

      {/* Alert Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div className={`${cardClasses} p-6 rounded-xl shadow-lg border-l-4 border-red-500`}>
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 bg-red-500/10 rounded-lg flex items-center justify-center">
              <AlertTriangle className="w-6 h-6 text-red-500" />
            </div>
            <div>
              <div className="text-2xl font-bold text-red-500">{sortedGroups.length}</div>
              <div className="text-sm text-gray-500">Alert Groups</div>
            </div>
          </div>
        </div>

        <div className={`${cardClasses} p-6 rounded-xl shadow-lg border-l-4 border-orange-500`}>
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 bg-orange-500/10 rounded-lg flex items-center justify-center">
              <Shield className="w-6 h-6 text-orange-500" />
            </div>
            <div>
              <div className="text-2xl font-bold text-orange-500">{new Set(sortedGroups.flatMap(g => g.alerts.flatMap(a => Array.isArray(a.affectedEntities) ? a.affectedEntities.map((e: any) => e.id) : []))).size}</div>
              <div className="text-sm text-gray-500">Affected Assets</div>
            </div>
          </div>
        </div>

        <div className={`${cardClasses} p-6 rounded-xl shadow-lg border-l-4 border-blue-500`}>
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 bg-blue-500/10 rounded-lg flex items-center justify-center">
              <Brain className="w-6 h-6 text-blue-500" />
            </div>
            <div>
              <div className="text-2xl font-bold text-blue-500">{new Set(sortedGroups.map(g => g.ruleId)).size}</div>
              <div className="text-sm text-gray-500">Rules Triggered</div>
            </div>
          </div>
        </div>

        <div className={`${cardClasses} p-6 rounded-xl shadow-lg border-l-4 border-green-500`}>
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 bg-green-500/10 rounded-lg flex items-center justify-center">
              <TrendingUp className="w-6 h-6 text-green-500" />
            </div>
            <div>
              <div className="text-2xl font-bold text-green-500">{Math.round(sortedGroups.reduce((sum, g) => sum + g.avgConfidence, 0) / sortedGroups.length) || 0}%</div>
              <div className="text-sm text-gray-500">Avg Confidence</div>
            </div>
          </div>
        </div>
      </div>

      {/* Detailed Alerts List */}
      <div className={`${cardClasses} rounded-xl shadow-lg flex-1 flex flex-col h-full`}>
        <div className="p-6 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center justify-between">
            <h3 className="text-xl font-semibold">Security Alerts</h3>
            <div className="flex items-center gap-4">
              {/* Sort Filter */}
              <div className="flex items-center gap-2">
                <label className="text-sm text-gray-500">Sort by:</label>
                <select
                  className="text-sm bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded px-2 py-1"
                  value={alertSortBy}
                  onChange={(e) => setAlertSortBy(e.target.value as 'severity' | 'time' | 'confidence')}
                >
                  <option value="severity">Severity</option>
                  <option value="time">Time</option>
                  <option value="confidence">Confidence</option>
                </select>
              </div>

              {/* Severity Filter */}
              <div className="flex items-center gap-2">
                <label className="text-sm text-gray-500">Filter:</label>
                <select
                  className="text-sm bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded px-2 py-1"
                  value={alertFilter}
                  onChange={(e) => setAlertFilter(e.target.value as 'all' | 'critical' | 'high' | 'medium')}
                >
                  <option value="all">All Alerts</option>
                  <option value="critical">Critical Only</option>
                  <option value="high">High & Critical</option>
                  <option value="medium">Medium & Above</option>
                </select>
              </div>

              <div className="flex items-center gap-2">
                <span className="text-sm text-gray-500">Showing {Math.min(sortedGroups.length, 100)} of {sortedGroups.length} alert groups</span>
                <div className={`flex items-center gap-1 text-sm ${supabaseConnected ? 'text-green-600' : 'text-red-600'}`}>
                  <div className={`w-2 h-2 rounded-full ${supabaseConnected ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`}></div>
                  {supabaseConnected ? 'Connected' : 'Offline Mode'}
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto" style={{ maxHeight: 'calc(100vh - 400px)' }}>
          {sortedGroups.length === 0 ? (
            <div className="text-center py-12 text-gray-500">
              <Shield className="w-16 h-16 mx-auto mb-4 opacity-50" />
              <h4 className="text-lg font-medium mb-2">No Active Alerts</h4>
              <p>Your environment is secure! No anomalies detected.</p>
              <p className="text-sm mt-2">Upload security logs to start monitoring</p>
            </div>
          ) : (
            <div className="divide-y divide-gray-200 dark:divide-gray-700">
              {sortedGroups.map((group) => (
                <div key={group.id} className={`p-6 hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-all ${
                  group.isCorrelation ? 'bg-gradient-to-r from-purple-50 to-pink-50 dark:from-purple-900/20 dark:to-pink-900/20 border-l-4 border-purple-500' :
                  group.allReviewed ? 'bg-gray-50 dark:bg-gray-800/30 opacity-60' : ''
                }`}>
                  <div className="flex items-start gap-4">
                    {/* Severity Indicator */}
                    <div className={`relative w-12 h-12 rounded-lg flex items-center justify-center ${
                      group.severity === 'critical' ? 'bg-red-500/20 text-red-600' :
                      group.severity === 'high' ? 'bg-orange-500/20 text-orange-600' :
                      group.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-600' :
                      'bg-blue-500/20 text-blue-600'
                    } ${group.allReviewed ? 'opacity-50' : ''}`}>
                      {group.isCorrelation ? <Zap className="w-6 h-6" /> :
                       group.severity === 'critical' ? <AlertTriangle className="w-6 h-6" /> :
                       group.severity === 'high' ? <Shield className="w-6 h-6" /> :
                       group.severity === 'medium' ? <Eye className="w-6 h-6" /> :
                       <Info className="w-6 h-6" />}
                      {group.allReviewed && (
                        <div className="absolute -top-1 -right-1 w-4 h-4 bg-green-500 rounded-full flex items-center justify-center">
                          <span className="text-white text-xs">✓</span>
                        </div>
                      )}
                    </div>

                    {/* Group Content */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-3 mb-2">
                        {group.isCorrelation && (
                          <span className="px-3 py-1 text-xs font-bold rounded-full uppercase tracking-wide bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-300">
                            🔗 CORRELATION
                          </span>
                        )}
                        <span className={`px-3 py-1 text-xs font-bold rounded-full uppercase tracking-wide ${
                          group.severity === 'critical' ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300' :
                          group.severity === 'high' ? 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300' :
                          group.severity === 'medium' ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300' :
                          'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300'
                        } ${group.allReviewed ? 'opacity-60' : ''}`}>
                          {group.severity}
                        </span>
                        {group.allReviewed && (
                          <span className="px-2 py-1 text-xs font-medium rounded-full bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300">
                            ✓ REVIEWED
                          </span>
                        )}
                        <span className="text-sm text-gray-500 bg-gray-100 dark:bg-gray-700 px-2 py-1 rounded">
                          {group.ruleName}
                        </span>
                        <span className="text-xs text-gray-500">
                          {group.latestTimestamp.toLocaleString()}
                        </span>
                        {!group.isCorrelation && group.count > 1 && (
                          <span className="text-xs bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300 px-2 py-1 rounded-full font-medium">
                            {group.count} alerts
                          </span>
                        )}
                      </div>

                      <div className="flex items-center justify-between">
                        <h4 className="text-lg font-semibold mb-2 text-gray-900 dark:text-gray-100">
                          {group.title}
                        </h4>
                        {!group.isCorrelation && group.count > 1 && (
                          <button
                            onClick={() => toggleGroupExpansion(group.id)}
                            className="flex items-center gap-2 text-sm text-blue-600 hover:text-blue-800 font-medium"
                          >
                            {group.isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                            {group.isExpanded ? 'Collapse' : 'Expand'}
                          </button>
                        )}
                        {!group.allReviewed && (
                          <button
                            onClick={() => markGroupAsReviewed(group)}
                            className="flex items-center gap-2 text-sm text-green-600 hover:text-green-800 font-medium"
                          >
                            ✓ Mark as Reviewed
                          </button>
                        )}
                      </div>

                      <p className="text-gray-600 dark:text-gray-400 mb-3 leading-relaxed">
                        {group.isCorrelation
                          ? group.alerts[0].description
                          : `${group.count} similar ${group.severity} severity alerts detected. Latest: ${group.alerts[0].description}`
                        }
                      </p>

                      {/* Show individual alerts when expanded */}
                      {group.isExpanded && !group.isCorrelation && (
                        <div className="mt-4 space-y-3 border-t border-gray-200 dark:border-gray-700 pt-4">
                          {group.alerts.map((alert, idx) => (
                            <div key={idx} className="bg-gray-50 dark:bg-gray-800 rounded-lg p-3">
                              <div className="flex items-center justify-between mb-2">
                                <span className="text-sm font-medium text-gray-900 dark:text-gray-100">
                                  {alert.title}
                                </span>
                                <span className="text-xs text-gray-500">
                                  {new Date(alert.detectedAt).toLocaleString()}
                                </span>
                              </div>
                              <p className="text-sm text-gray-600 dark:text-gray-400">
                                {alert.description}
                              </p>
                              <div className="flex items-center gap-2 mt-2">
                                <button
                                  onClick={() => handleAnomalyClick(alert)}
                                  className="text-xs text-blue-600 hover:text-blue-800 font-medium"
                                >
                                  View Details →
                                </button>
                                {!reviewedAlerts.has(alert.id) && (
                                  <button
                                    onClick={() => markAlertAsReviewed(alert.id)}
                                    className="text-xs text-green-600 hover:text-green-800 font-medium"
                                  >
                                    ✓ Mark Reviewed
                                  </button>
                                )}
                                {reviewedAlerts.has(alert.id) && (
                                  <span className="text-xs text-green-600 font-medium">
                                    ✓ Reviewed
                                  </span>
                                )}
                              </div>
                            </div>
                          ))}
                        </div>
                      )}

                      {/* Affected Entities - show unique entities from all alerts in group */}
                      {group.alerts.some(alert => Array.isArray(alert.affectedEntities) && alert.affectedEntities.length > 0) && (
                        <div className="mb-3">
                          <div className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                            Affected Assets:
                          </div>
                          <div className="flex flex-wrap gap-2">
                            {Array.from(new Set(
                              group.alerts
                                .flatMap(alert => alert.affectedEntities || [])
                                .map(entity => `${entity.type}-${entity.name}`)
                            ))
                            .slice(0, 8)
                            .map((entityKey) => {
                              const [type, name] = entityKey.split('-', 2);
                              return (
                                <span key={entityKey} className={`text-xs px-3 py-1 rounded-full font-medium ${
                                  type === 'user' ? 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300' :
                                  type === 'computer' ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400' :
                                  type === 'ip' ? 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400' :
                                  'bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-300'
                                }`}>
                                  {type === 'user' ? '👤' : type === 'computer' ? '💻' : type === 'ip' ? '🌐' : '📄'} {name}
                                </span>
                              );
                            })}
                          </div>
                        </div>
                      )}

                      {/* Recommendations - show from first alert or combined */}
                      {group.alerts.some(alert => Array.isArray(alert.recommendations) && alert.recommendations.length > 0) && (
                        <div className="mb-3">
                          <div className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">🛡️ Recommended Actions:</div>
                          <ul className="text-sm text-gray-600 dark:text-gray-400 space-y-1">
                            {group.alerts[0].recommendations?.slice(0, 3).map((rec: any, idx: number) => (
                              <li key={idx} className="flex items-start gap-2">
                                <span className="text-blue-500 mt-1">•</span>
                                <span>{rec}</span>
                              </li>
                            ))}
                            {(group.alerts[0].recommendations?.length || 0) > 3 && (
                              <li className="text-gray-500 text-xs">+{(group.alerts[0].recommendations?.length || 0) - 3} more recommendations</li>
                            )}
                          </ul>
                        </div>
                      )}
                    </div>

                    {/* Right Side Stats */}
                    <div className="text-right space-y-2">
                      <div className={`text-sm font-bold ${
                        group.avgConfidence >= 80 ? 'text-green-600' :
                        group.avgConfidence >= 60 ? 'text-yellow-600' :
                        'text-red-600'
                      }`}>
                        {Math.round(group.avgConfidence)}% Confidence
                      </div>
                      <div className="text-xs text-gray-500">
                        ID: {group.id.split('-')[0]}
                      </div>
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => handleAnomalyClick(group.alerts[0])}
                          className={`text-xs font-medium group-hover:underline ${
                            group.allReviewed ? 'text-gray-500' : 'text-blue-600 hover:text-blue-800'
                          }`}
                        >
                          View Details →
                        </button>
                        {onGraphAlert && (
                          <button
                            onClick={() => {
                              const relatedEvents = group.alerts[0].evidence?.events || [];
                              const affectedEntities = group.alerts[0].affectedEntities || [];
                              onGraphAlert(group.alerts[0], relatedEvents, affectedEntities);
                            }}
                            className={`text-xs font-medium group-hover:underline ${
                              group.allReviewed ? 'text-gray-500' : 'text-green-600 hover:text-green-800'
                            }`}
                            title="Graph this alert"
                          >
                            📊
                          </button>
                        )}
                        {group.allReviewed && (
                          <span className="text-xs text-green-600 font-medium">
                            ✓ All Reviewed
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Anomaly Details Modal */}
      {selectedAnomaly && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-2xl max-w-4xl w-full max-h-[90vh] flex flex-col">
            {/* Modal Header - Fixed */}
            <div className="p-6 border-b border-gray-200 dark:border-gray-700 flex-shrink-0">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <div className={`w-12 h-12 rounded-lg flex items-center justify-center ${
                    selectedAnomaly.severity === 'critical' ? 'bg-red-500/20 text-red-600' :
                    selectedAnomaly.severity === 'high' ? 'bg-orange-500/20 text-orange-600' :
                    selectedAnomaly.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-600' :
                    'bg-blue-500/20 text-blue-600'
                  }`}>
                    {selectedAnomaly.category === 'authentication' ? <Target size={24} /> :
                     selectedAnomaly.category === 'behavior' ? <MapPin size={24} /> :
                     selectedAnomaly.category === 'privilege' ? <Shield size={24} /> :
                     selectedAnomaly.category === 'temporal' ? <Clock size={24} /> :
                     <Sparkles size={24} />}
                  </div>
                  <div>
                    <h2 className="text-xl font-bold text-gray-900 dark:text-gray-100">{selectedAnomaly.title}</h2>
                    <div className="flex items-center gap-2 mt-1">
                      <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                        selectedAnomaly.severity === 'critical' ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400' :
                        selectedAnomaly.severity === 'high' ? 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400' :
                        selectedAnomaly.severity === 'medium' ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400' :
                        'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400'
                      }`}>
                        {selectedAnomaly.severity.toUpperCase()}
                      </span>
                      <span className="text-sm text-gray-500">{selectedAnomaly.ruleName}</span>
                      <span className="text-sm text-gray-400">•</span>
                      <span className="text-sm text-gray-500">{selectedAnomaly.confidence}% confidence</span>
                    </div>
                  </div>
                </div>
                <button
                  onClick={() => setSelectedAnomaly(null)}
                  className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                >
                  <X size={24} />
                </button>
              </div>
            </div>

            {/* Modal Content - Scrollable */}
            <div className="flex-1 overflow-y-auto p-6">
              <div className="space-y-6">
                {/* Description */}
                <div>
                  <h3 className="text-sm font-medium text-gray-500 uppercase tracking-wide mb-2">Description</h3>
                  <p className="text-gray-700 dark:text-gray-300 leading-relaxed">{selectedAnomaly.description}</p>
                </div>

                {/* Timeline */}
                <div>
                  <h3 className="text-sm font-medium text-gray-500 uppercase tracking-wide mb-2">Timeline</h3>
                  <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
                    <div className="grid md:grid-cols-2 gap-4">
                      <div>
                        <span className="text-sm text-gray-500">Detected At</span>
                        <p className="font-medium">{new Date(selectedAnomaly.detectedAt).toLocaleString()}</p>
                      </div>
                      <div>
                        <span className="text-sm text-gray-500">Event Time</span>
                        <p className="font-medium">{new Date(selectedAnomaly.timestamp).toLocaleString()}</p>
                      </div>
                      {selectedAnomaly.timeWindow && (
                        <>
                          <div>
                            <span className="text-sm text-gray-500">Window Start</span>
                            <p className="font-medium">{new Date(selectedAnomaly.timeWindow.start).toLocaleString()}</p>
                          </div>
                          <div>
                            <span className="text-sm text-gray-500">Window End</span>
                            <p className="font-medium">{new Date(selectedAnomaly.timeWindow.end).toLocaleString()}</p>
                          </div>
                        </>
                      )}
                    </div>
                  </div>
                </div>

                {/* Evidence */}
                {selectedAnomaly.evidence && Object.keys(selectedAnomaly.evidence).length > 0 && (
                  <div>
                    <h3 className="text-sm font-medium text-gray-500 uppercase tracking-wide mb-2">Evidence</h3>
                    <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
                      <div className="space-y-3">
                        {Object.entries(selectedAnomaly.evidence).map(([key, value]) => (
                          <div key={key} className="flex justify-between items-start">
                            <span className="text-sm text-gray-500 capitalize">{key.replace(/([A-Z])/g, ' $1').trim()}:</span>
                            <span className="text-sm font-medium text-gray-900 dark:text-gray-100 text-right max-w-xs">
                              {typeof value === 'object' ? JSON.stringify(value, null, 1) : String(value)}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                )}

                {/* Affected Entities */}
                {selectedAnomaly.affectedEntities && selectedAnomaly.affectedEntities.length > 0 && (
                  <div>
                    <h3 className="text-sm font-medium text-gray-500 uppercase tracking-wide mb-2">Affected Entities</h3>
                    <div className="flex flex-wrap gap-2">
                      {selectedAnomaly.affectedEntities.map((entity: any, index: number) => (
                        <div key={index} className={`px-3 py-1 rounded-full text-sm ${
                          entity.type === 'user' ? 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400' :
                          entity.type === 'computer' ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400' :
                          'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400'
                        }`}>
                          {entity.type === 'user' ? <User size={14} className="inline mr-1" /> :
                           entity.type === 'computer' ? <Monitor size={14} className="inline mr-1" /> :
                           <Globe size={14} className="inline mr-1" />}
                          {entity.name}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Service Account Information */}
                {selectedAnomaly.evidence && Object.entries(selectedAnomaly.evidence).some(([key, value]) =>
                  key.toLowerCase().includes('serviceaccount') ||
                  key.toLowerCase().includes('service_account') ||
                  (typeof value === 'string' && value.toLowerCase().includes('service'))
                ) && (
                  <div>
                    <h3 className="text-sm font-medium text-gray-500 uppercase tracking-wide mb-2">Service Account Information</h3>
                    <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
                      <div className="grid md:grid-cols-2 gap-4">
                        {Object.entries(selectedAnomaly.evidence)
                          .filter(([key, value]) => {
                            // Show service account related fields
                            const serviceFields = ['serviceAccountType', 'serviceAccountIndicators', 'isServiceAccount', 'accountAgeDays']
                            return serviceFields.some(field => key.toLowerCase().includes(field.toLowerCase()))
                          })
                          .map(([key, value]) => {
                            let displayKey = key.replace(/([A-Z])/g, ' $1').trim()
                            let displayValue = value

                            // Special formatting for service account type
                            if (key.toLowerCase().includes('serviceaccounttype')) {
                              displayKey = 'Service Account Type'
                              const typeMap: Record<string, string> = {
                                'application_service': 'Application Service',
                                'managed_service': 'Managed Service',
                                'group_managed': 'Group Managed',
                                'computer_account': 'Computer Account',
                                'regular_user': 'Regular User (Potential Issue)'
                              }
                              displayValue = typeMap[value as string] || value
                            }

                            // Special formatting for indicators
                            if (key.toLowerCase().includes('indicators') && Array.isArray(value)) {
                              displayKey = 'Detection Indicators'
                              displayValue = value.join(', ')
                            }

                            return (
                              <div key={key}>
                                <span className="text-sm text-gray-500 capitalize">{displayKey}</span>
                                <p className="font-medium text-gray-900 dark:text-gray-100">
                                  {displayValue}
                                </p>
                              </div>
                            )
                          })
                        }
                        {/* Show warning for regular user service accounts */}
                        {selectedAnomaly.evidence.serviceAccountType === 'regular_user' && (
                          <div className="col-span-2 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-700 rounded-lg p-3">
                            <div className="flex items-center">
                              <span className="text-yellow-600 dark:text-yellow-400">⚠️</span>
                              <span className="ml-2 text-sm text-yellow-800 dark:text-yellow-200 font-medium">
                                Security Risk: Regular user account used as service account
                              </span>
                            </div>
                            <p className="text-sm text-yellow-700 dark:text-yellow-300 mt-1">
                              Consider converting to a proper managed service account for better security.
                            </p>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                )}

                {/* GeoIP Information */}
                {selectedAnomaly.evidence && (
                  <div>
                    <h3 className="text-sm font-medium text-gray-500 uppercase tracking-wide mb-2">Geographic Information</h3>
                    <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
                      <div className="grid md:grid-cols-2 gap-4">
                        {Object.entries(selectedAnomaly.evidence)
                          .filter(([key, value]) => {
                            // Show GeoIP-related fields
                            const geoFields = ['country', 'city', 'region', 'isp', 'isTor', 'isVpn', 'isMalicious', 'riskScore']
                            return geoFields.some(field => key.toLowerCase().includes(field.toLowerCase()))
                          })
                          .map(([key, value]) => {
                            let displayKey = key.replace(/([A-Z])/g, ' $1').trim()
                            let displayValue = value

                            // Special formatting for boolean values
                            if (typeof value === 'boolean') {
                              if (key.toLowerCase().includes('tor')) {
                                displayKey = 'TOR Exit Node'
                                displayValue = value ? '🚨 Yes' : '✅ No'
                              } else if (key.toLowerCase().includes('vpn')) {
                                displayKey = 'VPN Connection'
                                displayValue = value ? '🔒 Yes' : '✅ No'
                              } else if (key.toLowerCase().includes('malicious')) {
                                displayKey = 'Malicious IP'
                                displayValue = value ? '🚨 Yes' : '✅ No'
                              } else {
                                displayValue = value ? 'Yes' : 'No'
                              }
                            }

                            // Special formatting for risk score
                            if (key.toLowerCase().includes('riskscore') && typeof value === 'number') {
                              displayKey = 'Risk Score'
                              const riskLevel = value >= 70 ? 'High' : value >= 40 ? 'Medium' : 'Low'
                              const riskColor = value >= 70 ? 'text-red-600' : value >= 40 ? 'text-yellow-600' : 'text-green-600'
                              displayValue = (
                                <span className={`${riskColor} font-semibold`}>
                                  {value}/100 ({riskLevel})
                                </span>
                              )
                            }

                            return (
                              <div key={key}>
                                <span className="text-sm text-gray-500 capitalize">{displayKey}</span>
                                <p className="font-medium text-gray-900 dark:text-gray-100">
                                  {typeof displayValue === 'object' ? displayValue : String(displayValue)}
                                </p>
                              </div>
                            )
                          })
                        }
                        {/* Show message if no GeoIP data */}
                        {Object.entries(selectedAnomaly.evidence)
                          .filter(([key, value]) => {
                            const geoFields = ['country', 'city', 'region', 'isp', 'isTor', 'isVpn', 'isMalicious', 'riskScore']
                            return geoFields.some(field => key.toLowerCase().includes(field.toLowerCase()))
                          })
                          .length === 0 && (
                          <div className="col-span-2">
                            <span className="text-sm text-gray-500">No geographic information available</span>
                            <p className="font-medium text-gray-900 dark:text-gray-100">
                              Local or private IP address
                            </p>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                )}

                {/* Recommendations */}
                {selectedAnomaly.recommendations && selectedAnomaly.recommendations.length > 0 && (
                  <div>
                    <h3 className="text-sm font-medium text-gray-500 uppercase tracking-wide mb-2">Recommendations</h3>
                    <div className="space-y-2">
                      {selectedAnomaly.recommendations.map((rec: string, index: number) => (
                        <div key={index} className="flex items-start gap-3 p-3 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
                          <AlertTriangle size={16} className="text-blue-500 mt-0.5 flex-shrink-0" />
                          <span className="text-sm text-gray-700 dark:text-gray-300">{rec}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Metadata */}
                {selectedAnomaly.metadata && Object.keys(selectedAnomaly.metadata).length > 0 && (
                  <div>
                    <h3 className="text-sm font-medium text-gray-500 uppercase tracking-wide mb-2">Additional Information</h3>
                    <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
                      <div className="grid md:grid-cols-2 gap-4">
                        {Object.entries(selectedAnomaly.metadata)
                          .filter(([key, value]) => value !== null && value !== undefined && value !== '')
                          .map(([key, value]) => {
                            // Special handling for different metadata types
                            let displayValue = value
                            let displayKey = key.replace(/([A-Z])/g, ' $1').trim()

                            // Handle time span formatting
                            if (key === 'timeSpanFormatted' && value) {
                              displayKey = 'Time Span'
                              displayValue = value
                            } else if (key === 'timeSpan' && typeof value === 'number') {
                              // Skip raw timeSpan if we have formatted version
                              if (selectedAnomaly.metadata?.timeSpanFormatted) return null
                              displayKey = 'Time Span'
                              displayValue = `${Math.round(value / 1000 / 60)} minutes`
                            } else if (key === 'alertCount') {
                              displayKey = 'Alert Count'
                              displayValue = value
                            } else if (key === 'uniqueRules') {
                              displayKey = 'Unique Rules'
                              displayValue = value
                            } else if (key === 'correlatedAlerts' && Array.isArray(value)) {
                              displayKey = 'Correlated Alerts'
                              displayValue = `${value.length} alerts`
                            } else if (typeof value === 'boolean') {
                              displayValue = value ? 'Yes' : 'No'
                            } else if (typeof value === 'number') {
                              displayValue = value.toLocaleString()
                            } else {
                              displayValue = String(value)
                            }

                            return (
                              <div key={key}>
                                <span className="text-sm text-gray-500 capitalize">{displayKey}</span>
                                <p className="font-medium text-gray-900 dark:text-gray-100">
                                  {displayValue}
                                </p>
                              </div>
                            )
                          })
                          .filter(Boolean) // Remove null entries
                        }
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Modal Footer - Fixed */}
            <div className="p-6 border-t border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700 flex-shrink-0">
              <div className="flex justify-between items-center">
                <div>
                  {onGraphAlert && (
                    <button
                      onClick={() => {
                        if (selectedAnomaly) {
                          // Extract related events and affected entities from evidence/context
                          const relatedEvents = selectedAnomaly.evidence?.events || [];
                          const affectedEntities = selectedAnomaly.affectedEntities || [];
                          onGraphAlert(selectedAnomaly, relatedEvents, affectedEntities);
                        }
                      }}
                      className="flex items-center gap-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors"
                    >
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                      </svg>
                      Graph Alert
                    </button>
                  )}
                </div>
                <div className="flex gap-3">
                  <button
                    onClick={() => setSelectedAnomaly(null)}
                    className="px-4 py-2 text-gray-600 dark:text-gray-300 hover:text-gray-800 dark:hover:text-gray-100 transition-colors"
                  >
                    Close
                  </button>
                  <button
                    onClick={() => {
                      if (selectedAnomaly) {
                        markAlertAsReviewed(selectedAnomaly.id);
                      }
                    }}
                    className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
                  >
                    Mark as Reviewed
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AlertsManagement;
