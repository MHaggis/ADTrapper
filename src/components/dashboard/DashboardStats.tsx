'use client'

import React from 'react';
import { TrendingUp, AlertTriangle, Activity, Brain, Target, Shield, Bell } from 'lucide-react';

interface Anomaly {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  ruleName: string;
  confidence: number;
  detectedAt: Date;
  affectedEntities?: Array<{
    type: 'user' | 'computer' | 'ip';
    id: string;
    name: string;
  }>;
}

interface Data {
  nodes: any[];
  edges: any[];
  metadata: any;
  rawLogs?: any[];
}

interface DashboardStatsProps {
  data: Data;
  anomalies: Anomaly[];
  cardClasses: string;
  onViewAlerts: () => void;
}

const DashboardStats: React.FC<DashboardStatsProps> = ({
  data,
  anomalies,
  cardClasses,
  onViewAlerts
}) => {
  return (
    <div className="space-y-6">
      {/* Enhanced Stats Cards */}
      <div className="grid md:grid-cols-4 gap-6">
        <div className={`${cardClasses} p-6 rounded-xl shadow-lg border-l-4 border-green-500`}>
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 bg-green-500/10 rounded-lg flex items-center justify-center">
              <TrendingUp className="w-6 h-6 text-green-500" />
            </div>
            <div>
              <h3 className="font-semibold text-gray-700 dark:text-gray-300">Security Score</h3>
              <p className="text-3xl font-bold text-green-500">
                {Math.max(10, 100 - Math.round(anomalies.filter(a => a.severity === 'critical' || a.severity === 'high').length / Math.max(1, data?.nodes?.length || 0) * 100))}%
              </p>
              <p className="text-xs text-gray-500 mt-1">Based on {anomalies.length} alerts</p>
            </div>
          </div>
        </div>

        <div className={`${cardClasses} p-6 rounded-xl shadow-lg border-l-4 border-red-500`}>
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 bg-red-500/10 rounded-lg flex items-center justify-center">
              <AlertTriangle className="w-6 h-6 text-red-500" />
            </div>
            <div>
              <h3 className="font-semibold text-gray-700 dark:text-gray-300">Active Threats</h3>
              <p className="text-3xl font-bold text-red-500">{anomalies.length}</p>
              <p className="text-xs text-gray-500 mt-1">{anomalies.filter(a => a.severity === 'critical').length} critical</p>
            </div>
          </div>
        </div>

        <div className={`${cardClasses} p-6 rounded-xl shadow-lg border-l-4 border-blue-500`}>
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 bg-blue-500/10 rounded-lg flex items-center justify-center">
              <Activity className="w-6 h-6 text-blue-500" />
            </div>
            <div>
              <h3 className="font-semibold text-gray-700 dark:text-gray-300">Events Analyzed</h3>
              <p className="text-3xl font-bold text-blue-500">{data.rawLogs?.length || 0}</p>
              <p className="text-xs text-gray-500 mt-1">{data.nodes?.length || 0} unique entities</p>
            </div>
          </div>
        </div>

        <div className={`${cardClasses} p-6 rounded-xl shadow-lg border-l-4 border-purple-500`}>
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 bg-purple-500/10 rounded-lg flex items-center justify-center">
              <Brain className="w-6 h-6 text-purple-500" />
            </div>
            <div>
              <h3 className="font-semibold text-gray-700 dark:text-gray-300">Detection Rate</h3>
              <p className="text-3xl font-bold text-purple-500">{data.rawLogs && data.rawLogs.length > 0 ? Math.round(anomalies.length / data.rawLogs.length * 100) : 0}%</p>
              <p className="text-xs text-gray-500 mt-1">Rules active</p>
            </div>
          </div>
        </div>
      </div>

      {/* Risk Distribution Chart */}
      <div className="grid md:grid-cols-2 gap-6">
        <div className={`${cardClasses} p-6 rounded-xl shadow-lg`}>
          <h3 className="font-semibold text-lg mb-4 flex items-center gap-2">
            <Target className="w-5 h-5" />
            Threat Severity Distribution
          </h3>
          <div className="space-y-4">
            {[
              { level: 'Critical', count: anomalies.filter(a => a.severity === 'critical').length, color: 'red', bgColor: 'bg-red-500' },
              { level: 'High', count: anomalies.filter(a => a.severity === 'high').length, color: 'orange', bgColor: 'bg-orange-500' },
              { level: 'Medium', count: anomalies.filter(a => a.severity === 'medium').length, color: 'yellow', bgColor: 'bg-yellow-500' },
              { level: 'Low/Info', count: anomalies.filter(a => a.severity === 'low' || a.severity === 'info').length, color: 'blue', bgColor: 'bg-blue-500' }
            ].map(item => (
              <div key={item.level} className="flex items-center gap-3">
                <div className="w-16 text-sm font-medium text-gray-700 dark:text-gray-300">{item.level}</div>
                <div className="flex-1 bg-gray-200 dark:bg-gray-700 rounded-full h-3">
                  <div
                    className={`${item.bgColor} h-3 rounded-full transition-all duration-300`}
                    style={{ width: `${anomalies.length > 0 ? (item.count / anomalies.length) * 100 : 0}%` }}
                  ></div>
                </div>
                <div className="w-12 text-sm font-bold text-gray-700 dark:text-gray-300">{item.count}</div>
              </div>
            ))}
          </div>
        </div>

        <div className={`${cardClasses} p-6 rounded-xl shadow-lg`}>
          <h3 className="font-semibold text-lg mb-4 flex items-center gap-2">
            <Shield className="w-5 h-5" />
            Top Affected Assets
          </h3>
          <div className="space-y-3">
            {(() => {
              const affectedCount = new Map<string, number>();
              anomalies.forEach(anomaly => {
                if (Array.isArray(anomaly.affectedEntities)) {
                  anomaly.affectedEntities.forEach((entity: any) => {
                    affectedCount.set(entity.name, (affectedCount.get(entity.name) || 0) + 1);
                  });
                }
              });
              return Array.from(affectedCount.entries())
                .sort((a, b) => b[1] - a[1])
                .slice(0, 6);
            })().map(([entityName, count], index) => (
              <div key={entityName} className="flex items-center gap-3 p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50">
                <div className={`w-8 h-8 rounded-lg flex items-center justify-center text-sm font-bold ${
                  index === 0 ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400' :
                  index === 1 ? 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400' :
                  index === 2 ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400' :
                  'bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-400'
                }`}>
                  {index + 1}
                </div>
                <div className="flex-1">
                  <div className="font-medium text-gray-900 dark:text-gray-100">{entityName}</div>
                  <div className="text-sm text-gray-500">{count} alerts</div>
                </div>
                <div className={`px-2 py-1 rounded text-xs font-medium ${
                  count >= 5 ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400' :
                  count >= 3 ? 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400' :
                  'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400'
                }`}>
                  {count >= 5 ? 'HIGH RISK' : count >= 3 ? 'MEDIUM RISK' : 'LOW RISK'}
                </div>
              </div>
            ))}
            {anomalies.length === 0 && (
              <div className="text-center py-8 text-gray-500">
                <Shield className="w-12 h-12 mx-auto mb-3 opacity-50" />
                <p>No data to display</p>
                <p className="text-sm">Upload security logs to see insights</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Recent Critical Alerts */}
      <div className={`${cardClasses} p-6 rounded-xl shadow-lg`}>
        <div className="flex items-center justify-between mb-4">
          <h3 className="font-semibold text-lg flex items-center gap-2">
            <Bell className="w-5 h-5" />
            Recent Critical Activity
          </h3>
          <button
            onClick={onViewAlerts}
            className="text-sm text-blue-600 hover:text-blue-800 font-medium"
          >
            View All Alerts →
          </button>
        </div>
        <div className="space-y-3">
          {anomalies.filter(a => a.severity === 'critical' || a.severity === 'high').slice(0, 5).map((anomaly, index) => (
            <div key={`${anomaly.id}-${index}`} className="flex items-center gap-3 p-4 rounded-lg bg-gradient-to-r from-red-50 to-orange-50 dark:from-red-900/20 dark:to-orange-900/20 border border-red-200 dark:border-red-800">
              <div className={`w-3 h-3 rounded-full ${
                anomaly.severity === 'critical' ? 'bg-red-500 animate-pulse' : 'bg-orange-500'
              }`}></div>
              <div className="flex-1">
                <p className="font-medium text-gray-900 dark:text-gray-100">{anomaly.title}</p>
                <p className="text-sm text-gray-600 dark:text-gray-400">{anomaly.description}</p>
                <div className="flex items-center gap-2 mt-1">
                  <span className={`text-xs px-2 py-1 rounded font-medium ${
                    anomaly.severity === 'critical' ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400' :
                    'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400'
                  }`}>
                    {anomaly.severity.toUpperCase()}
                  </span>
                  <span className="text-xs text-gray-500">{anomaly.ruleName}</span>
                </div>
              </div>
              <div className="text-right">
                <div className="text-sm font-medium text-gray-700 dark:text-gray-300">{Math.round(anomaly.confidence * 100)}%</div>
                <div className="text-xs text-gray-500">
                  {new Date(anomaly.detectedAt).toLocaleTimeString()}
                </div>
              </div>
            </div>
          ))}
          {anomalies.filter(a => a.severity === 'critical' || a.severity === 'high').length === 0 && (
            <div className="text-center py-8 text-gray-500">
              <Activity className="w-12 h-12 mx-auto mb-3 opacity-50" />
              <p className="font-medium">No Critical Alerts</p>
              <p className="text-sm">Your environment appears secure!</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default DashboardStats;
