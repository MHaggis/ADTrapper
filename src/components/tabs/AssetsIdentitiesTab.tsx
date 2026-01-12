import React, { useState, useMemo, useEffect } from 'react';
import {
  Search, Shield, AlertTriangle, User, Monitor, Globe, Building, Crown,
  Calendar, Clock, Mail, Phone, MapPin, Server, Database, Key, Lock,
  Users, Filter, Eye, TrendingUp, Activity, Zap, Target, Star
} from 'lucide-react';

// Import the AuthEvent type from analytics
import { AuthEvent } from '@/analytics/types';

interface AssetIdentity {
  id: string;
  type: 'user' | 'computer' | 'ip';
  name: string;
  displayName?: string;
  domain?: string;
  alertCount: number;
  lastActivity?: Date;
  riskScore: number;
  // AD attributes - optional for different asset types
  department?: string;
  title?: string;
  email?: string;
  enabled: boolean;
  privileged?: boolean; // Optional for IP assets
  isServiceAccount?: boolean;
  serviceAccountType?: string;
  groups?: string[];
  lastLogonDate?: Date;
  passwordLastSet?: Date;
  accountAgeDays?: number;
  badPasswordCount?: number;
  // Additional metadata
  location?: string;
  operatingSystem?: string;
  ipAddress?: string;
  totalEvents?: number;
}

interface AssetsIdentitiesTabProps {
  anomalies: any[];
  darkMode: boolean;
  events: AuthEvent[];
}

export const AssetsIdentitiesTab: React.FC<AssetsIdentitiesTabProps> = ({
  anomalies,
  darkMode,
  events
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState<'all' | 'user' | 'computer' | 'ip'>('all');
  const [selectedAsset, setSelectedAsset] = useState<AssetIdentity | null>(null);
  const [sortBy, setSortBy] = useState<'alerts' | 'risk' | 'activity' | 'name'>('alerts');

  // Helper function to parse AD date format
  const parseADDate = (dateString?: string): Date | undefined => {
    if (!dateString) return undefined;
    // Parse "/Date(1756522254798)/" format
    const match = dateString.match(/\/Date\((\d+)\)\//);
    if (match) {
      return new Date(parseInt(match[1]));
    }
    return new Date(dateString);
  };

  // Helper function to detect service accounts
  const isServiceAccount = (userName: string, description?: string, groups?: string[]): boolean => {
    const serviceAccountPatterns = [
      /^svc/i,
      /^service/i,
      /service$/i,
      /\$/, // Computer accounts
      /system$/i,
      /administrator$/i,
      /admin$/i
    ];

    const isServiceByName = serviceAccountPatterns.some(pattern => pattern.test(userName));
    const isServiceByDescription = description && (
      description.toLowerCase().includes('service') ||
      description.toLowerCase().includes('system') ||
      description.toLowerCase().includes('application')
    );
    const isServiceByGroups = groups?.some(group =>
      group.toLowerCase().includes('service') ||
      group.toLowerCase().includes('computer')
    );

    return isServiceByName || !!isServiceByDescription || !!isServiceByGroups;
  };

  // Helper function to determine service account type
  const getServiceAccountType = (userName: string, description?: string): string => {
    if (userName.endsWith('$')) return 'computer_account';
    if (/sql|database|db/i.test(userName) || /sql|database|db/i.test(description || '')) return 'database_service';
    if (/web|iis|apache|nginx/i.test(userName) || /web|server/i.test(description || '')) return 'web_service';
    if (/backup|archive/i.test(userName)) return 'backup_service';
    if (/monitor|monitor/i.test(userName)) return 'monitoring_service';
    return 'application_service';
  };

  // Helper function to calculate risk score
  const calculateRiskScore = (asset: any, type: 'user' | 'computer' | 'ip', events: AuthEvent[]): number => {
    let score = 0;

    if (type === 'user') {
      // User risk factors - simplified since we don't have AD info in AuthEvent
      const userEvents = events.filter(e => e.userName === asset.name);
      const failedEvents = userEvents.filter(e => e.status === 'Failed');

      // Failed authentication attempts
      score += Math.min(failedEvents.length * 2, 30);

      // High volume of events
      if (userEvents.length > 1000) score += 20;

      // Failed login ratio
      const failureRate = userEvents.length > 0 ? failedEvents.length / userEvents.length : 0;
      if (failureRate > 0.5) score += 25;
    }

    if (type === 'computer') {
      // Computer risk factors
      const computerEvents = events.filter(e => e.computerName === asset.name);
      const failedEvents = computerEvents.filter(e => e.status === 'Failed');
      score += Math.min(failedEvents.length * 1.5, 25);

      // High volume of authentication attempts
      if (computerEvents.length > 1000) score += 20;

      // Failed login ratio
      const failureRate = computerEvents.length > 0 ? failedEvents.length / computerEvents.length : 0;
      if (failureRate > 0.3) score += 15;
    }

    if (type === 'ip') {
      // IP risk factors
      const ipEvents = events.filter(e => e.sourceIp === asset.name);
      const failedEvents = ipEvents.filter(e => e.status === 'Failed');
      const successRate = ipEvents.length > 0 ? (ipEvents.length - failedEvents.length) / ipEvents.length : 1;

      if (successRate < 0.1) score += 40; // Very low success rate
      else if (successRate < 0.3) score += 25; // Low success rate

      // High volume from single IP
      if (ipEvents.length > 500) score += 20;

      // Suspicious ports
      const suspiciousPorts = ipEvents.filter(e => e.sourcePort && e.sourcePort > 1024);
      if (suspiciousPorts.length > ipEvents.length * 0.8) score += 15;
    }

    return Math.min(Math.max(score, 0), 100);
  };

  // Process events into assets and identities
  const assetsIdentities: AssetIdentity[] = useMemo(() => {
    if (events.length === 0) return [];

    const users = new Map<string, any>();
    const computers = new Map<string, any>();
    const ips = new Map<string, any>();

    // Process each event
    events.forEach(event => {
      // Ensure timestamp is a Date object
      const timestamp = event.timestamp instanceof Date ? event.timestamp : new Date(event.timestamp);

      // Process users
      if (event.userName && event.userName !== '*$' && event.userName !== 'ANONYMOUS LOGON') {
        const userKey = `${event.userName}`;
        if (!users.has(userKey)) {
          users.set(userKey, {
            name: event.userName,
            domain: event.domainName,
            events: [],
            lastActivity: timestamp
          });
        }

        const user = users.get(userKey);
        user.events.push(event);
        if (timestamp.getTime() > user.lastActivity.getTime()) {
          user.lastActivity = timestamp;
        }
      }

      // Process computers
      if (event.computerName) {
        const computerKey = event.computerName;
        if (!computers.has(computerKey)) {
          computers.set(computerKey, {
            name: event.computerName,
            domain: event.computerName.includes('.') ? event.computerName.split('.').slice(1).join('.') : undefined,
            events: [],
            lastActivity: timestamp,
            displayName: event.computerName.split('.')[0].toUpperCase()
          });
        }

        const computer = computers.get(computerKey);
        computer.events.push(event);
        if (timestamp.getTime() > computer.lastActivity.getTime()) {
          computer.lastActivity = timestamp;
        }
      }

      // Process IPs
      if (event.sourceIp && event.sourceIp !== '-') {
        const ipKey = event.sourceIp;
        if (!ips.has(ipKey)) {
          ips.set(ipKey, {
            name: ipKey,
            events: [],
            lastActivity: timestamp
          });
        }

        const ip = ips.get(ipKey);
        ip.events.push(event);
        if (timestamp.getTime() > ip.lastActivity.getTime()) {
          ip.lastActivity = timestamp;
        }
      }
    });

    // Convert to AssetIdentity format
    const assets: AssetIdentity[] = [];

    // Process users
    users.forEach((userData, key) => {
      const isSvcAccount = isServiceAccount(userData.name);
      const failedEvents = userData.events.filter((e: AuthEvent) => e.status === 'Failed');

      assets.push({
        id: `user-${key}`,
        type: 'user',
        name: userData.name,
        displayName: userData.name,
        domain: userData.domain,
        alertCount: failedEvents.length,
        lastActivity: userData.lastActivity,
        riskScore: calculateRiskScore(userData, 'user', userData.events),
        enabled: true, // Assume enabled since we don't have AD info
        privileged: false, // Assume not privileged since we don't have AD info
        isServiceAccount: isSvcAccount,
        serviceAccountType: isSvcAccount ? getServiceAccountType(userData.name) : undefined,
        badPasswordCount: failedEvents.length,
        totalEvents: userData.events.length
      });
    });

    // Process computers
    computers.forEach((computerData, key) => {
      const failedEvents = computerData.events.filter((e: AuthEvent) => e.status === 'Failed');

      assets.push({
        id: `computer-${key}`,
        type: 'computer',
        name: computerData.name,
        displayName: computerData.displayName,
        domain: computerData.domain,
        alertCount: failedEvents.length,
        lastActivity: computerData.lastActivity,
        riskScore: calculateRiskScore(computerData, 'computer', computerData.events),
        enabled: true, // Computers are always enabled
        privileged: computerData.name.toLowerCase().includes('dc') || computerData.name.toLowerCase().includes('domain'),
        totalEvents: computerData.events.length
      });
    });

    // Process IPs
    ips.forEach((ipData, key) => {
      const failedEvents = ipData.events.filter((e: AuthEvent) => e.status === 'Failed');

      assets.push({
        id: `ip-${key}`,
        type: 'ip',
        name: ipData.name,
        alertCount: failedEvents.length,
        lastActivity: ipData.lastActivity,
        riskScore: calculateRiskScore(ipData, 'ip', ipData.events),
        enabled: true, // IPs are always enabled
        privileged: false, // IPs don't have privilege levels
        totalEvents: ipData.events.length,
        location: ipData.name.startsWith('192.168.') ? 'Internal Network' :
                 ipData.name.startsWith('10.') ? 'Internal Network' :
                 ipData.name.startsWith('172.') ? 'Internal Network' : 'External Network'
      });
    });

    return assets;
  }, [events]);

  // Filter and sort assets
  const filteredAssets = useMemo(() => {
    let filtered = assetsIdentities.filter(asset => {
      const matchesSearch = searchTerm === '' ||
        asset.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        asset.displayName?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        asset.department?.toLowerCase().includes(searchTerm.toLowerCase());

      const matchesType = filterType === 'all' || asset.type === filterType;

      return matchesSearch && matchesType;
    });

    // Sort
    filtered.sort((a, b) => {
      switch (sortBy) {
        case 'alerts':
          return b.alertCount - a.alertCount;
        case 'risk':
          return b.riskScore - a.riskScore;
        case 'activity':
          return (b.lastActivity?.getTime() || 0) - (a.lastActivity?.getTime() || 0);
        case 'name':
          return a.name.localeCompare(b.name);
        default:
          return 0;
      }
    });

    return filtered;
  }, [assetsIdentities, searchTerm, filterType, sortBy]);

  const getAssetIcon = (type: string) => {
    switch (type) {
      case 'user':
        return <User className="w-6 h-6" />;
      case 'computer':
        return <Monitor className="w-6 h-6" />;
      case 'ip':
        return <Globe className="w-6 h-6" />;
      default:
        return <Server className="w-6 h-6" />;
    }
  };

  const getRiskColor = (score: number) => {
    if (score >= 80) return 'text-red-500';
    if (score >= 60) return 'text-orange-500';
    if (score >= 40) return 'text-yellow-500';
    return 'text-green-500';
  };

  const getRiskBg = (score: number) => {
    if (score >= 80) return 'bg-red-500/10 border-red-500/20';
    if (score >= 60) return 'bg-orange-500/10 border-orange-500/20';
    if (score >= 40) return 'bg-yellow-500/10 border-yellow-500/20';
    return 'bg-green-500/10 border-green-500/20';
  };

  const formatLastActivity = (date?: Date | string) => {
    if (!date) return 'Never';

    // Ensure we have a Date object
    const dateObj = date instanceof Date ? date : new Date(date);
    
    // Check if the date is valid
    if (isNaN(dateObj.getTime())) return 'Invalid Date';

    const now = new Date();
    const diffMs = now.getTime() - dateObj.getTime();
    const diffMins = Math.floor(diffMs / (1000 * 60));
    const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    return `${diffDays}d ago`;
  };

  // Show empty state if no data
  if (events.length === 0) {
    return (
      <div className="h-full flex items-center justify-center">
        <div className="text-center">
          <Users className="w-16 h-16 mx-auto mb-4 text-gray-400" />
          <h3 className="text-xl font-medium text-gray-600 dark:text-gray-400 mb-2">
            No Event Data Available
          </h3>
          <p className="text-gray-500 dark:text-gray-500">
            Upload event data to view assets and identities
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h2 className="text-4xl font-bold mb-2 bg-gradient-to-r from-blue-500 via-purple-500 to-pink-500 bg-clip-text text-transparent">
              🏢 Assets & Identities
            </h2>
            <p className="text-gray-600 dark:text-gray-400 text-lg">
              Comprehensive view of your Active Directory assets, identities, and their security posture
            </p>
          </div>

          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-blue-500/10 to-purple-500/10 border border-blue-500/20 rounded-lg">
              <Shield className="w-5 h-5 text-blue-500" />
              <span className="text-sm font-medium text-blue-600 dark:text-blue-400">
                {filteredAssets.length} Assets Monitored
              </span>
            </div>
            <div className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-red-500/10 to-orange-500/10 border border-red-500/20 rounded-lg">
              <AlertTriangle className="w-5 h-5 text-red-500" />
              <span className="text-sm font-medium text-red-600 dark:text-red-400">
                {filteredAssets.reduce((sum, asset) => sum + asset.alertCount, 0)} Total Alerts
              </span>
            </div>
            <div className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-green-500/10 to-emerald-500/10 border border-green-500/20 rounded-lg">
              <Activity className="w-5 h-5 text-green-500" />
              <span className="text-sm font-medium text-green-600 dark:text-green-400">
                {filteredAssets.reduce((sum, asset) => sum + (asset.totalEvents || 0), 0)} Total Events
              </span>
            </div>
          </div>
        </div>

        {/* Search and Filters */}
        <div className="flex flex-col sm:flex-row gap-4 mb-6">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-5 h-5" />
            <input
              type="text"
              placeholder="Search by name, department, or attributes..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-3 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-transparent shadow-lg"
            />
          </div>

          <div className="flex gap-2">
            <select
              value={filterType}
              onChange={(e) => setFilterType(e.target.value as any)}
              className="px-4 py-3 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="all">All Types</option>
              <option value="user">Users</option>
              <option value="computer">Computers</option>
              <option value="ip">IP Addresses</option>
            </select>

            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as any)}
              className="px-4 py-3 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="alerts">Sort by Alerts</option>
              <option value="risk">Sort by Risk</option>
              <option value="activity">Sort by Activity</option>
              <option value="name">Sort by Name</option>
            </select>
          </div>
        </div>
      </div>

      {/* Assets Grid */}
      <div className="flex-1 overflow-y-auto">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {filteredAssets.map((asset) => (
            <div
              key={asset.id}
              onClick={() => setSelectedAsset(asset)}
              className={`relative p-6 rounded-2xl shadow-xl border cursor-pointer transform transition-all duration-300 hover:scale-105 hover:shadow-2xl ${
                darkMode
                  ? 'bg-gray-800/50 border-gray-700/50 hover:bg-gray-800/80'
                  : 'bg-white/80 border-gray-200 hover:bg-white'
              } backdrop-blur-sm`}
            >
              {/* Header */}
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div className={`p-3 rounded-xl ${getRiskBg(asset.riskScore)}`}>
                    {getAssetIcon(asset.type)}
                  </div>
                  <div>
                    <h3 className="text-lg font-bold text-gray-900 dark:text-gray-100">
                      {asset.displayName || asset.name}
                    </h3>
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                      {asset.domain && `${asset.domain}\\`}{asset.name}
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  {asset.privileged && (
                    <Crown className="w-5 h-5 text-yellow-500" />
                  )}
                  {asset.isServiceAccount && (
                    <Server className="w-5 h-5 text-blue-500" />
                  )}
                  <div className={`px-2 py-1 rounded-full text-xs font-medium ${getRiskBg(asset.riskScore)} ${getRiskColor(asset.riskScore)}`}>
                    Risk: {asset.riskScore}
                  </div>
                </div>
              </div>

              {/* Key Metrics */}
              <div className="grid grid-cols-2 gap-4 mb-4">
                <div className="text-center p-3 rounded-lg bg-gradient-to-br from-red-500/10 to-red-600/10 border border-red-500/20">
                  <AlertTriangle className="w-6 h-6 text-red-500 mx-auto mb-1" />
                  <div className="text-2xl font-bold text-red-500">{asset.alertCount}</div>
                  <div className="text-xs text-gray-500">Alerts</div>
                </div>

                <div className="text-center p-3 rounded-lg bg-gradient-to-br from-blue-500/10 to-blue-600/10 border border-blue-500/20">
                  <Activity className="w-6 h-6 text-blue-500 mx-auto mb-1" />
                  <div className="text-2xl font-bold text-blue-500">{asset.totalEvents || 0}</div>
                  <div className="text-xs text-gray-500">Events</div>
                </div>
              </div>

              {/* AD Attributes */}
              <div className="space-y-2 mb-4">
                {asset.department && (
                  <div className="flex items-center gap-2 text-sm">
                    <Building className="w-4 h-4 text-gray-400" />
                    <span className="text-gray-600 dark:text-gray-300">{asset.department}</span>
                  </div>
                )}
                {asset.title && (
                  <div className="flex items-center gap-2 text-sm">
                    <Star className="w-4 h-4 text-gray-400" />
                    <span className="text-gray-600 dark:text-gray-300">{asset.title}</span>
                  </div>
                )}
                {asset.location && (
                  <div className="flex items-center gap-2 text-sm">
                    <MapPin className="w-4 h-4 text-gray-400" />
                    <span className="text-gray-600 dark:text-gray-300">{asset.location}</span>
                  </div>
                )}
              </div>

              {/* Footer */}
              <div className="flex items-center justify-between pt-4 border-t border-gray-200 dark:border-gray-700">
                <div className="flex items-center gap-2 text-sm text-gray-500">
                  <Clock className="w-4 h-4" />
                  <span>Last: {formatLastActivity(asset.lastActivity)}</span>
                </div>

                <div className="flex items-center gap-2 text-sm text-blue-600 dark:text-blue-400 font-medium">
                  <Eye className="w-4 h-4" />
                  <span>View Details</span>
                </div>
              </div>
            </div>
          ))}
        </div>

        {filteredAssets.length === 0 && (
          <div className="text-center py-12">
            <Users className="w-16 h-16 mx-auto mb-4 text-gray-400" />
            <h3 className="text-xl font-medium text-gray-600 dark:text-gray-400 mb-2">
              No Assets Found
            </h3>
            <p className="text-gray-500 dark:text-gray-500">
              Try adjusting your search or filter criteria
            </p>
          </div>
        )}
      </div>

      {/* Asset Details Modal */}
      {selectedAsset && (
        <AssetDetailsModal
          asset={selectedAsset}
          onClose={() => setSelectedAsset(null)}
          darkMode={darkMode}
          events={events}
        />
      )}
    </div>
  );
};

// Asset Details Modal Component
interface AssetDetailsModalProps {
  asset: AssetIdentity;
  onClose: () => void;
  darkMode: boolean;
  events: AuthEvent[];
}

const AssetDetailsModal: React.FC<AssetDetailsModalProps> = ({ asset, onClose, darkMode, events }) => {
  // Get real alerts for this asset from event data
  const assetEvents = events.filter(event => {
    switch (asset.type) {
      case 'user':
        return event.userName === asset.name;
      case 'computer':
        return event.computerName === asset.name;
      case 'ip':
        return event.sourceIp === asset.name;
      default:
        return false;
    }
  });

  // Convert events to alerts format
  const assetAlerts = assetEvents.slice(0, 10).map(event => ({
    id: event.id,
    title: event.status === 'Failed'
      ? `Authentication Failure - ${event.eventId}`
      : `Successful Authentication - ${event.eventId}`,
    severity: event.status === 'Failed' ? 'high' : 'low',
    timestamp: event.timestamp,
    description: `${event.status} authentication from ${event.sourceIp || 'unknown IP'} to ${event.computerName || 'unknown computer'}`,
    event: event
  }));

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-2xl max-w-4xl w-full max-h-[90vh] overflow-hidden">
        {/* Header */}
        <div className="p-6 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className={`p-3 rounded-xl ${
                asset.type === 'user' ? 'bg-blue-500/20 text-blue-600' :
                asset.type === 'computer' ? 'bg-green-500/20 text-green-600' :
                'bg-purple-500/20 text-purple-600'
              }`}>
                {asset.type === 'user' ? <User className="w-8 h-8" /> :
                 asset.type === 'computer' ? <Monitor className="w-8 h-8" /> :
                 <Globe className="w-8 h-8" />}
              </div>
              <div>
                <h2 className="text-2xl font-bold text-gray-900 dark:text-gray-100">
                  {asset.displayName || asset.name}
                </h2>
                <div className="flex items-center gap-4 mt-2">
                  <span className="text-sm text-gray-500">
                    {asset.domain && `${asset.domain}\\`}{asset.name}
                  </span>
                  <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                    asset.enabled ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400' :
                    'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400'
                  }`}>
                    {asset.enabled ? 'Enabled' : 'Disabled'}
                  </span>
                  {asset.privileged && (
                    <span className="px-2 py-1 rounded-full text-xs font-medium bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400">
                      Privileged
                    </span>
                  )}
                  {asset.isServiceAccount && (
                    <span className="px-2 py-1 rounded-full text-xs font-medium bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400">
                      Service Account
                    </span>
                  )}
                </div>
              </div>
            </div>
            <button
              onClick={onClose}
              className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700"
            >
              ✕
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto max-h-[calc(70vh)]">
          <div className="grid md:grid-cols-2 gap-8">
            {/* Left Column - AD Attributes */}
            <div>
              <h3 className="text-lg font-semibold mb-4 text-gray-900 dark:text-gray-100">
                📋 Identity Details
              </h3>

              <div className="space-y-4">
                {asset.department && (
                  <div className="flex items-center gap-3 p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50">
                    <Building className="w-5 h-5 text-gray-400" />
                    <div>
                      <div className="text-sm text-gray-500">Department</div>
                      <div className="font-medium text-gray-900 dark:text-gray-100">{asset.department}</div>
                    </div>
                  </div>
                )}

                {asset.title && (
                  <div className="flex items-center gap-3 p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50">
                    <Star className="w-5 h-5 text-gray-400" />
                    <div>
                      <div className="text-sm text-gray-500">Title</div>
                      <div className="font-medium text-gray-900 dark:text-gray-100">{asset.title}</div>
                    </div>
                  </div>
                )}

                {asset.email && (
                  <div className="flex items-center gap-3 p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50">
                    <Mail className="w-5 h-5 text-gray-400" />
                    <div>
                      <div className="text-sm text-gray-500">Email</div>
                      <div className="font-medium text-gray-900 dark:text-gray-100">{asset.email}</div>
                    </div>
                  </div>
                )}

                {asset.lastLogonDate && (
                  <div className="flex items-center gap-3 p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50">
                    <Clock className="w-5 h-5 text-gray-400" />
                    <div>
                      <div className="text-sm text-gray-500">Last Logon</div>
                      <div className="font-medium text-gray-900 dark:text-gray-100">
                        {asset.lastLogonDate.toLocaleString()}
                      </div>
                    </div>
                  </div>
                )}

                {asset.passwordLastSet && (
                  <div className="flex items-center gap-3 p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50">
                    <Key className="w-5 h-5 text-gray-400" />
                    <div>
                      <div className="text-sm text-gray-500">Password Last Set</div>
                      <div className="font-medium text-gray-900 dark:text-gray-100">
                        {asset.passwordLastSet.toLocaleString()}
                      </div>
                    </div>
                  </div>
                )}

                {asset.groups && asset.groups.length > 0 && (
                  <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50">
                    <div className="flex items-center gap-3 mb-2">
                      <Users className="w-5 h-5 text-gray-400" />
                      <div className="text-sm text-gray-500">Group Memberships</div>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {asset.groups.slice(0, 5).map((group, idx) => (
                        <span key={idx} className="px-2 py-1 bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400 text-xs rounded-full">
                          {group}
                        </span>
                      ))}
                      {asset.groups.length > 5 && (
                        <span className="px-2 py-1 bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-400 text-xs rounded-full">
                          +{asset.groups.length - 5} more
                        </span>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Right Column - Security Metrics & Alerts */}
            <div>
              <h3 className="text-lg font-semibold mb-4 text-gray-900 dark:text-gray-100">
                🛡️ Security Overview
              </h3>

              {/* Risk Score */}
              <div className="mb-6">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Risk Score</span>
                  <span className={`text-lg font-bold ${asset.riskScore >= 80 ? 'text-red-500' : asset.riskScore >= 60 ? 'text-orange-500' : 'text-green-500'}`}>
                    {asset.riskScore}/100
                  </span>
                </div>
                <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-3">
                  <div
                    className={`h-3 rounded-full transition-all duration-300 ${
                      asset.riskScore >= 80 ? 'bg-red-500' :
                      asset.riskScore >= 60 ? 'bg-orange-500' :
                      asset.riskScore >= 40 ? 'bg-yellow-500' : 'bg-green-500'
                    }`}
                    style={{ width: `${asset.riskScore}%` }}
                  ></div>
                </div>
              </div>

              {/* Key Metrics */}
              <div className="grid grid-cols-2 gap-4 mb-6">
                <div className="text-center p-4 rounded-lg bg-gradient-to-br from-red-500/10 to-red-600/10 border border-red-500/20">
                  <AlertTriangle className="w-8 h-8 text-red-500 mx-auto mb-2" />
                  <div className="text-3xl font-bold text-red-500">{asset.alertCount}</div>
                  <div className="text-sm text-gray-600 dark:text-gray-400">Active Alerts</div>
                </div>

                <div className="text-center p-4 rounded-lg bg-gradient-to-br from-blue-500/10 to-blue-600/10 border border-blue-500/20">
                  <Activity className="w-8 h-8 text-blue-500 mx-auto mb-2" />
                  <div className="text-3xl font-bold text-blue-500">{asset.totalEvents || 0}</div>
                  <div className="text-sm text-gray-600 dark:text-gray-400">Total Events</div>
                </div>
              </div>

              {/* Recent Alerts */}
              <div>
                <h4 className="text-md font-semibold mb-3 text-gray-900 dark:text-gray-100">
                  Recent Security Alerts
                </h4>
                <div className="space-y-3">
                  {assetAlerts.map((alert) => (
                    <div key={alert.id} className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50 border border-gray-200 dark:border-gray-600">
                      <div className="flex items-center justify-between mb-2">
                        <h5 className="font-medium text-gray-900 dark:text-gray-100">{alert.title}</h5>
                        <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                          alert.severity === 'high' ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400' :
                          alert.severity === 'medium' ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400' :
                          'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400'
                        }`}>
                          {alert.severity.toUpperCase()}
                        </span>
                      </div>
                      <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">{alert.description}</p>
                      <div className="flex items-center justify-between text-xs text-gray-500">
                        <span>Event ID: {alert.event.eventId}</span>
                        <span>{alert.timestamp.toLocaleString()}</span>
                      </div>
                      {alert.event.rawData?.status && (
                        <div className="mt-1 text-xs text-gray-400">
                          Status: {alert.event.rawData.status}
                        </div>
                      )}
                    </div>
                  ))}
                  {assetAlerts.length === 0 && (
                    <div className="text-center py-4 text-gray-500">
                      <Shield className="w-8 h-8 mx-auto mb-2 opacity-50" />
                      <p>No recent alerts</p>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
