import React from 'react';
import {
  User, Shield, AlertTriangle, Brain, Zap, Flame, LogIn, UserPlus,
  Bell, Settings
} from 'lucide-react';
import { Stats, UserMenuPosition } from '../types/adtrapper.types';

interface ADTrapperHeaderProps {
  darkMode: boolean;
  setDarkMode: (dark: boolean) => void;
  stats: Stats;
  onSessionsClick?: () => void;
}

export const ADTrapperHeader: React.FC<ADTrapperHeaderProps> = ({
  darkMode,
  setDarkMode,
  stats,
  onSessionsClick
}) => {
  const cardClasses = darkMode
    ? 'bg-gray-800 border-gray-700'
    : 'bg-white border-gray-200';

  return (
    <div className={`${cardClasses} shadow-lg border-b p-4 relative z-10`}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <div className="w-10 h-10 bg-gradient-to-r from-red-500 to-orange-500 rounded-lg flex items-center justify-center">
              <Flame className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="text-2xl font-bold bg-gradient-to-r from-red-500 to-orange-500 bg-clip-text text-transparent">
                🔥 ADTrapper
              </h1>
              <p className="text-xs text-gray-500">
                AD Security Analysis Platform
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-4">
          {onSessionsClick && (
            <button
              onClick={onSessionsClick}
              className={`p-2 rounded-lg ${darkMode ? 'bg-gray-700 hover:bg-gray-600' : 'bg-gray-100 hover:bg-gray-200'} transition-colors`}
              title="My Data"
            >
              👤
            </button>
          )}

          <button
            onClick={() => setDarkMode(!darkMode)}
            className={`p-2 rounded-lg ${darkMode ? 'bg-gray-700 hover:bg-gray-600' : 'bg-gray-100 hover:bg-gray-200'} transition-colors`}
          >
            {darkMode ? '☀️' : '🌙'}
          </button>
        </div>  
      </div>
      {/* Enhanced Stats */}
      <div className="flex gap-6 mt-6">
        <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-blue-500/10 border border-blue-500/20">
          <User size={16} className="text-blue-500" />
          <span className="text-sm font-medium">Users: {stats.totalUsers}</span>
        </div>
        <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-red-500/10 border border-red-500/20">
          <Shield size={16} className="text-red-500" />
          <span className="text-sm font-medium">Privileged: {stats.privilegedUsers}</span>
        </div>
        <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-orange-500/10 border border-orange-500/20">
          <AlertTriangle size={16} className="text-orange-500" />
          <span className="text-sm font-medium">Failed: {stats.failedLogins}</span>
        </div>
        <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-purple-500/10 border border-purple-500/20">
          <Brain size={16} className="text-purple-500" />
          <span className="text-sm font-medium">Anomalies: {0}</span>
        </div>
        <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-yellow-500/10 border border-yellow-500/20">
          <Zap size={16} className="text-yellow-500" />
          <span className="text-sm font-medium">Risk Score: {Math.round(stats.highRiskNodes / stats.totalUsers * 100) || 0}%</span>
        </div>
      </div>
    </div>
  );
};
