import React from 'react';
import DashboardStats from '@/components/dashboard/DashboardStats';

interface DashboardTabProps {
  data: any;
  anomalies: any[];
  darkMode: boolean;
  setActiveTab: (tab: string) => void;
}

export const DashboardTab: React.FC<DashboardTabProps> = ({
  data,
  anomalies,
  darkMode,
  setActiveTab
}) => {
  return (
    <DashboardStats
      data={data}
      anomalies={anomalies}
      cardClasses={darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'}
      onViewAlerts={() => setActiveTab('alerts')}
    />
  );
};
