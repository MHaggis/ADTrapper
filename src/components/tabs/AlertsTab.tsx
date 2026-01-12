import React from 'react';
import AlertsManagement from '@/components/alerts/AlertsManagement';

interface AlertsTabProps {
  anomalies: any[];
  supabaseConnected: boolean;
  darkMode: boolean;
  onGraphAlert?: (anomaly: any, relatedEvents: any[], affectedEntities: any[]) => void;
}

export const AlertsTab: React.FC<AlertsTabProps> = ({
  anomalies,
  supabaseConnected,
  darkMode,
  onGraphAlert
}) => {
  return (
    <AlertsManagement
      anomalies={anomalies}
      supabaseConnected={supabaseConnected}
      cardClasses={darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'}
      onGraphAlert={onGraphAlert}
    />
  );
};
