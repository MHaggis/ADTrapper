import React from 'react';
import AnalyticsPage from '@/components/analytics/AnalyticsPage';

interface AnalyticsTabProps {
  anomalies: any[];
  darkMode: boolean;
}

export const AnalyticsTab: React.FC<AnalyticsTabProps> = ({
  anomalies,
  darkMode
}) => {
  return (
    <AnalyticsPage
      anomalies={anomalies}
      cardClasses={darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'}
      darkMode={darkMode}
    />
  );
};
