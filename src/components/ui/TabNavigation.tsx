import React from 'react';
import { TabConfig } from '../types/adtrapper.types';

interface TabNavigationProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  tabs: TabConfig[];
  darkMode: boolean;
}

export const TabNavigation: React.FC<TabNavigationProps> = ({
  activeTab,
  setActiveTab,
  tabs,
  darkMode
}) => {
  const cardClasses = darkMode
    ? 'bg-gray-800 border-gray-700'
    : 'bg-white border-gray-200';

  return (
    <div className={`${cardClasses} border-b relative z-10`}>
      <div className="flex">
        {tabs.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-2 px-6 py-3 border-b-2 transition-all relative ${
              activeTab === tab.id
                ? 'border-blue-500 text-blue-500'
                : 'border-transparent hover:text-blue-400'
            }`}
          >
            <tab.icon size={16} />
            {tab.label}
            {tab.badge && tab.badge > 0 && (
              <div className="w-5 h-5 bg-red-500 text-white text-xs rounded-full flex items-center justify-center">
                {tab.badge}
              </div>
            )}
          </button>
        ))}
      </div>
    </div>
  );
};
