import React from 'react';
import { WifiOff } from 'lucide-react';

interface OfflineBannerProps {
  supabaseConnected: boolean;
}

export const OfflineBanner: React.FC<OfflineBannerProps> = ({ supabaseConnected }) => {
  if (supabaseConnected) return null;

  return (
    <div className="bg-yellow-500/10 border-b border-yellow-500/20 p-2 relative z-10">
      <div className="flex items-center justify-center gap-2 text-yellow-600 dark:text-yellow-400 text-sm">
        <WifiOff size={16} />
        <span>Offline Mode - Running with sample data. Upload and save features unavailable.</span>
      </div>
    </div>
  );
};
