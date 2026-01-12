import React, { useRef, useEffect } from 'react';
import { createPortal } from 'react-dom';
import { User, Database, Settings, Lock } from 'lucide-react';
import { UserMenuPosition } from '../types/adtrapper.types';

interface UserMenuProps {
  showUserMenu: boolean;
  setShowUserMenu: (show: boolean) => void;
  dropdownPosition: UserMenuPosition;
  profile: any;
  user: any;
  userSessions: any[];
  onProfileClick: () => void;
  onSessionsClick: () => void;
  onSettingsClick: () => void;
  onSignOut: () => void;
}

export const UserMenu: React.FC<UserMenuProps> = ({
  showUserMenu,
  setShowUserMenu,
  dropdownPosition,
  profile,
  user,
  userSessions,
  onProfileClick,
  onSessionsClick,
  onSettingsClick,
  onSignOut
}) => {
  const userMenuRef = useRef<HTMLDivElement>(null);

  // Close user menu when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      const target = event.target as Node;

      // Check if click is outside both the menu button and the dropdown
      if (userMenuRef.current && !userMenuRef.current.contains(target)) {
        // Also check if the click is not on the portal dropdown
        const dropdownElement = document.querySelector('[data-dropdown-portal]');
        if (!dropdownElement || !dropdownElement.contains(target)) {
          setShowUserMenu(false);
        }
      }
    };

    if (showUserMenu) {
      document.addEventListener('mousedown', handleClickOutside);
      return () => {
        document.removeEventListener('mousedown', handleClickOutside);
      };
    }
  }, [showUserMenu, setShowUserMenu]);

  if (!showUserMenu || typeof window === 'undefined') return null;

  return createPortal(
    <div
      data-dropdown-portal
      className="fixed w-48 bg-white dark:bg-gray-800 rounded-lg shadow-xl border border-gray-200 dark:border-gray-700 transition-all duration-200"
      style={{
        top: dropdownPosition.top,
        right: dropdownPosition.right,
        zIndex: 999999,
        boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.25)'
      }}
    >
      <div className="p-2">
        <button
          onClick={() => {
            onProfileClick();
            setShowUserMenu(false);
          }}
          className="w-full text-left px-3 py-2 text-sm hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg flex items-center gap-2"
        >
          <User size={16} />
          My Profile
        </button>
        <button
          onClick={() => {
            onSessionsClick();
            setShowUserMenu(false);
          }}
          className="w-full text-left px-3 py-2 text-sm hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg flex items-center gap-2"
        >
          <Database size={16} />
          My Data
        </button>
        <button
          onClick={() => {
            onSettingsClick();
            setShowUserMenu(false);
          }}
          className="w-full text-left px-3 py-2 text-sm hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg flex items-center gap-2"
        >
          <Settings size={16} />
          Settings
        </button>
        <hr className="my-2 border-gray-200 dark:border-gray-700" />
        <button
          onClick={async () => {
            try {
              console.log('Sign out clicked');
              await onSignOut();
              setShowUserMenu(false);
              console.log('Sign out completed');
            } catch (error) {
              console.error('Sign out error:', error);
              alert('Sign out failed. Please try again.');
            }
          }}
          className="w-full text-left px-3 py-2 text-sm text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg flex items-center gap-2"
        >
          <Lock size={16} />
          Sign Out
        </button>
      </div>
    </div>,
    document.body
  );
};
