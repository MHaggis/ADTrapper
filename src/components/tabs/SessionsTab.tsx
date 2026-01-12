import React from 'react';
import { Upload, Database, Eye, AlertTriangle } from 'lucide-react';

import { UploadedSession as ServiceUploadedSession } from '@/lib/fileUploadService';

interface UploadedSession extends ServiceUploadedSession {
  // Extend the service type if needed
}

interface SessionsTabProps {
  darkMode: boolean;
  userSessions: UploadedSession[];
  currentSession: UploadedSession | null;
  setActiveTab: (tab: string) => void;
  loadSessionData: (session: UploadedSession) => Promise<any>;
  deleteSession: (sessionId: string) => Promise<boolean>;
  updateData: (data: any) => void;
}

export const SessionsTab: React.FC<SessionsTabProps> = ({
  darkMode,
  userSessions,
  currentSession,
  setActiveTab,
  loadSessionData,
  deleteSession,
  updateData
}) => {
  const cardClasses = darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200';

  if (userSessions.length === 0) {
    return (
      <div className="max-w-6xl mx-auto">
        <div className={`${cardClasses} p-8 rounded-xl shadow-lg text-center`}>
          <Database className="w-16 h-16 mx-auto text-gray-400 mb-4" />
          <h3 className="text-xl font-semibold mb-2">No Sessions Yet</h3>
          <p className="text-gray-500 mb-4">
            Upload your first authentication log file to start analyzing security events
          </p>
          <button
            onClick={() => setActiveTab('upload')}
            className="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
          >
            Upload Data
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto">
      <div className="mb-6 flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold mb-2">My Analysis Sessions</h2>
          <p className="text-gray-500">View and manage your uploaded data</p>
        </div>
        <button
          onClick={() => setActiveTab('upload')}
          className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors flex items-center gap-2"
        >
          <Upload className="w-4 h-4" />
          Upload New Data
        </button>
      </div>

      <div className="grid gap-4">
        {userSessions.map((session) => (
          <div
            key={session.id}
            className={`${cardClasses} p-6 rounded-xl shadow-lg border ${
              currentSession?.id === session.id ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20' : 'border-gray-200 dark:border-gray-700'
            }`}
          >
            <div className="flex justify-between items-start">
              <div className="flex-1">
                <div className="flex items-center gap-3 mb-3">
                  <div className="w-10 h-10 bg-gradient-to-r from-blue-500 to-purple-500 rounded-lg flex items-center justify-center">
                    <Database className="w-5 h-5 text-white" />
                  </div>
                  <div>
                    <h3 className="font-semibold text-lg">{session.session_name}</h3>
                    <p className="text-sm text-gray-500">
                      Uploaded {new Date(session.uploaded_at).toLocaleDateString()} at {new Date(session.uploaded_at).toLocaleTimeString()}
                    </p>
                  </div>
                </div>

                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                  <div className="bg-gray-50 dark:bg-gray-800 p-3 rounded-lg">
                                              <div className="text-2xl font-bold text-blue-600">{session.event_count ?? 0}</div>
                            <div className="text-sm text-gray-500">Events</div>
                          </div>
                          <div className="bg-gray-50 dark:bg-gray-800 p-3 rounded-lg">
                            <div className="text-2xl font-bold text-orange-600">{session.anomaly_count ?? 0}</div>
                            <div className="text-sm text-gray-500">Anomalies</div>
                          </div>
                          <div className="bg-gray-50 dark:bg-gray-800 p-3 rounded-lg">
                            <div className="text-2xl font-bold text-green-600">
                              {session.file_size_bytes ? `${Math.round(session.file_size_bytes / 1024 / 1024)}MB` : 'N/A'}
                            </div>
                            <div className="text-sm text-gray-500">File Size</div>
                          </div>
                          <div className="bg-gray-50 dark:bg-gray-800 p-3 rounded-lg">
                            <div className="text-2xl font-bold text-purple-600">
                              {session.time_range_start && session.time_range_end
                                ? `${Math.round((new Date(session.time_range_end).getTime() - new Date(session.time_range_start).getTime()) / (1000 * 60 * 60))}h`
                                : 'N/A'
                              }
                            </div>
                            <div className="text-sm text-gray-500">Time Range</div>
                          </div>
                </div>

                {session.file_name && (
                  <div className="text-sm text-gray-600 dark:text-gray-400 mb-3">
                    <strong>File:</strong> {session.file_name}
                  </div>
                )}
              </div>

              <div className="flex gap-2 ml-4">
                <button
                  onClick={async () => {
                    try {
                      const sessionData = await loadSessionData(session);
                      if (sessionData) {
                        updateData(sessionData);
                        setActiveTab('dashboard');
                      }
                    } catch (error) {
                      console.error('Error loading session:', error);
                      alert('Failed to load session data');
                    }
                  }}
                  className="px-3 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors flex items-center gap-2"
                >
                  <Eye className="w-4 h-4" />
                  View
                </button>
                <button
                  onClick={async () => {
                    if (confirm('Are you sure you want to delete this session? This action cannot be undone.')) {
                      try {
                        await deleteSession(session.id);
                      } catch (error) {
                        console.error('Error deleting session:', error);
                        alert('Failed to delete session');
                      }
                    }
                  }}
                  className="px-3 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors flex items-center gap-2"
                >
                  <AlertTriangle className="w-4 h-4" />
                  Delete
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
