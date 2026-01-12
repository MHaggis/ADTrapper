import { useState, useEffect } from 'react';
import { supabase } from '@/lib/supabase';
import { FileUploadService, UploadedSession } from '@/lib/fileUploadService';
import { GraphData } from '../types/adtrapper.types';
import { normalizeData, convertEventsToGraphFormat } from '../utils/adtrapper.utils';

export const useSupabaseConnection = (user: any) => {
  const [supabaseConnected, setSupabaseConnected] = useState(false);
  const [userSessions, setUserSessions] = useState<UploadedSession[]>([]);
  const [currentSession, setCurrentSession] = useState<UploadedSession | null>(null);

  // Test Supabase connection on mount
  useEffect(() => {
    const testSupabaseConnection = async () => {
      try {
        const { data, error } = await supabase.auth.getSession();
        if (error) {
          console.warn('Supabase auth test failed:', error);
          setSupabaseConnected(false);
        } else {
          setSupabaseConnected(true);
        }
      } catch (err) {
        console.error('Supabase connection test failed:', err);
        setSupabaseConnected(false);
      }
    };

    testSupabaseConnection();
  }, []);

  // Load user sessions on login (or in anonymous mode)
  useEffect(() => {
    console.log('useEffect triggered, user:', user?.id || null);
    if (user) {
      console.log('User authenticated, loading sessions...');
      loadUserSessions();
    } else {
      console.log('Anonymous mode - loading sessions...');
      loadUserSessions(); // Load sessions even in anonymous mode
    }
  }, [user?.id]); // Use user.id instead of user to prevent duplicate calls

  const loadUserSessions = async (): Promise<UploadedSession[]> => {
    // In anonymous mode, user is null but we still want to load sessions
    try {
      console.log('Loading user sessions (anonymous mode)');
      const sessions = await FileUploadService.getUserSessions();
      console.log('Loaded sessions:', sessions);
      console.log('Number of sessions:', sessions.length);
      setUserSessions(sessions);

      return sessions;
    } catch (error) {
      console.error('Error loading user sessions:', error);
      // Connection failed - this is expected if Supabase is down
      setSupabaseConnected(false);
      return [];
    }
  };

  const loadSessionData = async (session: UploadedSession): Promise<GraphData | null> => {
    try {
      console.log('Loading session data for:', session.id);
      const sessionData = await FileUploadService.loadSessionData(session);
      console.log('Session data loaded:', sessionData);

      if (sessionData && sessionData.events && Array.isArray(sessionData.events)) {
        // Convert events to graph format first
        console.log('Converting events to graph format...');
        console.log('Raw events sample:', sessionData.events.slice(0, 3));
        const graphData = convertEventsToGraphFormat(sessionData.events, sessionData.context);
        console.log('Graph data created:', { 
          nodes: graphData.nodes.length, 
          edges: graphData.edges.length,
          rawLogs: graphData.rawLogs?.length || 0
        });

        // Then normalize the graph data
        const normalizedSessionData = normalizeData(graphData);
        console.log('Normalized session data:', {
          nodes: normalizedSessionData.nodes.length,
          edges: normalizedSessionData.edges.length,
          rawLogs: normalizedSessionData.rawLogs?.length || 0
        });
        setCurrentSession(session);
        return normalizedSessionData;
      }
      return null;
    } catch (sessionError) {
      console.warn('Session data loading failed:', sessionError);
      return null;
    }
  };

  const deleteSession = async (sessionId: string): Promise<boolean> => {
    try {
      await FileUploadService.deleteSession(sessionId);
      await loadUserSessions(); // Refresh sessions list
      return true;
    } catch (error) {
      console.error('Error deleting session:', error);
      return false;
    }
  };

  const updateSessionAnalysis = async (sessionId: string, anomalyCount: number): Promise<boolean> => {
    try {
      await FileUploadService.updateSessionAnalysis(sessionId, anomalyCount);
      return true;
    } catch (updateError) {
      console.warn('Could not update session analysis:', updateError);
      return false;
    }
  };

  return {
    supabaseConnected,
    userSessions,
    currentSession,
    setCurrentSession,
    loadUserSessions,
    loadSessionData,
    deleteSession,
    updateSessionAnalysis
  };
};
