import { supabase } from './supabase';

export interface FeedbackSubmission {
  subject: string;
  message: string;
  category: 'general' | 'bug' | 'feature' | 'support' | 'billing';
  priority: 'low' | 'normal' | 'high' | 'urgent';
}

export interface FeedbackItem {
  id: string;
  subject: string;
  message: string;
  category: 'general' | 'bug' | 'feature' | 'support' | 'billing';
  priority: 'low' | 'normal' | 'high' | 'urgent';
  is_read: boolean;
  admin_response?: string;
  responded_at?: string;
  created_at: string;
}

export class FeedbackService {
  private static supabase = supabase;

  /**
   * Submit feedback from a user
   */
  static async submitFeedback(feedback: FeedbackSubmission): Promise<{ success: boolean; feedback?: FeedbackItem }> {
    try {
      // In anonymous mode, just call the API without authentication
      const response = await fetch('/api/feedback', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(feedback),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Failed to submit feedback');
      }

      const result = await response.json();
      return {
        success: true,
        feedback: result.feedback
      };
    } catch (error) {
      console.error('Error submitting feedback:', error);
      throw error;
    }
  }

  /**
   * Get user's own feedback history
   */
  static async getUserFeedback(): Promise<FeedbackItem[]> {
    try {
      // In anonymous mode, just call the API without authentication
      const response = await fetch('/api/feedback', {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Failed to fetch feedback');
      }

      const result = await response.json();
      return result.feedback || [];
    } catch (error) {
      console.error('Error fetching user feedback:', error);
      throw error;
    }
  }

  /**
   * Admin function to get all feedback (requires admin role)
   */
  static async getAllFeedback(): Promise<FeedbackItem[]> {
    try {
      const { data, error } = await this.supabase
        .from('user_feedback')
        .select(`
          id,
          subject,
          message,
          category,
          priority,
          is_read,
          admin_response,
          responded_at,
          created_at,
          user_profiles!inner (
            email,
            display_name,
            organization
          )
        `)
        .order('created_at', { ascending: false });

      if (error) {
        throw error;
      }

      return data || [];
    } catch (error) {
      console.error('Error fetching all feedback:', error);
      throw error;
    }
  }

  /**
   * Admin function to mark feedback as read
   */
  static async markFeedbackAsRead(feedbackId: string): Promise<void> {
    try {
      const { error } = await this.supabase
        .from('user_feedback')
        .update({ is_read: true })
        .eq('id', feedbackId);

      if (error) {
        throw error;
      }
    } catch (error) {
      console.error('Error marking feedback as read:', error);
      throw error;
    }
  }

  /**
   * Admin function to respond to feedback
   */
  static async respondToFeedback(feedbackId: string, response: string): Promise<void> {
    try {
      const { error } = await this.supabase
        .from('user_feedback')
        .update({
          admin_response: response,
          responded_at: new Date().toISOString(),
          is_read: true
        })
        .eq('id', feedbackId);

      if (error) {
        throw error;
      }
    } catch (error) {
      console.error('Error responding to feedback:', error);
      throw error;
    }
  }

  /**
   * Get feedback statistics for admin dashboard
   */
  static async getFeedbackStats(): Promise<{
    total: number;
    unread: number;
    byCategory: Record<string, number>;
    byPriority: Record<string, number>;
  }> {
    try {
      const { data, error } = await this.supabase
        .from('user_feedback')
        .select('category, priority, is_read');

      if (error) {
        throw error;
      }

      const stats = {
        total: data?.length || 0,
        unread: data?.filter((f: any) => !f.is_read).length || 0,
        byCategory: {} as Record<string, number>,
        byPriority: {} as Record<string, number>
      };

      data?.forEach((feedback: any) => {
        stats.byCategory[feedback.category] = (stats.byCategory[feedback.category] || 0) + 1;
        stats.byPriority[feedback.priority] = (stats.byPriority[feedback.priority] || 0) + 1;
      });

      return stats;
    } catch (error) {
      console.error('Error fetching feedback stats:', error);
      throw error;
    }
  }
}
