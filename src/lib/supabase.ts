// Mock Supabase client for anonymous mode
// This prevents REST API calls and provides mock responses

interface MockResult {
  data: any
  error: { message: string } | null
}

// Chainable mock query builder
const createQueryBuilder = (): any => {
  const result: any = {
    data: [],
    error: null,
    eq: (...args: any[]) => result,
    neq: (...args: any[]) => result,
    lt: (...args: any[]) => result,
    gt: (...args: any[]) => result,
    lte: (...args: any[]) => result,
    gte: (...args: any[]) => result,
    like: (...args: any[]) => result,
    ilike: (...args: any[]) => result,
    is: (...args: any[]) => result,
    in: (...args: any[]) => result,
    contains: (...args: any[]) => result,
    order: (...args: any[]) => result,
    limit: (...args: any[]) => result,
    range: (...args: any[]) => result,
    single: async (): Promise<MockResult> => ({ data: null, error: null }),
    maybeSingle: async (): Promise<MockResult> => ({ data: null, error: null })
  }
  return result
}

export const supabase: any = {
  auth: {
    getSession: async () => ({
      data: { session: null, user: null },
      error: null
    }),
    getUser: async () => ({
      data: { user: null },
      error: null
    }),
    signInWithPassword: async () => ({
      data: { session: null, user: null },
      error: { message: 'Authentication not available in anonymous mode' }
    }),
    signUp: async () => ({
      data: { session: null, user: null },
      error: { message: 'Authentication not available in anonymous mode' }
    }),
    signOut: async () => ({
      error: null
    }),
    onAuthStateChange: (callback: any) => {
      return {
        data: { subscription: { unsubscribe: () => {} } }
      }
    }
  },
  from: (table: string) => ({
    select: (...args: any[]) => createQueryBuilder(),
    insert: (...args: any[]) => ({
      select: (...args: any[]) => ({
        single: async () => ({
          data: { id: 'mock-id' },
          error: null
        })
      })
    }),
    update: (...args: any[]) => ({
      eq: (...args: any[]) => ({
        select: (...args: any[]) => ({
          single: async () => ({
            data: null,
            error: null
          })
        })
      })
    }),
    delete: () => createQueryBuilder()
  }),
  storage: {
    from: (bucket: string) => ({
      remove: async (paths: string[]) => ({ error: null }),
      download: async (path: string) => ({ data: null, error: null }),
      upload: async (path: string, file: any) => ({ data: { path }, error: null }),
      getPublicUrl: (path: string) => ({ data: { publicUrl: '' } })
    })
  }
}

// Database types for our simplified schema
export interface Database {
  public: {
    Tables: {
      analysis_sessions: {
        Row: {
          id: string
          session_name: string
          uploaded_at: string
          file_name: string | null
          file_size_bytes: number | null
          event_count: number | null
          anomaly_count: number | null
          time_range_start: string | null
          time_range_end: string | null
          storage_path: string
          created_at: string
        }
        Insert: {
          id?: string
          session_name: string
          uploaded_at?: string
          file_name?: string | null
          file_size_bytes?: number | null
          event_count?: number | null
          anomaly_count?: number | null
          time_range_start?: string | null
          time_range_end?: string | null
          storage_path: string
          created_at?: string
        }
        Update: {
          id?: string
          session_name?: string
          uploaded_at?: string
          file_name?: string | null
          file_size_bytes?: number | null
          event_count?: number | null
          anomaly_count?: number | null
          time_range_start?: string | null
          time_range_end?: string | null
          storage_path?: string
          created_at?: string
        }
      }
      event_data: {
        Row: {
          id: string
          session_id: string
          event_type: string | null
          event_data: any
          timestamp: string | null
          source_ip: string | null
          destination_ip: string | null
          username: string | null
          computer_name: string | null
          event_id: number | null
          created_at: string
        }
        Insert: {
          id?: string
          session_id: string
          event_type?: string | null
          event_data: any
          timestamp?: string | null
          source_ip?: string | null
          destination_ip?: string | null
          username?: string | null
          computer_name?: string | null
          event_id?: number | null
          created_at?: string
        }
        Update: {
          id?: string
          session_id?: string
          event_type?: string | null
          event_data?: any
          timestamp?: string | null
          source_ip?: string | null
          destination_ip?: string | null
          username?: string | null
          computer_name?: string | null
          event_id?: number | null
          created_at?: string
        }
      }
      analysis_results: {
        Row: {
          id: string
          session_id: string
          rule_id: string
          rule_name: string
          severity: string
          event_data: any
          findings: any
          timestamp: string
          created_at: string
        }
        Insert: {
          id?: string
          session_id: string
          rule_id: string
          rule_name: string
          severity?: string
          event_data?: any
          findings?: any
          timestamp?: string
          created_at?: string
        }
        Update: {
          id?: string
          session_id?: string
          rule_id?: string
          rule_name?: string
          severity?: string
          event_data?: any
          findings?: any
          timestamp?: string
          created_at?: string
        }
      }
      feedback: {
        Row: {
          id: string
          session_id: string | null
          rating: number
          feedback_text: string | null
          is_bug_report: boolean
          contact_email: string | null
          created_at: string
        }
        Insert: {
          id?: string
          session_id?: string | null
          rating: number
          feedback_text?: string | null
          is_bug_report?: boolean
          contact_email?: string | null
          created_at?: string
        }
        Update: {
          id?: string
          session_id?: string | null
          rating?: number
          feedback_text?: string | null
          is_bug_report?: boolean
          contact_email?: string | null
          created_at?: string
        }
      }
    }
  }
}
