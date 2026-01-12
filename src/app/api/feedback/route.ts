import { NextRequest, NextResponse } from 'next/server';
import { Pool } from 'pg';

export async function POST(request: NextRequest) {
  try {
    // In anonymous mode, just validate and return success without database
    const body = await request.json();
    const { subject, message, category, priority } = body;

    // Validate required fields
    if (!subject?.trim() || !message?.trim()) {
      return NextResponse.json(
        { error: 'Subject and message are required' },
        { status: 400 }
      );
    }

    // Validate category and priority
    const validCategories = ['general', 'bug', 'feature', 'support', 'billing'];
    const validPriorities = ['low', 'normal', 'high', 'urgent'];

    if (!validCategories.includes(category)) {
      return NextResponse.json(
        { error: 'Invalid category' },
        { status: 400 }
      );
    }

    if (!validPriorities.includes(priority)) {
      return NextResponse.json(
        { error: 'Invalid priority' },
        { status: 400 }
      );
    }

    // Mock successful feedback submission
    console.log('Feedback submitted (mock):', { subject, message, category, priority });

    return NextResponse.json({
      success: true,
      message: 'Feedback submitted successfully (anonymous mode)',
      feedback: {
        id: 'mock-' + Date.now(),
        subject: subject.trim(),
        category,
        priority,
        created_at: new Date().toISOString()
      }
    });

  } catch (error) {
    console.error('Unexpected error in feedback API:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

// GET endpoint to retrieve user's own feedback (for future use)
export async function GET(request: NextRequest) {
  try {
    // In anonymous mode, return mock feedback data
    const mockFeedback = [
      {
        id: 'mock-1',
        subject: 'Welcome to ADTrapper',
        message: 'Thank you for using ADTrapper in anonymous mode!',
        category: 'general',
        priority: 'normal',
        is_read: false,
        admin_response: null,
        responded_at: null,
        created_at: new Date().toISOString()
      }
    ];

    return NextResponse.json({
      success: true,
      feedback: mockFeedback
    });

  } catch (error) {
    console.error('Unexpected error in feedback GET API:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
