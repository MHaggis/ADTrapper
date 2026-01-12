import { NextRequest, NextResponse } from 'next/server';

export async function GET(request: NextRequest) {
  try {
    // In anonymous mode, admin features are not available
    return NextResponse.json(
      { error: 'Admin features not available in anonymous mode' },
      { status: 403 }
    );
  } catch (error) {
    console.error('Admin API error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}