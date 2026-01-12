import { NextRequest, NextResponse } from 'next/server';
import https from 'https';

// Create an HTTPS agent that accepts self-signed certificates
const httpsAgent = new https.Agent({
  rejectUnauthorized: false, // Accept self-signed certificates
});

// Helper function to determine if we should use the HTTPS agent
const getFetchOptions = (url: string, ignoreSslErrors: boolean = true) => {
  const options: any = {};
  
  // Only use the HTTPS agent for HTTPS URLs when SSL errors should be ignored
  if (url.startsWith('https://') && ignoreSslErrors) {
    // @ts-ignore - agent property exists but TypeScript doesn't recognize it
    options.agent = httpsAgent;
  }
  
  return options;
};

interface SplunkHECRequest {
  action: 'test' | 'send';
  endpoint: string;
  token: string;
  data?: any;
  ignoreSslErrors?: boolean;
}

export async function POST(request: NextRequest) {
  try {
    const body: SplunkHECRequest = await request.json();
    const { action, endpoint, token, data, ignoreSslErrors = true } = body;

    if (!endpoint || !token) {
      return NextResponse.json(
        { error: 'Endpoint and token are required' },
        { status: 400 }
      );
    }

    // Normalize endpoint to include /services/collector
    const normalizeEndpoint = (url: string): string => {
      let normalizedEndpoint = url.replace(/\/+$/, '');
      if (!normalizedEndpoint.includes('/services/collector')) {
        normalizedEndpoint += '/services/collector';
      }
      return normalizedEndpoint;
    };

    const hecEndpoint = normalizeEndpoint(endpoint);

    console.log(`Splunk HEC ${action} request to:`, hecEndpoint);

    if (action === 'test') {
      // Test connection with a simple event
      const testEvent = {
        event: {
          message: 'ADTrapper connection test',
          timestamp: new Date().toISOString(),
          test: true
        },
        sourcetype: 'adtrapper:test',
        time: Math.floor(Date.now() / 1000)
      };

      const fetchOptions = getFetchOptions(hecEndpoint, ignoreSslErrors);
      const response = await fetch(hecEndpoint, {
        method: 'POST',
        headers: {
          'Authorization': `Splunk ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(testEvent),
        ...fetchOptions
      });

      if (response.ok) {
        const responseText = await response.text();
        console.log('Splunk HEC test successful:', responseText);
        return NextResponse.json({ 
          success: true, 
          message: 'Connection test successful',
          response: responseText
        });
      } else {
        const errorText = await response.text();
        console.error('Splunk HEC test failed:', response.status, response.statusText, errorText);
        return NextResponse.json({
          success: false,
          error: `HTTP ${response.status}: ${response.statusText}`,
          details: errorText
        }, { status: response.status });
      }
    }

    if (action === 'send' && data) {
      // Send actual log data
      const fetchOptions = getFetchOptions(hecEndpoint, ignoreSslErrors);
      const response = await fetch(hecEndpoint, {
        method: 'POST',
        headers: {
          'Authorization': `Splunk ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(data),
        ...fetchOptions
      });

      if (response.ok) {
        const responseText = await response.text();
        console.log('Splunk HEC send successful:', responseText);
        return NextResponse.json({ 
          success: true, 
          message: 'Logs sent successfully',
          response: responseText
        });
      } else {
        const errorText = await response.text();
        console.error('Splunk HEC send failed:', response.status, response.statusText, errorText);
        return NextResponse.json({
          success: false,
          error: `HTTP ${response.status}: ${response.statusText}`,
          details: errorText
        }, { status: response.status });
      }
    }

    return NextResponse.json(
      { error: 'Invalid action or missing data' },
      { status: 400 }
    );

  } catch (error) {
    console.error('Splunk HEC API error:', error);
    
    let errorMessage = 'Unknown error occurred';
    if (error instanceof Error) {
      errorMessage = error.message;
      
      // Handle specific error types
      if (error.message.includes('ECONNREFUSED')) {
        errorMessage = 'Connection refused - check if Splunk HEC service is running and accessible';
      } else if (error.message.includes('ENOTFOUND')) {
        errorMessage = 'Host not found - check the endpoint URL';
      } else if (error.message.includes('ECONNRESET')) {
        errorMessage = 'Connection reset - possible network or SSL issues';
      } else if (error.message.includes('certificate')) {
        errorMessage = 'SSL certificate error - this API endpoint should handle self-signed certificates';
      }
    }

    return NextResponse.json(
      { 
        success: false, 
        error: errorMessage,
        type: 'server_error'
      },
      { status: 500 }
    );
  }
}

export async function GET() {
  return NextResponse.json({
    message: 'Splunk HEC API endpoint',
    endpoints: {
      POST: {
        description: 'Test connection or send logs to Splunk HEC',
        actions: ['test', 'send'],
        required: ['action', 'endpoint', 'token'],
        optional: ['data (for send action)']
      }
    }
  });
}
