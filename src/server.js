/**
 * SMS Authentication Service
 * Express server for handling SMS-based authentication via Supabase
 */

const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

// Import handlers
const { 
  handleTwilioWebhook,
  handleStatusCallback 
} = require('./twilio-webhook');
const { 
  handleAuthCallback, 
  handleAuthSuccess, 
  handleAuthError, 
  handleSessionStatus 
} = require('./auth-callback');

// Environment variables
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';

// Validate required environment variables
const requiredEnvVars = [
  'SUPABASE_URL',
  'SUPABASE_ANON_KEY',
  'SUPABASE_SERVICE_ROLE_KEY',
  'TWILIO_ACCOUNT_SID',
  'TWILIO_AUTH_TOKEN',
  'TWILIO_PHONE_NUMBER',
  'APP_URL',
  'MESSAGING_SERVICE_SID'  // Required for RCS
];

const missingEnvVars = requiredEnvVars.filter(varName => !process.env[varName]);
if (missingEnvVars.length > 0) {
  console.error('[ERROR] Missing required environment variables:', missingEnvVars);
  if (NODE_ENV === 'production') {
    process.exit(1);
  }
}

// Initialize Express app
const app = express();

// Trust proxy for proper IP and protocol detection on Render
app.set('trust proxy', true);

// Middleware
app.use(cors({
  origin: true, // Allow all origins for webhooks
  credentials: true
}));

// Parse JSON with higher limit for potential large payloads
app.use(express.json({ limit: '10mb' }));

// Parse URL-encoded data (for Twilio webhooks)
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request logging middleware
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'rcs-auth-service',
    environment: NODE_ENV,
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    config: {
      has_supabase_url: !!process.env.SUPABASE_URL,
      has_supabase_keys: !!process.env.SUPABASE_SERVICE_ROLE_KEY,
      has_twilio_config: !!process.env.TWILIO_ACCOUNT_SID,
      has_messaging_service: !!process.env.MESSAGING_SERVICE_SID,
      auth_method: 'email_magic_link',
      session_duration: process.env.SESSION_DURATION_DAYS || '7',
      rcs_security_required: process.env.RCS_SECURITY_REQUIRED === 'true'
    }
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    service: 'RCS Authentication Service',
    version: '2.0.0',
    endpoints: {
      health: '/health',
      twilio_webhook: '/api/twilio/webhook',
      status_callback: '/api/twilio/status-callback',
      auth_callback: '/api/auth/callback',
      auth_status: '/api/auth/status',
      auth_success: '/auth/success',
      auth_error: '/auth/error',
      rcs_setup: '/rcs-setup'
    }
  });
});

// RCS Authentication endpoints
app.post('/api/twilio/webhook', handleTwilioWebhook);
app.post('/api/twilio/status-callback', handleStatusCallback);
app.get('/api/auth/callback', handleAuthCallback);
app.get('/api/auth/status', handleSessionStatus);

// Auth result pages
app.get('/auth/success', handleAuthSuccess);
app.get('/auth/error', handleAuthError);

// RCS setup help page
app.get('/rcs-setup', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Enable RCS Messaging</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; }
        h1 { color: #333; }
        .instruction { background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .platform { font-weight: bold; color: #0066cc; }
        code { background: #e0e0e0; padding: 2px 6px; border-radius: 3px; }
      </style>
    </head>
    <body>
      <h1>🔐 Enable RCS for Secure Messaging</h1>
      <p>This service requires RCS (Rich Communication Services) for enhanced security.</p>
      
      <div class="instruction">
        <p class="platform">📱 Android (Google Messages)</p>
        <ol>
          <li>Open <strong>Messages</strong> app</li>
          <li>Tap the three dots menu → <strong>Settings</strong></li>
          <li>Tap <strong>Chat features</strong></li>
          <li>Toggle <strong>Enable chat features</strong> ON</li>
          <li>Wait for "Connected" status</li>
        </ol>
      </div>

      <div class="instruction">
        <p class="platform">🍎 iPhone (iOS 18+)</p>
        <ol>
          <li>Open <strong>Settings</strong></li>
          <li>Tap <strong>Messages</strong></li>
          <li>Find <strong>RCS Messaging</strong></li>
          <li>Toggle <strong>RCS Messaging</strong> ON</li>
        </ol>
      </div>

      <h2>Why RCS?</h2>
      <ul>
        <li>✅ Encrypted messaging between services</li>
        <li>✅ Verified business identity</li>
        <li>✅ Protection against SMS vulnerabilities</li>
        <li>✅ Rich interactive features</li>
      </ul>

      <h2>Test Your RCS</h2>
      <p>Once enabled, text <code>LOGIN</code> to <strong>${process.env.TWILIO_PHONE_NUMBER || '+1XXXXXXXXXX'}</strong></p>
    </body>
    </html>
  `);
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Not Found',
    message: `Endpoint ${req.method} ${req.path} not found`,
    timestamp: new Date().toISOString()
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('[ERROR]', err);
  
  // Don't leak error details in production
  const message = NODE_ENV === 'production' 
    ? 'Internal server error' 
    : err.message;
  
  res.status(err.status || 500).json({
    error: message,
    timestamp: new Date().toISOString()
  });
});

// Graceful shutdown handling
process.on('SIGTERM', () => {
  console.log('[INFO] SIGTERM signal received, closing HTTP server');
  server.close(() => {
    console.log('[INFO] HTTP server closed');
    process.exit(0);
  });
});

// Start server
const server = app.listen(PORT, () => {
  console.log('[INFO] RCS Authentication Service started');
  console.log(`[INFO] Environment: ${NODE_ENV}`);
  console.log(`[INFO] Port: ${PORT}`);
  console.log(`[INFO] App URL: ${process.env.APP_URL || 'Not configured'}`);
  console.log(`[INFO] Auth Method: Email Magic Link with RCS notifications`);
  console.log(`[INFO] Session Duration: ${process.env.SESSION_DURATION_DAYS || '7'} days`);
  console.log(`[INFO] RCS Security Required: ${process.env.RCS_SECURITY_REQUIRED === 'true' ? 'Yes' : 'No'}`);
  console.log(`[INFO] Messaging Service: ${process.env.MESSAGING_SERVICE_SID ? 'Configured' : 'Not configured'}`);
  
  if (NODE_ENV === 'development') {
    console.log(`[INFO] Local URL: http://localhost:${PORT}`);
    console.log(`[INFO] RCS Setup URL: http://localhost:${PORT}/rcs-setup`);
  }
});

// Export for testing
module.exports = app;