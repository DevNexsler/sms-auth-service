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
const { handleTwilioWebhook } = require('./twilio-webhook');
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
  'APP_URL'
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
    service: 'sms-auth-service',
    environment: NODE_ENV,
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    config: {
      has_supabase_url: !!process.env.SUPABASE_URL,
      has_supabase_keys: !!process.env.SUPABASE_SERVICE_ROLE_KEY,
      has_twilio_config: !!process.env.TWILIO_ACCOUNT_SID,
      auth_method: process.env.AUTH_METHOD || 'magic_link',
      session_duration: process.env.AUTH_SESSION_DURATION_DAYS || '7'
    }
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    service: 'SMS Authentication Service',
    version: '1.0.0',
    endpoints: {
      health: '/health',
      twilio_webhook: '/api/twilio/webhook',
      auth_callback: '/api/auth/callback',
      auth_status: '/api/auth/status',
      auth_success: '/auth/success',
      auth_error: '/auth/error'
    }
  });
});

// SMS Authentication endpoints
app.post('/api/twilio/webhook', handleTwilioWebhook);
app.get('/api/auth/callback', handleAuthCallback);
app.get('/api/auth/status', handleSessionStatus);

// Auth result pages
app.get('/auth/success', handleAuthSuccess);
app.get('/auth/error', handleAuthError);

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
  console.log('[INFO] SMS Authentication Service started');
  console.log(`[INFO] Environment: ${NODE_ENV}`);
  console.log(`[INFO] Port: ${PORT}`);
  console.log(`[INFO] App URL: ${process.env.APP_URL || 'Not configured'}`);
  console.log(`[INFO] Auth Method: ${process.env.AUTH_METHOD || 'magic_link'}`);
  console.log(`[INFO] Session Duration: ${process.env.AUTH_SESSION_DURATION_DAYS || '7'} days`);
  
  if (NODE_ENV === 'development') {
    console.log(`[INFO] Local URL: http://localhost:${PORT}`);
  }
});

// Export for testing
module.exports = app;