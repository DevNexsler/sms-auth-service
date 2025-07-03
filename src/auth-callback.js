/**
 * Auth Callback Handler
 * Handles magic link callbacks from email authentication
 */

const { createClient } = require('@supabase/supabase-js');
const SessionManager = require('./session_manager');
const { sendSMS } = require('./sms_helper');

// Initialize Supabase client
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// Initialize session manager
const sessionManager = new SessionManager(supabase);

/**
 * Handle magic link callback
 * This endpoint is called when user clicks the magic link in their email
 */
async function handleAuthCallback(req, res) {
  try {
    const { token_hash, type, error: callbackError } = req.query;

    // Handle errors from Supabase
    if (callbackError) {
      console.error('Callback error from Supabase:', callbackError);
      return res.redirect(`/auth/error?message=${encodeURIComponent(callbackError)}`);
    }

    // Verify this is a magic link callback
    if (type !== 'magiclink' && type !== 'recovery') {
      return res.status(400).send('Invalid callback type');
    }

    // Verify token_hash exists
    if (!token_hash) {
      return res.redirect('/auth/error?message=Missing+authentication+token');
    }

    // Exchange token for session
    const { data, error } = await supabase.auth.verifyOtp({
      token_hash,
      type: type === 'recovery' ? 'recovery' : 'magiclink',
    });

    if (error) {
      console.error('Token verification error:', error);
      
      // Determine appropriate error message
      let errorMessage = 'Authentication failed';
      if (error.message.includes('expired')) {
        errorMessage = 'This link has expired. Please request a new one.';
      } else if (error.message.includes('invalid')) {
        errorMessage = 'This link is invalid or has already been used.';
      }
      
      return res.redirect(`/auth/error?message=${encodeURIComponent(errorMessage)}`);
    }

    if (!data.user || !data.session) {
      return res.redirect('/auth/error?message=Authentication+failed');
    }

    // Find SMS session by email
    const { data: smsSession } = await supabase
      .from('sms_sessions')
      .select('*')
      .eq('email', data.user.email)
      .order('updated_at', { ascending: false })
      .limit(1)
      .single();

    if (!smsSession) {
      console.error('No SMS session found for email:', data.user.email);
      return res.redirect('/auth/error?message=Session+not+found');
    }

    // Create authenticated session
    const sessionDuration = parseInt(process.env.AUTH_SESSION_DURATION_DAYS) || 7;
    await sessionManager.createSession(
      smsSession.phone_number,
      data.user.email,
      data.user.id,
      data.session.access_token,
      'magic_link'
    );

    // Send SMS confirmation
    try {
      await sendSMS(
        smsSession.phone_number,
        `✅ You're authenticated for ${sessionDuration} days! ` +
        "You can now interact with the AI assistant via SMS. " +
        "Text LOGOUT anytime to sign out."
      );
    } catch (smsError) {
      console.error('Failed to send SMS confirmation:', smsError);
      // Continue even if SMS fails
    }

    // Set session cookie (optional, for web-based management)
    if (data.session) {
      res.cookie('auth-token', data.session.access_token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: sessionDuration * 24 * 60 * 60 * 1000 // Convert days to milliseconds
      });
    }

    // Redirect to success page
    return res.redirect('/auth/success');

  } catch (error) {
    console.error('Callback handler error:', error);
    return res.redirect('/auth/error?message=An+unexpected+error+occurred');
  }
}

/**
 * Handle auth success page
 */
async function handleAuthSuccess(req, res) {
  const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Authentication Successful</title>
      <style>
        body {
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          display: flex;
          align-items: center;
          justify-content: center;
          min-height: 100vh;
          margin: 0;
          background: #f9fafb;
        }
        .container {
          text-align: center;
          padding: 2rem;
          background: white;
          border-radius: 8px;
          box-shadow: 0 1px 3px rgba(0,0,0,0.1);
          max-width: 400px;
        }
        .success-icon {
          width: 64px;
          height: 64px;
          margin: 0 auto 1.5rem;
          background: #10b981;
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
        }
        .success-icon svg {
          width: 32px;
          height: 32px;
          stroke: white;
          stroke-width: 3;
        }
        h1 {
          color: #111827;
          font-size: 1.5rem;
          margin-bottom: 0.5rem;
        }
        p {
          color: #6b7280;
          line-height: 1.5;
          margin: 0.5rem 0;
        }
        .close-notice {
          margin-top: 2rem;
          padding: 1rem;
          background: #eff6ff;
          border-radius: 6px;
          font-size: 0.875rem;
          color: #3730a3;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="success-icon">
          <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" />
          </svg>
        </div>
        <h1>Authentication Successful!</h1>
        <p>You're now signed in to the AI Assistant.</p>
        <p>Return to your SMS conversation to continue.</p>
        <div class="close-notice">
          You can close this window now.
        </div>
      </div>
      <script>
        // Auto-close window after 5 seconds (if opened as popup)
        setTimeout(() => {
          if (window.opener) {
            window.close();
          }
        }, 5000);
      </script>
    </body>
    </html>
  `;
  
  res.status(200).send(html);
}

/**
 * Handle auth error page
 */
async function handleAuthError(req, res) {
  const message = req.query.message || 'Authentication failed';
  
  const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Authentication Error</title>
      <style>
        body {
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          display: flex;
          align-items: center;
          justify-content: center;
          min-height: 100vh;
          margin: 0;
          background: #f9fafb;
        }
        .container {
          text-align: center;
          padding: 2rem;
          background: white;
          border-radius: 8px;
          box-shadow: 0 1px 3px rgba(0,0,0,0.1);
          max-width: 400px;
        }
        .error-icon {
          width: 64px;
          height: 64px;
          margin: 0 auto 1.5rem;
          background: #ef4444;
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
        }
        .error-icon svg {
          width: 32px;
          height: 32px;
          stroke: white;
          stroke-width: 3;
        }
        h1 {
          color: #111827;
          font-size: 1.5rem;
          margin-bottom: 0.5rem;
        }
        p {
          color: #6b7280;
          line-height: 1.5;
          margin: 0.5rem 0;
        }
        .error-message {
          margin: 1rem 0;
          padding: 1rem;
          background: #fef2f2;
          border-radius: 6px;
          color: #991b1b;
          font-size: 0.875rem;
        }
        .help-text {
          margin-top: 1.5rem;
          font-size: 0.875rem;
          color: #6b7280;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="error-icon">
          <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </div>
        <h1>Authentication Error</h1>
        <div class="error-message">
          ${message}
        </div>
        <p class="help-text">
          Please return to your SMS conversation and text LOGIN to try again.
        </p>
      </div>
    </body>
    </html>
  `;
  
  res.status(400).send(html);
}

/**
 * Handle session status check (API endpoint)
 */
async function handleSessionStatus(req, res) {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.replace('Bearer ', '') || req.cookies['auth-token'];

    if (!token) {
      return res.status(401).json({ error: 'No authentication token' });
    }

    // Verify token with Supabase
    const { data: { user }, error } = await supabase.auth.getUser(token);

    if (error || !user) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    // Find SMS session
    const { data: session } = await supabase
      .from('sms_sessions')
      .select('*')
      .eq('user_id', user.id)
      .eq('session_token', token)
      .single();

    if (!session) {
      return res.status(404).json({ error: 'Session not found' });
    }

    // Check if expired
    if (new Date(session.expires_at) < new Date()) {
      return res.status(401).json({ 
        error: 'Session expired',
        expired_at: session.expires_at
      });
    }

    // Return session info
    res.json({
      authenticated: true,
      phone_number: session.phone_number,
      email: user.email,
      expires_at: session.expires_at,
      auth_method: session.auth_method,
      user_id: user.id,
      org_id: user.user_metadata?.org_id,
      user_role: user.user_metadata?.user_role
    });

  } catch (error) {
    console.error('Session status error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
}

module.exports = {
  handleAuthCallback,
  handleAuthSuccess,
  handleAuthError,
  handleSessionStatus
};