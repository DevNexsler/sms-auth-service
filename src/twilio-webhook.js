/**
 * Twilio Webhook Handler
 * Processes incoming SMS messages and triggers authentication flows
 */

const { createClient } = require('@supabase/supabase-js');
const twilio = require('twilio');
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
 * Main webhook handler for Twilio SMS
 */
async function handleTwilioWebhook(req, res) {
  try {
    // Verify Twilio signature for security
    if (!verifyTwilioSignature(req)) {
      return res.status(403).json({ error: 'Invalid signature' });
    }

    const { From: phoneNumber, Body: message, MessageSid } = req.body;
    console.log(`Received SMS from ${phoneNumber}: ${message}`);

    // Normalize phone number to E.164 format
    const normalizedPhone = normalizePhoneNumber(phoneNumber);
    const normalizedMessage = message.trim().toUpperCase();

    // Check for existing session
    const session = await sessionManager.getSession(normalizedPhone);

    // Route to appropriate handler
    if (isAuthCommand(normalizedMessage)) {
      await handleAuthRequest(normalizedPhone, session);
    } else if (isOTPCode(message) && session?.auth_method === 'otp') {
      await handleOTPVerification(normalizedPhone, message.trim(), session);
    } else if (isLogoutCommand(normalizedMessage)) {
      await handleLogout(normalizedPhone);
    } else if (session && new Date(session.expires_at) > new Date()) {
      await handleAuthenticatedRequest(normalizedPhone, message, session);
    } else {
      await handleUnauthenticatedRequest(normalizedPhone, message);
    }

    res.status(200).send('OK');
  } catch (error) {
    console.error('Webhook error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
}

/**
 * Verify Twilio webhook signature
 */
function verifyTwilioSignature(req) {
  const twilioSignature = req.headers['x-twilio-signature'];
  const url = `${process.env.WEBHOOK_URL}/api/twilio/webhook`;
  
  return twilio.validateRequest(
    process.env.TWILIO_AUTH_TOKEN,
    twilioSignature,
    url,
    req.body
  );
}

/**
 * Handle authentication request
 */
async function handleAuthRequest(phoneNumber, existingSession) {
  try {
    // Check rate limiting
    const rateLimit = await sessionManager.checkRateLimit(phoneNumber);
    if (rateLimit.limited) {
      const resetTime = new Date(rateLimit.resetTime);
      const minutesRemaining = Math.ceil((resetTime - Date.now()) / 60000);
      
      return await sendSMS(phoneNumber,
        `⏳ Too many attempts. Please try again in ${minutesRemaining} minutes.`
      );
    }

    // Get user email from existing session or database lookup
    const email = existingSession?.email || await lookupEmailByPhone(phoneNumber);
    
    if (!email) {
      return await sendSMS(phoneNumber,
        "📱 Phone number not registered. Please contact your administrator to set up access."
      );
    }

    // Record authentication attempt
    await sessionManager.recordAuthAttempt(phoneNumber, email);

    // Determine auth method from environment or session
    const authMethod = process.env.AUTH_METHOD || 'magic_link';

    if (authMethod === 'otp') {
      // Send OTP
      const { data, error } = await supabase.auth.signInWithOtp({
        email: email,
        options: {
          shouldCreateUser: false
        }
      });

      if (error) {
        console.error('OTP generation error:', error);
        return await sendSMS(phoneNumber,
          "❌ Authentication failed. Please try again later."
        );
      }

      // Store auth method in session
      await supabase
        .from('sms_sessions')
        .upsert({
          phone_number: phoneNumber,
          email: email,
          auth_method: 'otp',
          updated_at: new Date().toISOString()
        });

      return await sendSMS(phoneNumber,
        `📧 Check your email! We've sent a 6-digit code to ${maskEmail(email)}. ` +
        "Reply with the code to complete authentication."
      );
    } else {
      // Send magic link
      const { data, error } = await supabase.auth.signInWithOtp({
        email: email,
        options: {
          shouldCreateUser: false,
          emailRedirectTo: `${process.env.APP_URL}/api/auth/callback`
        }
      });

      if (error) {
        console.error('Magic link error:', error);
        return await sendSMS(phoneNumber,
          "❌ Authentication failed. Please try again later."
        );
      }

      // Store auth method in session
      await supabase
        .from('sms_sessions')
        .upsert({
          phone_number: phoneNumber,
          email: email,
          auth_method: 'magic_link',
          updated_at: new Date().toISOString()
        });

      return await sendSMS(phoneNumber,
        `✉️ Check your email! We've sent a magic link to ${maskEmail(email)}. ` +
        "Click the link to complete authentication."
      );
    }
  } catch (error) {
    console.error('Authentication error:', error);
    return await sendSMS(phoneNumber,
      "❌ An error occurred. Please try again later."
    );
  }
}

/**
 * Handle OTP verification
 */
async function handleOTPVerification(phoneNumber, otpCode, session) {
  try {
    const { data, error } = await supabase.auth.verifyOtp({
      email: session.email,
      token: otpCode,
      type: 'email'
    });

    if (error) {
      console.error('OTP verification error:', error);
      
      // Check remaining attempts
      const rateLimit = await sessionManager.checkRateLimit(phoneNumber);
      
      if (rateLimit.remainingAttempts > 0) {
        return await sendSMS(phoneNumber,
          `❌ Invalid code. ${rateLimit.remainingAttempts} attempts remaining. ` +
          "Please check the code and try again."
        );
      } else {
        return await sendSMS(phoneNumber,
          "❌ Too many failed attempts. Please request a new code."
        );
      }
    }

    // Create authenticated session
    const authSession = await sessionManager.createSession(
      phoneNumber,
      session.email,
      data.user.id,
      data.session.access_token,
      'otp'
    );

    const durationDays = parseInt(process.env.AUTH_SESSION_DURATION_DAYS) || 7;
    
    return await sendSMS(phoneNumber,
      `✅ Authentication successful! You're now signed in for ${durationDays} days. ` +
      "How can I help you today?"
    );
  } catch (error) {
    console.error('OTP verification error:', error);
    return await sendSMS(phoneNumber,
      "❌ Verification failed. Please try again or request a new code."
    );
  }
}

/**
 * Handle logout request
 */
async function handleLogout(phoneNumber) {
  await sessionManager.invalidateSession(phoneNumber);
  return await sendSMS(phoneNumber,
    "👋 You've been signed out successfully. Text LOGIN to sign in again."
  );
}

/**
 * Handle authenticated request
 */
async function handleAuthenticatedRequest(phoneNumber, message, session) {
  try {
    // Get user context with RBAC info
    const userContext = await sessionManager.getUserContext(phoneNumber);
    
    if (!userContext) {
      await sessionManager.invalidateSession(phoneNumber);
      return await sendSMS(phoneNumber,
        "⚠️ Session expired. Please text LOGIN to authenticate again."
      );
    }

    // Here you would integrate with your AI agent
    // For now, we'll just echo back with user info
    const response = await processAIRequest(message, userContext);
    
    return await sendSMS(phoneNumber, response);
  } catch (error) {
    console.error('Request processing error:', error);
    return await sendSMS(phoneNumber,
      "❌ An error occurred processing your request. Please try again."
    );
  }
}

/**
 * Handle unauthenticated request
 */
async function handleUnauthenticatedRequest(phoneNumber, message) {
  return await sendSMS(phoneNumber,
    "🔒 Please authenticate first by texting LOGIN. " +
    "You'll receive a verification link via email."
  );
}

/**
 * Process AI request with user context
 * This is where you'd integrate with your AI agent
 */
async function processAIRequest(message, userContext) {
  // Placeholder for AI integration
  // In production, this would call your AI agent with full context
  
  return `[AI Response] You said: "${message}"\n` +
         `Organization: ${userContext.org_id}\n` +
         `Role: ${userContext.user_role}`;
}

/**
 * Lookup email by phone number
 * This would connect to your user management system
 */
async function lookupEmailByPhone(phoneNumber) {
  // First check SMS sessions table
  const { data: session } = await supabase
    .from('sms_sessions')
    .select('email')
    .eq('phone_number', phoneNumber)
    .single();

  if (session?.email) {
    return session.email;
  }

  // Check organization phone numbers
  const { data: phoneRecord } = await supabase
    .from('organization_phone_numbers')
    .select('assigned_to_email')
    .eq('phone_number', phoneNumber)
    .single();

  return phoneRecord?.assigned_to_email || null;
}

/**
 * Helper functions
 */
function normalizePhoneNumber(phone) {
  // Ensure E.164 format
  if (!phone.startsWith('+')) {
    // Assume US number if no country code
    return `+1${phone.replace(/\D/g, '')}`;
  }
  return phone;
}

function isAuthCommand(message) {
  const authCommands = ['LOGIN', 'SIGNIN', 'AUTH', 'AUTHENTICATE'];
  return authCommands.includes(message);
}

function isLogoutCommand(message) {
  const logoutCommands = ['LOGOUT', 'SIGNOUT', 'EXIT', 'QUIT'];
  return logoutCommands.includes(message);
}

function isOTPCode(message) {
  // Check if message is a 6-digit code
  return /^\d{6}$/.test(message.trim());
}

function maskEmail(email) {
  const [localPart, domain] = email.split('@');
  const maskedLocal = localPart.length > 2
    ? `${localPart.slice(0, 2)}***`
    : '***';
  return `${maskedLocal}@${domain}`;
}

module.exports = {
  handleTwilioWebhook,
  handleAuthRequest,
  handleOTPVerification,
  handleAuthenticatedRequest
};