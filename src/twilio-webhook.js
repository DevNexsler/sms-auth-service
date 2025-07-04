/**
 * Twilio Webhook Handler
 * Processes incoming SMS messages and triggers authentication flows
 */

const { createClient } = require('@supabase/supabase-js');
const twilio = require('twilio');
const SessionManager = require('./session_manager');
const { sendSMS } = require('./rcs-helper');

// Initialize Supabase client
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// Initialize session manager
const sessionManager = new SessionManager(supabase);

/**
 * Main webhook handler for Twilio SMS/RCS
 */
async function handleTwilioWebhook(req, res) {
  try {
    // Verify Twilio signature for security
    if (!verifyTwilioSignature(req)) {
      return res.status(403).json({ error: 'Invalid signature' });
    }

    const { 
      From: phoneNumber, 
      Body: message, 
      MessageSid,
      ChannelPrefix // RCS, SM, or MM
    } = req.body;
    
    console.log(`Received ${ChannelPrefix || 'SMS'} from ${phoneNumber}: ${message}`);

    // Normalize phone number to E.164 format
    const normalizedPhone = normalizePhoneNumber(phoneNumber);
    const normalizedMessage = message.trim().toUpperCase();

    // Check for existing session
    const session = await sessionManager.getSession(normalizedPhone);

    // Check for channel downgrade
    if (session?.rcs_required && session?.channel_type === 'RCS' && ChannelPrefix !== 'RCS') {
      await handleSecurityDowngrade(normalizedPhone);
      return res.status(200).send('OK');
    }

    // Route to appropriate handler
    if (isAuthCommand(normalizedMessage)) {
      await handleAuthRequest(normalizedPhone, session);
    } else if (isOTPCode(message) && session?.auth_method === 'otp') {
      await handleOTPVerification(normalizedPhone, message.trim(), session);
    } else if (isLogoutCommand(normalizedMessage)) {
      await handleLogout(normalizedPhone);
    } else if (session && new Date(session.expires_at) > new Date()) {
      await handleAuthenticatedRequest(normalizedPhone, message, session, ChannelPrefix);
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
 * Handle authentication request with RCS channel awareness
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

    // Get RCS settings
    const rcsRequired = process.env.RCS_SECURITY_REQUIRED === 'true';
    const sessionDuration = parseInt(process.env.SESSION_DURATION_DAYS) || 7;

    // Create or update session with RCS requirements
    await sessionManager.upsertSession(phoneNumber, email, 'magic_link', rcsRequired, sessionDuration);

    // Send magic link via email (primary authentication method)
    const { data, error } = await supabase.auth.signInWithOtp({
      email: email,
      options: {
        shouldCreateUser: false,
        emailRedirectTo: `${process.env.APP_URL}/api/auth/callback?phone=${encodeURIComponent(phoneNumber)}`
      }
    });

    if (error) {
      console.error('Magic link error:', error);
      return await sendSMS(phoneNumber,
        "❌ Authentication failed. Please try again later."
      );
    }

    // Send RCS notification about email with status callback
    const message = await sendMessageWithChannelTracking(phoneNumber,
      `🔐 Authentication email sent!\n\n` +
      `Check ${maskEmail(email)} for your magic link.\n\n` +
      `This secure session will last ${sessionDuration} days.`
    );

    // Store message SID for channel tracking
    await supabase
      .from('sms_sessions')
      .update({
        last_message_sid: message.sid,
        updated_at: new Date().toISOString()
      })
      .eq('phone_number', phoneNumber);

    return message;
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
 * Handle authenticated request with RCS channel verification
 */
async function handleAuthenticatedRequest(phoneNumber, message, session, channelPrefix) {
  try {
    // Check for RCS security requirement
    if (session.rcs_required && channelPrefix !== 'RCS') {
      return await handleSecurityDowngrade(phoneNumber);
    }

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
    
    // Send response with channel tracking
    return await sendMessageWithChannelTracking(phoneNumber, response);
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

/**
 * Send message with channel tracking
 */
async function sendMessageWithChannelTracking(phoneNumber, message) {
  try {
    const result = await sendSMS(phoneNumber, message, {
      statusCallback: `${process.env.APP_URL}/api/twilio/status-callback`
    });
    
    return result;
  } catch (error) {
    console.error('Message send error:', error);
    throw error;
  }
}

/**
 * Handle security downgrade from RCS to SMS
 */
async function handleSecurityDowngrade(phoneNumber) {
  try {
    // Mark session as compromised
    await supabase
      .from('sms_sessions')
      .update({ 
        channel_downgrade_detected: true,
        authenticated_at: null,
        session_token: null,
        expires_at: null,
        updated_at: new Date().toISOString()
      })
      .eq('phone_number', phoneNumber);
    
    // Notify user
    return await sendSMS(phoneNumber,
      "⚠️ Secure RCS channel unavailable.\n\n" +
      "For your security, this conversation has been paused.\n\n" +
      "To continue:\n" +
      "• Android: Messages → Settings → Chat features → Enable\n" +
      "• iPhone: Settings → Messages → RCS → Enable\n\n" +
      `Learn more: ${process.env.RCS_SETUP_URL || process.env.APP_URL + '/rcs-setup'}`
    );
  } catch (error) {
    console.error('Security downgrade handling error:', error);
  }
}

/**
 * Handle status callback for channel detection
 */
async function handleStatusCallback(req, res) {
  try {
    const { 
      MessageSid, 
      MessageStatus, 
      ChannelPrefix,
      To
    } = req.body;
    
    console.log(`Status callback: ${MessageSid} - ${MessageStatus} via ${ChannelPrefix}`);
    
    // Update channel type in database
    if (ChannelPrefix) {
      await supabase.rpc('update_channel_type', {
        p_message_sid: MessageSid,
        p_channel_prefix: ChannelPrefix
      });
    }
    
    res.sendStatus(200);
  } catch (error) {
    console.error('Status callback error:', error);
    res.sendStatus(500);
  }
}

module.exports = {
  handleTwilioWebhook,
  handleAuthRequest,
  handleOTPVerification,
  handleAuthenticatedRequest,
  handleStatusCallback,
  handleSecurityDowngrade
};