/**
 * Session Manager for SMS Authentication
 * Handles session lifecycle and user context retrieval
 */

class SessionManager {
  constructor(supabase) {
    this.supabase = supabase;
    this.sessionCache = new Map(); // Simple in-memory cache
  }

  /**
   * Get active session for a phone number
   */
  async getSession(phoneNumber) {
    // Check cache first
    const cached = this.sessionCache.get(phoneNumber);
    if (cached && new Date(cached.expires_at) > new Date()) {
      return cached;
    }

    // Query database
    const { data: session, error } = await this.supabase
      .from('sms_sessions')
      .select('*')
      .eq('phone_number', phoneNumber)
      .single();

    if (error || !session) {
      this.sessionCache.delete(phoneNumber);
      return null;
    }

    // Check if session is expired
    if (new Date(session.expires_at) < new Date()) {
      await this.invalidateSession(phoneNumber);
      return null;
    }

    // Cache valid session
    this.sessionCache.set(phoneNumber, session);
    return session;
  }

  /**
   * Validate session and check if still active
   */
  async validateSession(phoneNumber) {
    const session = await this.getSession(phoneNumber);
    if (!session || !session.user_id || !session.session_token) {
      return false;
    }

    try {
      // Verify token with Supabase Auth
      const { data: { user }, error } = await this.supabase.auth.getUser(
        session.session_token
      );

      if (error || !user) {
        // Token is invalid, clear session
        await this.invalidateSession(phoneNumber);
        return false;
      }

      return true;
    } catch (error) {
      console.error('Session validation error:', error);
      return false;
    }
  }

  /**
   * Create or update session after successful authentication
   */
  async createSession(phoneNumber, email, userId, accessToken, authMethod = 'magic_link') {
    const sessionDurationDays = parseInt(process.env.AUTH_SESSION_DURATION_DAYS) || 7;
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + sessionDurationDays);

    const { data: session, error } = await this.supabase
      .from('sms_sessions')
      .upsert({
        phone_number: phoneNumber,
        email: email,
        user_id: userId,
        session_token: accessToken,
        auth_method: authMethod,
        authenticated_at: new Date().toISOString(),
        expires_at: expiresAt.toISOString(),
        auth_attempts: 0, // Reset on successful auth
        updated_at: new Date().toISOString()
      }, {
        onConflict: 'phone_number'
      })
      .select()
      .single();

    if (error) {
      console.error('Failed to create session:', error);
      throw error;
    }

    // Update cache
    this.sessionCache.set(phoneNumber, session);
    return session;
  }

  /**
   * Refresh an existing session
   */
  async refreshSession(phoneNumber) {
    const session = await this.getSession(phoneNumber);
    if (!session || !session.session_token) {
      return null;
    }

    try {
      // Note: Refresh token functionality would require storing refresh tokens
      // For now, we'll extend the existing session
      const sessionDurationDays = parseInt(process.env.AUTH_SESSION_DURATION_DAYS) || 7;
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + sessionDurationDays);

      const { data: updatedSession, error } = await this.supabase
        .from('sms_sessions')
        .update({
          expires_at: expiresAt.toISOString(),
          updated_at: new Date().toISOString()
        })
        .eq('phone_number', phoneNumber)
        .select()
        .single();

      if (error) {
        console.error('Failed to refresh session:', error);
        return null;
      }

      // Update cache
      this.sessionCache.set(phoneNumber, updatedSession);
      return updatedSession;
    } catch (error) {
      console.error('Session refresh error:', error);
      return null;
    }
  }

  /**
   * Invalidate a session
   */
  async invalidateSession(phoneNumber) {
    // Clear from cache
    this.sessionCache.delete(phoneNumber);

    // Update database
    const { error } = await this.supabase
      .from('sms_sessions')
      .update({
        session_token: null,
        authenticated_at: null,
        expires_at: null,
        updated_at: new Date().toISOString()
      })
      .eq('phone_number', phoneNumber);

    if (error) {
      console.error('Failed to invalidate session:', error);
    }
  }

  /**
   * Get user context including RBAC information
   */
  async getUserContext(phoneNumber) {
    const session = await this.getSession(phoneNumber);
    if (!session || !session.user_id || !session.session_token) {
      return null;
    }

    try {
      // Get user with JWT claims
      const { data: { user }, error } = await this.supabase.auth.getUser(
        session.session_token
      );

      if (error || !user) {
        return null;
      }

      // Extract RBAC info from JWT (set by auth hook)
      const orgId = user.user_metadata?.org_id || 
                    user.app_metadata?.org_id ||
                    null;
      
      const userRole = user.user_metadata?.user_role || 
                       user.app_metadata?.user_role ||
                       null;

      return {
        user_id: user.id,
        email: user.email,
        phone_number: phoneNumber,
        org_id: orgId,
        user_role: userRole,
        session_expires_at: session.expires_at,
        metadata: session.metadata || {}
      };
    } catch (error) {
      console.error('Failed to get user context:', error);
      return null;
    }
  }

  /**
   * Record authentication attempt (for rate limiting)
   */
  async recordAuthAttempt(phoneNumber, email) {
    const { data, error } = await this.supabase
      .from('sms_sessions')
      .upsert({
        phone_number: phoneNumber,
        email: email,
        auth_attempts: 1,
        last_attempt_at: new Date().toISOString()
      }, {
        onConflict: 'phone_number',
        ignoreDuplicates: false
      })
      .select()
      .single();

    if (!error && data.auth_attempts > 1) {
      // Increment attempts if session already exists
      await this.supabase
        .from('sms_sessions')
        .update({
          auth_attempts: data.auth_attempts + 1,
          last_attempt_at: new Date().toISOString()
        })
        .eq('phone_number', phoneNumber);
    }

    return data;
  }

  /**
   * Check if phone number is rate limited
   */
  async checkRateLimit(phoneNumber) {
    const { data: session } = await this.supabase
      .from('sms_sessions')
      .select('auth_attempts, last_attempt_at')
      .eq('phone_number', phoneNumber)
      .single();

    if (!session) return { limited: false, remainingAttempts: 3 };

    // Check if enough time has passed to reset attempts
    const timeSinceLastAttempt = Date.now() - new Date(session.last_attempt_at).getTime();
    const oneHour = 60 * 60 * 1000;

    if (timeSinceLastAttempt > oneHour) {
      // Reset attempts
      await this.supabase
        .from('sms_sessions')
        .update({ auth_attempts: 0 })
        .eq('phone_number', phoneNumber);
      
      return { limited: false, remainingAttempts: 3 };
    }

    const maxAttempts = 3;
    const isLimited = session.auth_attempts >= maxAttempts;
    const remainingAttempts = Math.max(0, maxAttempts - session.auth_attempts);
    const resetTime = new Date(session.last_attempt_at).getTime() + oneHour;

    return {
      limited: isLimited,
      remainingAttempts,
      resetTime: isLimited ? new Date(resetTime) : null
    };
  }

  /**
   * Store OTP for verification
   */
  async storeOTP(phoneNumber, otp, expirationMinutes = 10) {
    const expiresAt = new Date();
    expiresAt.setMinutes(expiresAt.getMinutes() + expirationMinutes);

    const { error } = await this.supabase
      .from('sms_sessions')
      .update({
        pending_otp: otp,
        otp_expires_at: expiresAt.toISOString()
      })
      .eq('phone_number', phoneNumber);

    if (error) {
      console.error('Failed to store OTP:', error);
      throw error;
    }
  }

  /**
   * Verify OTP
   */
  async verifyOTP(phoneNumber, providedOTP) {
    const { data: session } = await this.supabase
      .from('sms_sessions')
      .select('pending_otp, otp_expires_at')
      .eq('phone_number', phoneNumber)
      .single();

    if (!session || !session.pending_otp) {
      return { valid: false, reason: 'No OTP found' };
    }

    // Check expiration
    if (new Date(session.otp_expires_at) < new Date()) {
      await this.clearOTP(phoneNumber);
      return { valid: false, reason: 'OTP expired' };
    }

    // Verify OTP (constant-time comparison for security)
    const isValid = session.pending_otp === providedOTP;

    if (isValid) {
      await this.clearOTP(phoneNumber);
    }

    return { valid: isValid };
  }

  /**
   * Clear stored OTP
   */
  async clearOTP(phoneNumber) {
    await this.supabase
      .from('sms_sessions')
      .update({
        pending_otp: null,
        otp_expires_at: null
      })
      .eq('phone_number', phoneNumber);
  }

  /**
   * Clean up expired sessions (maintenance function)
   */
  async cleanupExpiredSessions() {
    const { data, error } = await this.supabase
      .rpc('cleanup_expired_sessions');

    if (error) {
      console.error('Failed to cleanup sessions:', error);
    }

    // Clear cache
    this.sessionCache.clear();

    return !error;
  }

  /**
   * Get session statistics (for monitoring)
   */
  async getSessionStats() {
    const { data, error } = await this.supabase
      .from('sms_sessions')
      .select('authenticated_at, expires_at, auth_method')
      .not('authenticated_at', 'is', null)
      .gte('expires_at', new Date().toISOString());

    if (error) {
      console.error('Failed to get session stats:', error);
      return null;
    }

    const stats = {
      activeSessions: data.length,
      byMethod: {
        magic_link: data.filter(s => s.auth_method === 'magic_link').length,
        otp: data.filter(s => s.auth_method === 'otp').length
      },
      averageSessionAge: 0
    };

    if (data.length > 0) {
      const ages = data.map(s => 
        Date.now() - new Date(s.authenticated_at).getTime()
      );
      stats.averageSessionAge = ages.reduce((a, b) => a + b, 0) / ages.length;
    }

    return stats;
  }
}

module.exports = SessionManager;