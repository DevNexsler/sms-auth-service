-- 01_sms_sessions_table.sql
-- RCS-enabled SMS Sessions table for phone-based authentication

-- Create SMS sessions table to track phone-to-user mappings with RCS support
CREATE TABLE IF NOT EXISTS sms_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  phone_number text NOT NULL UNIQUE,
  user_id uuid REFERENCES auth.users(id) ON DELETE CASCADE,
  email text NOT NULL,
  session_token text,
  auth_method text DEFAULT 'magic_link' CHECK (auth_method IN ('magic_link', 'otp')),
  authenticated_at timestamptz,
  expires_at timestamptz,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now(),
  
  -- Track authentication attempts for rate limiting
  auth_attempts integer DEFAULT 0,
  last_attempt_at timestamptz,
  
  -- OTP specific fields
  pending_otp text, -- Store OTP temporarily during verification
  otp_expires_at timestamptz, -- OTP expiration time
  
  -- RCS Channel tracking
  channel_type text DEFAULT 'UNKNOWN' CHECK (channel_type IN ('RCS', 'SMS', 'UNKNOWN', 'PENDING')),
  channel_downgrade_detected boolean DEFAULT false,
  rcs_required boolean DEFAULT true,
  last_message_sid text, -- Track last message for channel detection
  session_duration_days integer DEFAULT 7,
  
  -- Session metadata (can store additional context)
  metadata jsonb DEFAULT '{}'::jsonb
);

-- Create indexes for performance
CREATE INDEX idx_sms_sessions_phone ON sms_sessions(phone_number);
CREATE INDEX idx_sms_sessions_user_id ON sms_sessions(user_id);
CREATE INDEX idx_sms_sessions_expires ON sms_sessions(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX idx_sms_sessions_email ON sms_sessions(email);
CREATE INDEX idx_sms_sessions_message_sid ON sms_sessions(last_message_sid);
CREATE INDEX idx_sms_sessions_channel ON sms_sessions(channel_type) WHERE channel_type != 'UNKNOWN';

-- Enable Row Level Security
ALTER TABLE sms_sessions ENABLE ROW LEVEL SECURITY;

-- RLS Policies
-- Only service role can manage sessions (for security)
CREATE POLICY "Service role manages all sessions"
  ON sms_sessions FOR ALL 
  TO service_role
  USING (true)
  WITH CHECK (true);

-- Authenticated users can view their own session
CREATE POLICY "Users can view own session"
  ON sms_sessions FOR SELECT
  TO authenticated
  USING (user_id = auth.uid());

-- Function to clean up expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  -- Delete sessions that have been expired for more than 30 days
  DELETE FROM sms_sessions 
  WHERE expires_at < (now() - interval '30 days');
  
  -- Clear OTP fields for expired OTPs
  UPDATE sms_sessions
  SET 
    pending_otp = NULL,
    otp_expires_at = NULL
  WHERE otp_expires_at < now();
  
  -- Clear channel downgrade sessions older than 1 day
  DELETE FROM sms_sessions
  WHERE channel_downgrade_detected = true
    AND updated_at < (now() - interval '1 day');
END;
$$;

-- Create a trigger to update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_sms_sessions_updated_at 
  BEFORE UPDATE ON sms_sessions
  FOR EACH ROW 
  EXECUTE FUNCTION update_updated_at_column();

-- Helper function to get active session by phone number with RCS check
CREATE OR REPLACE FUNCTION get_active_session(phone text)
RETURNS TABLE (
  session_id uuid,
  user_id uuid,
  email text,
  expires_at timestamptz,
  channel_type text,
  channel_downgrade_detected boolean,
  metadata jsonb
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  RETURN QUERY
  SELECT 
    s.id,
    s.user_id,
    s.email,
    s.expires_at,
    s.channel_type,
    s.channel_downgrade_detected,
    s.metadata
  FROM sms_sessions s
  WHERE s.phone_number = phone
    AND s.expires_at > now()
    AND s.authenticated_at IS NOT NULL
    AND s.channel_downgrade_detected = false
  LIMIT 1;
END;
$$;

-- Helper function to create or update session with RCS settings
CREATE OR REPLACE FUNCTION upsert_sms_session(
  p_phone_number text,
  p_email text,
  p_auth_method text DEFAULT 'magic_link',
  p_rcs_required boolean DEFAULT true,
  p_session_duration_days integer DEFAULT 7
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_session_id uuid;
BEGIN
  INSERT INTO sms_sessions (
    phone_number, 
    email, 
    auth_method, 
    rcs_required, 
    session_duration_days,
    channel_type
  )
  VALUES (
    p_phone_number, 
    p_email, 
    p_auth_method, 
    p_rcs_required, 
    p_session_duration_days,
    'PENDING'
  )
  ON CONFLICT (phone_number) 
  DO UPDATE SET
    email = EXCLUDED.email,
    auth_method = EXCLUDED.auth_method,
    auth_attempts = sms_sessions.auth_attempts + 1,
    last_attempt_at = now(),
    rcs_required = EXCLUDED.rcs_required,
    session_duration_days = EXCLUDED.session_duration_days,
    channel_type = 'PENDING',
    channel_downgrade_detected = false,
    updated_at = now()
  RETURNING id INTO v_session_id;
  
  RETURN v_session_id;
END;
$$;

-- Function to update channel type based on message delivery
CREATE OR REPLACE FUNCTION update_channel_type(
  p_message_sid text,
  p_channel_prefix text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_channel_type text;
  v_rcs_required boolean;
BEGIN
  -- Determine channel type from prefix
  v_channel_type := CASE 
    WHEN p_channel_prefix = 'RCS' THEN 'RCS'
    WHEN p_channel_prefix IN ('SM', 'MM') THEN 'SMS'
    ELSE 'UNKNOWN'
  END;
  
  -- Update session with channel info
  UPDATE sms_sessions
  SET 
    channel_type = v_channel_type,
    channel_downgrade_detected = (rcs_required AND v_channel_type = 'SMS')
  WHERE last_message_sid = p_message_sid;
  
  -- If downgrade detected, revoke authentication
  UPDATE sms_sessions
  SET 
    authenticated_at = NULL,
    session_token = NULL,
    expires_at = NULL
  WHERE last_message_sid = p_message_sid
    AND channel_downgrade_detected = true;
END;
$$;

-- Function to check if RCS is available for a phone number
CREATE OR REPLACE FUNCTION check_rcs_capability(p_phone_number text)
RETURNS TABLE (
  is_capable boolean,
  last_known_channel text,
  days_since_last_rcs integer
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  RETURN QUERY
  SELECT 
    COALESCE(s.channel_type = 'RCS', false) as is_capable,
    s.channel_type as last_known_channel,
    EXTRACT(DAY FROM (now() - s.updated_at))::integer as days_since_last_rcs
  FROM sms_sessions s
  WHERE s.phone_number = p_phone_number
    AND s.channel_type = 'RCS'
  ORDER BY s.updated_at DESC
  LIMIT 1;
  
  -- If no RCS history found, return unknown
  IF NOT FOUND THEN
    RETURN QUERY SELECT false, 'UNKNOWN'::text, NULL::integer;
  END IF;
END;
$$;

-- Grant execute permissions on helper functions
GRANT EXECUTE ON FUNCTION get_active_session(text) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION upsert_sms_session(text, text, text, boolean, integer) TO service_role;
GRANT EXECUTE ON FUNCTION cleanup_expired_sessions() TO service_role;
GRANT EXECUTE ON FUNCTION update_channel_type(text, text) TO service_role;
GRANT EXECUTE ON FUNCTION check_rcs_capability(text) TO service_role;

-- Create a scheduled job to clean up expired sessions (if using pg_cron)
-- This is optional and requires pg_cron extension
-- SELECT cron.schedule('cleanup-expired-sessions', '0 2 * * *', 'SELECT cleanup_expired_sessions();');

-- Add comment for documentation
COMMENT ON TABLE sms_sessions IS 'Stores RCS-enabled SMS authentication sessions with channel tracking and security controls';
COMMENT ON COLUMN sms_sessions.phone_number IS 'Phone number in E.164 format (e.g., +1234567890)';
COMMENT ON COLUMN sms_sessions.auth_method IS 'Authentication method used: magic_link or otp';
COMMENT ON COLUMN sms_sessions.session_token IS 'Supabase access token (stored securely, never sent via SMS)';
COMMENT ON COLUMN sms_sessions.channel_type IS 'Message channel used: RCS, SMS, or UNKNOWN';
COMMENT ON COLUMN sms_sessions.channel_downgrade_detected IS 'True if session started with RCS but downgraded to SMS';
COMMENT ON COLUMN sms_sessions.rcs_required IS 'Whether this session requires RCS for security';
COMMENT ON COLUMN sms_sessions.session_duration_days IS 'How long the session remains valid in days';
COMMENT ON COLUMN sms_sessions.metadata IS 'Additional session context (e.g., device info, location, org settings)';