/**
 * SMS Helper Functions
 * Utilities for sending SMS messages via Twilio
 */

const twilio = require('twilio');

// Initialize Twilio client
const twilioClient = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);

/**
 * Send SMS message
 */
async function sendSMS(toNumber, message, options = {}) {
  try {
    // Ensure message doesn't exceed SMS length limits
    const truncatedMessage = truncateMessage(message);
    
    const messageOptions = {
      body: truncatedMessage,
      to: toNumber,
      from: process.env.TWILIO_PHONE_NUMBER,
      ...options
    };

    // Send message
    const result = await twilioClient.messages.create(messageOptions);
    
    console.log(`SMS sent to ${toNumber}: ${result.sid}`);
    return result;
  } catch (error) {
    console.error('SMS send error:', error);
    
    // Handle specific Twilio errors
    if (error.code === 21211) {
      throw new Error('Invalid phone number format');
    } else if (error.code === 21610) {
      throw new Error('Phone number is on the blocklist');
    } else if (error.code === 21408) {
      throw new Error('Permission denied to send to this region');
    }
    
    throw error;
  }
}

/**
 * Send SMS with retry logic
 */
async function sendSMSWithRetry(toNumber, message, maxRetries = 3) {
  let lastError;
  
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await sendSMS(toNumber, message);
    } catch (error) {
      lastError = error;
      console.error(`SMS send attempt ${attempt} failed:`, error.message);
      
      // Don't retry for permanent errors
      if (error.message.includes('Invalid phone number') ||
          error.message.includes('blocklist') ||
          error.message.includes('Permission denied')) {
        throw error;
      }
      
      // Wait before retry (exponential backoff)
      if (attempt < maxRetries) {
        await new Promise(resolve => setTimeout(resolve, 1000 * Math.pow(2, attempt - 1)));
      }
    }
  }
  
  throw lastError;
}

/**
 * Send bulk SMS messages
 */
async function sendBulkSMS(recipients, message) {
  const results = [];
  
  // Process in batches to avoid rate limits
  const batchSize = 10;
  for (let i = 0; i < recipients.length; i += batchSize) {
    const batch = recipients.slice(i, i + batchSize);
    
    const batchPromises = batch.map(async (recipient) => {
      try {
        const result = await sendSMS(recipient.phone, 
          personalizeMessage(message, recipient));
        return { success: true, phone: recipient.phone, messageId: result.sid };
      } catch (error) {
        return { success: false, phone: recipient.phone, error: error.message };
      }
    });
    
    const batchResults = await Promise.allSettled(batchPromises);
    results.push(...batchResults.map(r => r.value || r.reason));
    
    // Rate limit between batches
    if (i + batchSize < recipients.length) {
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  }
  
  return results;
}

/**
 * Validate phone number format
 */
function validatePhoneNumber(phoneNumber) {
  // E.164 format validation
  const e164Regex = /^\+[1-9]\d{1,14}$/;
  
  if (!e164Regex.test(phoneNumber)) {
    // Try to fix common formatting issues
    let cleaned = phoneNumber.replace(/\D/g, '');
    
    // Add US country code if missing
    if (cleaned.length === 10) {
      cleaned = '1' + cleaned;
    }
    
    // Add + prefix
    if (!cleaned.startsWith('+')) {
      cleaned = '+' + cleaned;
    }
    
    // Validate again
    if (!e164Regex.test(cleaned)) {
      return { valid: false, formatted: null };
    }
    
    return { valid: true, formatted: cleaned };
  }
  
  return { valid: true, formatted: phoneNumber };
}

/**
 * Truncate message to SMS limits
 */
function truncateMessage(message, maxLength = 1600) {
  if (message.length <= maxLength) {
    return message;
  }
  
  // Leave room for ellipsis
  const truncated = message.substring(0, maxLength - 3) + '...';
  
  // Try to break at a word boundary
  const lastSpace = truncated.lastIndexOf(' ');
  if (lastSpace > maxLength - 50) {
    return truncated.substring(0, lastSpace) + '...';
  }
  
  return truncated;
}

/**
 * Split long message into multiple SMS
 */
function splitMessage(message, maxLength = 160) {
  if (message.length <= maxLength) {
    return [message];
  }
  
  const parts = [];
  let remaining = message;
  
  while (remaining.length > 0) {
    if (remaining.length <= maxLength) {
      parts.push(remaining);
      break;
    }
    
    // Find a good breaking point
    let breakPoint = maxLength;
    const lastSpace = remaining.lastIndexOf(' ', maxLength);
    if (lastSpace > maxLength - 20) {
      breakPoint = lastSpace;
    }
    
    parts.push(remaining.substring(0, breakPoint));
    remaining = remaining.substring(breakPoint).trim();
  }
  
  // Add part numbers if multiple parts
  if (parts.length > 1) {
    return parts.map((part, index) => 
      `(${index + 1}/${parts.length}) ${part}`
    );
  }
  
  return parts;
}

/**
 * Personalize message with recipient data
 */
function personalizeMessage(template, recipient) {
  let message = template;
  
  // Replace placeholders
  Object.keys(recipient).forEach(key => {
    const placeholder = `{{${key}}}`;
    if (message.includes(placeholder)) {
      message = message.replace(new RegExp(placeholder, 'g'), recipient[key]);
    }
  });
  
  return message;
}

/**
 * Format phone number for display
 */
function formatPhoneForDisplay(phoneNumber) {
  // Remove + and country code for US numbers
  if (phoneNumber.startsWith('+1') && phoneNumber.length === 12) {
    const cleaned = phoneNumber.substring(2);
    return `(${cleaned.substring(0, 3)}) ${cleaned.substring(3, 6)}-${cleaned.substring(6)}`;
  }
  
  return phoneNumber;
}

/**
 * Check if number can receive SMS (using Twilio Lookup API)
 */
async function canReceiveSMS(phoneNumber) {
  try {
    const lookup = await twilioClient.lookups.v1
      .phoneNumbers(phoneNumber)
      .fetch({ type: ['carrier'] });
    
    return {
      valid: true,
      carrier: lookup.carrier,
      type: lookup.carrier?.type,
      canReceiveSMS: lookup.carrier?.type === 'mobile' || 
                     lookup.carrier?.type === 'voip'
    };
  } catch (error) {
    console.error('Phone lookup error:', error);
    return {
      valid: false,
      error: error.message
    };
  }
}

/**
 * Get SMS delivery status
 */
async function getSMSStatus(messageSid) {
  try {
    const message = await twilioClient.messages(messageSid).fetch();
    
    return {
      status: message.status,
      errorCode: message.errorCode,
      errorMessage: message.errorMessage,
      dateCreated: message.dateCreated,
      dateSent: message.dateSent,
      dateUpdated: message.dateUpdated
    };
  } catch (error) {
    console.error('Get SMS status error:', error);
    throw error;
  }
}

module.exports = {
  sendSMS,
  sendSMSWithRetry,
  sendBulkSMS,
  validatePhoneNumber,
  truncateMessage,
  splitMessage,
  personalizeMessage,
  formatPhoneForDisplay,
  canReceiveSMS,
  getSMSStatus
};