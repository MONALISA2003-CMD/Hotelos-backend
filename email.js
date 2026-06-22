// email.js — Real transactional email via Resend (resend.com).
// Free tier: 3,000 emails/month, 100/day — genuinely free, not a trial, plenty for a single property.
// If RESEND_API_KEY isn't set, this degrades gracefully to logging instead of throwing,
// so the rest of the app keeps working even before you've set up an email domain.

const RESEND_API_KEY = process.env.RESEND_API_KEY;
const FROM_EMAIL = process.env.FROM_EMAIL || 'HotelOS Pro <onboarding@resend.dev>'; // resend.dev works without domain verification for testing

let resend = null;
if (RESEND_API_KEY) {
  const { Resend } = require('resend');
  resend = new Resend(RESEND_API_KEY);
} else {
  console.warn('⚠️  RESEND_API_KEY not set — emails will be logged to console instead of sent. Set RESEND_API_KEY in Railway variables to enable real email.');
}

async function send({ to, subject, html }) {
  if (!to) return { skipped: true, reason: 'no recipient email on file' };
  if (!resend) {
    console.log(`[EMAIL-SIMULATED] To: ${to} | Subject: ${subject}`);
    return { skipped: true, reason: 'RESEND_API_KEY not configured' };
  }
  try {
    const result = await resend.emails.send({ from: FROM_EMAIL, to, subject, html });
    return { sent: true, id: result?.data?.id };
  } catch (e) {
    console.error('Email send failed:', e.message);
    return { sent: false, error: e.message };
  }
}

function money(n) {
  return 'UGX ' + Number(n || 0).toLocaleString();
}

async function sendBookingConfirmation({ guestEmail, guestName, bookingId, roomNumber, roomType, checkin, checkout, total, branchName }) {
  return send({
    to: guestEmail,
    subject: `Booking Confirmed — ${branchName} (${bookingId})`,
    html: `
      <div style="font-family:sans-serif;max-width:560px;margin:0 auto;color:#1a1a1a">
        <h2 style="color:#4f8ef7">Booking Confirmed</h2>
        <p>Dear ${guestName},</p>
        <p>Your reservation at <strong>${branchName}</strong> is confirmed. Details below:</p>
        <table style="width:100%;border-collapse:collapse;margin:16px 0">
          <tr><td style="padding:8px;color:#666">Booking ID</td><td style="padding:8px;font-weight:600">${bookingId}</td></tr>
          <tr style="background:#f5f5f5"><td style="padding:8px;color:#666">Room</td><td style="padding:8px;font-weight:600">${roomNumber} (${roomType})</td></tr>
          <tr><td style="padding:8px;color:#666">Check-in</td><td style="padding:8px;font-weight:600">${checkin}</td></tr>
          <tr style="background:#f5f5f5"><td style="padding:8px;color:#666">Check-out</td><td style="padding:8px;font-weight:600">${checkout}</td></tr>
          <tr><td style="padding:8px;color:#666">Total</td><td style="padding:8px;font-weight:700;color:#e8b84b">${money(total)}</td></tr>
        </table>
        <p style="color:#666;font-size:13px">We look forward to welcoming you. If you need to make changes, please contact the front desk.</p>
        <hr style="border:none;border-top:1px solid #eee;margin:24px 0">
        <p style="color:#999;font-size:11px">Powered by Monalisa Tech Solutions · kabuusumonalisa@gmail.com · +256703953711</p>
      </div>`
  });
}

async function sendPaymentReceipt({ guestEmail, guestName, bookingId, amount, method, branchName }) {
  return send({
    to: guestEmail,
    subject: `Payment Receipt — ${branchName} (${bookingId})`,
    html: `
      <div style="font-family:sans-serif;max-width:560px;margin:0 auto;color:#1a1a1a">
        <h2 style="color:#2dd4a0">Payment Received</h2>
        <p>Dear ${guestName},</p>
        <p>We've received your payment of <strong style="color:#e8b84b">${money(amount)}</strong> via ${method} for booking ${bookingId}.</p>
        <p style="color:#666;font-size:13px">Thank you for choosing ${branchName}.</p>
        <hr style="border:none;border-top:1px solid #eee;margin:24px 0">
        <p style="color:#999;font-size:11px">Powered by Monalisa Tech Solutions · kabuusumonalisa@gmail.com · +256703953711</p>
      </div>`
  });
}

async function sendPasswordChangedAlert({ userEmail, userName }) {
  if (!userEmail) return { skipped: true };
  return send({
    to: userEmail,
    subject: 'Your HotelOS Pro password was changed',
    html: `
      <div style="font-family:sans-serif;max-width:560px;margin:0 auto;color:#1a1a1a">
        <h2 style="color:#f05c6e">Password Changed</h2>
        <p>Hi ${userName},</p>
        <p>This confirms your HotelOS Pro password was just changed. If this wasn't you, contact your administrator immediately.</p>
      </div>`
  });
}

module.exports = { send, sendBookingConfirmation, sendPaymentReceipt, sendPasswordChangedAlert };
