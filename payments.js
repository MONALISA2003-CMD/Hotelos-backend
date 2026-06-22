// payments.js — Real Stripe integration.
// Uses Stripe Checkout (hosted payment page) rather than custom card forms — this means
// HotelOS Pro itself never touches raw card numbers, which keeps PCI compliance scope minimal.
// Fulfillment happens via webhook (checkout.session.completed), NOT the success redirect,
// because a guest closing their browser after paying shouldn't mean the booking never gets marked paid.

const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;
const APP_URL = process.env.APP_URL || 'http://localhost:3000';

let stripe = null;
if (STRIPE_SECRET_KEY) {
  stripe = require('stripe')(STRIPE_SECRET_KEY, { apiVersion: '2024-06-20' });
} else {
  console.warn('⚠️  STRIPE_SECRET_KEY not set — payment endpoints will return a clear error instead of crashing. Set it in Railway variables to enable real payments.');
}

const isConfigured = () => !!stripe;

// Creates a hosted Stripe Checkout session for a booking. Returns a URL the frontend redirects to.
async function createCheckoutSession({ bookingId, amount, currency = 'usd', guestEmail, description }) {
  if (!stripe) throw new Error('Payments are not configured on this server yet (missing STRIPE_SECRET_KEY).');

  // Stripe expects the smallest currency unit (cents for USD). UGX has no minor unit in Stripe's
  // supported list in the same way, so amounts here are illustrative — in production you'd convert
  // the hotel's local currency total into a Stripe-supported currency at checkout time.
  const unitAmount = Math.round(amount * 100);

  const session = await stripe.checkout.sessions.create({
    mode: 'payment',
    payment_method_types: ['card'],
    customer_email: guestEmail || undefined,
    line_items: [{
      price_data: {
        currency,
        product_data: { name: description || `Hotel Booking ${bookingId}` },
        unit_amount: unitAmount
      },
      quantity: 1
    }],
    metadata: { bookingId }, // this is how the webhook knows which booking to mark paid
    success_url: `${APP_URL}/payment-success?booking=${bookingId}`,
    cancel_url: `${APP_URL}/payment-cancelled?booking=${bookingId}`,
    expires_at: Math.floor(Date.now() / 1000) + 30 * 60 // 30 minute expiry
  });

  return { url: session.url, sessionId: session.id };
}

// Stripe webhook handler. Mounted with express.raw() body parsing (see server.js) —
// the signature check fails silently if the body has been JSON-parsed first.
function constructWebhookEvent(rawBody, signature) {
  if (!stripe || !STRIPE_WEBHOOK_SECRET) {
    throw new Error('Webhook not configured (missing STRIPE_SECRET_KEY or STRIPE_WEBHOOK_SECRET)');
  }
  return stripe.webhooks.constructEvent(rawBody, signature, STRIPE_WEBHOOK_SECRET);
}

module.exports = { isConfigured, createCheckoutSession, constructWebhookEvent };
