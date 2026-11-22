
'use strict';

const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;
const isProduction = process.env.NODE_ENV === 'production';

const scrypt = promisify(crypto.scrypt);

const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const APP_URL = (
  process.env.APP_URL ||
  process.env.RENDER_EXTERNAL_URL ||
  `http://localhost:${PORT}`
).replace(/\/$/, '');

if (!DATABASE_URL) {
  console.error('Missing DATABASE_URL environment variable.');
  process.exit(1);
}

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error('JWT_SECRET must contain at least 32 characters.');
  process.exit(1);
}

if (!ADMIN_USERNAME || !ADMIN_PASSWORD || ADMIN_PASSWORD.length < 12) {
  console.error('Set ADMIN_USERNAME and an ADMIN_PASSWORD of at least 12 characters.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: isProduction ? { rejectUnauthorized: false } : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

app.disable('x-powered-by');
app.set('trust proxy', 1);

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  if (isProduction) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
});

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: false, limit: '2mb' }));

// Basic in-memory rate limiting for sensitive endpoints.
const requestCounts = new Map();

function rateLimit(maxRequests, windowMs) {
  return (req, res, next) => {
    const key = `${req.ip}:${req.path}`;
    const now = Date.now();
    let entry = requestCounts.get(key);

    if (!entry || now > entry.resetAt) {
      entry = { count: 0, resetAt: now + windowMs };
    }

    entry.count += 1;
    requestCounts.set(key, entry);

    if (entry.count > maxRequests) {
      return res.status(429).json({
        error: 'Too many requests. Please try again shortly.'
      });
    }

    next();
  };
}

// Passwords are stored using Node's built-in scrypt hashing.
async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = await scrypt(password, salt, 64);
  return `${salt}:${derived.toString('hex')}`;
}

async function verifyPassword(password, storedHash) {
  if (!storedHash || !storedHash.includes(':')) return false;

  const [salt, hash] = storedHash.split(':');
  const expected = Buffer.from(hash, 'hex');
  const actual = await scrypt(password, salt, 64);

  return expected.length === actual.length &&
    crypto.timingSafeEqual(expected, actual);
}

function safeEqual(a, b) {
  const first = Buffer.from(String(a || ''));
  const second = Buffer.from(String(b || ''));

  return first.length === second.length &&
    crypto.timingSafeEqual(first, second);
}

// Signed tokens use HMAC-SHA256.
function createToken(payload, expiresInSeconds) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
    .toString('base64url');

  const body = Buffer.from(JSON.stringify({
    ...payload,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + expiresInSeconds
  })).toString('base64url');

  const unsigned = `${header}.${body}`;
  const signature = crypto
    .createHmac('sha256', JWT_SECRET)
    .update(unsigned)
    .digest('base64url');

  return `${unsigned}.${signature}`;
}

function verifyToken(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const unsigned = `${parts[0]}.${parts[1]}`;
    const expected = crypto
      .createHmac('sha256', JWT_SECRET)
      .update(unsigned)
      .digest('base64url');

    if (!safeEqual(parts[2], expected)) return null;

    const payload = JSON.parse(
      Buffer.from(parts[1], 'base64url').toString('utf8')
    );

    if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

function getBearerToken(req) {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Bearer ')) return null;
  return header.slice(7);
}

function requireSeller(req, res, next) {
  const token = getBearerToken(req);
  const payload = token ? verifyToken(token) : null;

  if (!payload || payload.role !== 'seller' || !payload.userId) {
    return res.status(401).json({ error: 'Please log in to continue.' });
  }

  req.user = payload;
  next();
}

function requireAdmin(req, res, next) {
  const token = getBearerToken(req);
  const payload = token ? verifyToken(token) : null;

  if (!payload || payload.role !== 'admin') {
    return res.status(401).json({ error: 'Admin access required.' });
  }

  req.admin = payload;
  next();
}

function cleanText(value, maxLength = 500) {
  return String(value ?? '').trim().slice(0, maxLength);
}

function validEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value || ''));
}

function publicUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    phone: user.phone,
    created_at: user.created_at
  };
}

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS sellers (
      id BIGSERIAL PRIMARY KEY,
      name VARCHAR(120) NOT NULL,
      email VARCHAR(255) NOT NULL UNIQUE,
      phone VARCHAR(40),
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS payments (
      id BIGSERIAL PRIMARY KEY,
      seller_id BIGINT NOT NULL REFERENCES sellers(id) ON DELETE CASCADE,
      reference VARCHAR(120) NOT NULL UNIQUE,
      product_count INTEGER NOT NULL CHECK (product_count >= 5),
      amount_kobo BIGINT NOT NULL,
      currency VARCHAR(3) NOT NULL DEFAULT 'NGN',
      status VARCHAR(20) NOT NULL DEFAULT 'pending',
      paystack_response JSONB,
      products_created BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      paid_at TIMESTAMPTZ
    );

    CREATE TABLE IF NOT EXISTS products (
      id BIGSERIAL PRIMARY KEY,
      seller_id BIGINT NOT NULL REFERENCES sellers(id) ON DELETE CASCADE,
      payment_reference VARCHAR(120) NOT NULL REFERENCES payments(reference),
      title VARCHAR(180) NOT NULL,
      description TEXT NOT NULL,
      price NUMERIC(14,2) NOT NULL DEFAULT 0,
      category VARCHAR(100),
      image_url TEXT,
      contact VARCHAR(100),
      status VARCHAR(20) NOT NULL DEFAULT 'pending',
      rejection_reason TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      reviewed_at TIMESTAMPTZ
    );

    CREATE INDEX IF NOT EXISTS products_status_idx ON products(status);
    CREATE INDEX IF NOT EXISTS products_seller_idx ON products(seller_id);
    CREATE INDEX IF NOT EXISTS products_created_idx ON products(created_at DESC);
    CREATE INDEX IF NOT EXISTS payments_seller_idx ON payments(seller_id);
    CREATE INDEX IF NOT EXISTS payments_status_idx ON payments(status);
  `);

  console.log('VendoSpot database tables are ready.');
}

async function paystackRequest(endpoint, options = {}) {
  if (!PAYSTACK_SECRET_KEY) {
    throw new Error('Paystack is not configured. Set PAYSTACK_SECRET_KEY.');
  }

  const response = await fetch(`https://api.paystack.co${endpoint}`, {
    ...options,
    headers: {
      Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
      'Content-Type': 'application/json',
      ...(options.headers || {})
    }
  });

  const result = await response.json();

  if (!response.ok || !result.status) {
    throw new Error(result.message || 'Paystack request failed.');
  }

  return result.data;
}

async function verifyPaystackReference(reference) {
  const data = await paystackRequest(
    `/transaction/verify/${encodeURIComponent(reference)}`
  );

  if (
    data.status !== 'success' ||
    data.currency !== 'NGN' ||
    !data.reference
  ) {
    throw new Error('This payment has not been confirmed as successful.');
  }

  return data;
}

// Health check.
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', service: 'VendoSpot' });
  } catch {
    res.status(503).json({ status: 'error', error: 'Database unavailable.' });
  }
});

// SELLER REGISTRATION.
app.post(
  '/api/auth/register',
  rateLimit(10, 15 * 60 * 1000),
  async (req, res) => {
    try {
      const name = cleanText(req.body.name, 120);
      const email = cleanText(req.body.email, 255).toLowerCase();
      const phone = cleanText(req.body.phone, 40);
      const password = String(req.body.password || '');

      if (!name || !validEmail(email) || password.length < 8) {
        return res.status(400).json({
          error: 'Enter your name, a valid email and a password of at least 8 characters.'
        });
      }

      if (password.length > 200) {
        return res.status(400).json({ error: 'Password is too long.' });
      }

      const passwordHash = await hashPassword(password);

      const result = await pool.query(
        `INSERT INTO sellers (name, email, phone, password_hash)
         VALUES ($1, $2, $3, $4)
         RETURNING id, name, email, phone, created_at`,
        [name, email, phone || null, passwordHash]
      );

      const user = result.rows[0];
      const token = createToken(
        { userId: String(user.id), role: 'seller' },
        7 * 24 * 60 * 60
      );

      res.status(201).json({ token, user: publicUser(user) });
    } catch (error) {
      if (error.code === '23505') {
        return res.status(409).json({
          error: 'An account with this email already exists.'
        });
      }

      console.error('Registration error:', error.message);
      res.status(500).json({ error: 'Could not create your account.' });
    }
  }
);

// SELLER LOGIN.
app.post(
  '/api/auth/login',
  rateLimit(10, 15 * 60 * 1000),
  async (req, res) => {
    try {
      const email = cleanText(req.body.email, 255).toLowerCase();
      const password = String(req.body.password || '');

      const result = await pool.query(
        'SELECT * FROM sellers WHERE email = $1',
        [email]
      );

      const user = result.rows[0];

      if (!user || !(await verifyPassword(password, user.password_hash))) {
        return res.status(401).json({ error: 'Invalid email or password.' });
      }

      const token = createToken(
        { userId: String(user.id), role: 'seller' },
        7 * 24 * 60 * 60
      );

      res.json({ token, user: publicUser(user) });
    } catch (error) {
      console.error('Login error:', error.message);
      res.status(500).json({ error: 'Login could not be completed.' });
    }
  }
);

// CURRENT SELLER.
app.get('/api/auth/me', requireSeller, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, email, phone, created_at
       FROM sellers WHERE id = $1`,
      [req.user.userId]
    );

    if (!result.rows[0]) {
      return res.status(404).json({ error: 'Account not found.' });
    }

    res.json({ user: publicUser(result.rows[0]) });
  } catch (error) {
    res.status(500).json({ error: 'Could not load your account.' });
  }
});

// PUBLIC MARKETPLACE: APPROVED PRODUCTS ONLY.
app.get('/api/products', async (req, res) => {
  try {
    const search = cleanText(req.query.search, 100);
    const category = cleanText(req.query.category, 100);

    const result = await pool.query(
      `SELECT p.id, p.title, p.description, p.price, p.category,
              p.image_url, p.contact, p.created_at, s.name AS seller_name
       FROM products p
       JOIN sellers s ON s.id = p.seller_id
       WHERE p.status = 'approved'
         AND ($1 = '' OR
              p.title ILIKE '%' || $1 || '%' OR
              p.description ILIKE '%' || $1 || '%')
         AND ($2 = '' OR p.category = $2)
       ORDER BY p.created_at DESC
       LIMIT 200`,
      [search, category]
    );

    res.json({ products: result.rows });
  } catch (error) {
    console.error('Marketplace error:', error.message);
    res.status(500).json({ error: 'Could not load marketplace products.' });
  }
});

// INITIALIZE A LISTING PAYMENT.
// ₦500 per product, minimum 5 products.
app.post(
  '/api/payments/initialize',
  requireSeller,
  rateLimit(10, 10 * 60 * 1000),
  async (req, res) => {
    try {
      const productCount = Number(req.body.productCount);

      if (
        !Number.isInteger(productCount) ||
        productCount < 5 ||
        productCount > 100
      ) {
        return res.status(400).json({
          error: 'You must advertise at least 5 products. Maximum order is 100 products.'
        });
      }

      const sellerResult = await pool.query(
        'SELECT id, email FROM sellers WHERE id = $1',
        [req.user.userId]
      );

      const seller = sellerResult.rows[0];
      if (!seller) {
        return res.status(404).json({ error: 'Seller account not found.' });
      }

      const amountKobo = productCount * 500 * 100;
      const reference = `VSP-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`;

      await pool.query(
        `INSERT INTO payments
         (seller_id, reference, product_count, amount_kobo, currency, status)
         VALUES ($1, $2, $3, $4, 'NGN', 'pending')`,
        [seller.id, reference, productCount, amountKobo]
      );

      try {
        const payment = await paystackRequest('/transaction/initialize', {
          method: 'POST',
          body: JSON.stringify({
            email: seller.email,
            amount: amountKobo,
            currency: 'NGN',
            reference,
            callback_url: `${APP_URL}/api/payments/callback`,
            metadata: {
              service: 'VendoSpot product listing',
              seller_id: String(seller.id),
              product_count: productCount,
              price_per_product_naira: 500
            }
          })
        });

        res.json({
          authorization_url: payment.authorization_url,
          reference,
          productCount,
          amount: productCount * 500
        });
      } catch (error) {
        await pool.query(
          `UPDATE payments SET status = 'failed' WHERE reference = $1`,
          [reference]
        );
        throw error;
      }
    } catch (error) {
      console.error('Payment initialization error:', error.message);
      res.status(500).json({
        error: error.message || 'Could not initialize payment.'
      });
    }
  }
);

// PAYSTACK REDIRECT CALLBACK.
// Paystack redirects here after the customer attempts payment.
app.get('/api/payments/callback', async (req, res) => {
  const reference = cleanText(req.query.reference, 120);

  if (!reference) {
    return res.redirect(`${APP_URL}/?payment=missing_reference`);
  }

  try {
    await verifyPaystackReference(reference);
    res.redirect(`${APP_URL}/?reference=${encodeURIComponent(reference)}`);
  } catch (error) {
    console.error('Payment callback verification:', error.message);
    res.redirect(`${APP_URL}/?payment=not_confirmed&reference=${encodeURIComponent(reference)}`);
  }
});

// VERIFY A PAYMENT FOR THE LOGGED-IN SELLER.
app.get(
  '/api/payments/verify/:reference',
  requireSeller,
  async (req, res) => {
    try {
      const reference = cleanText(req.params.reference, 120);

      const paymentResult = await pool.query(
        `SELECT * FROM payments
         WHERE reference = $1 AND seller_id = $2`,
        [reference, req.user.userId]
      );

      const payment = paymentResult.rows[0];

      if (!payment) {
        return res.status(404).json({ error: 'Payment record not found.' });
      }

      if (payment.status === 'success') {
        return res.json({
          status: 'success',
          paid: true,
          productCount: payment.product_count,
          amount: Number(payment.amount_kobo) / 100,
          productsCreated: payment.products_created
        });
      }

      const data = await verifyPaystackReference(reference);

      if (
        Number(data.amount) !== Number(payment.amount_kobo) ||
        data.currency !== payment.currency
      ) {
        return res.status(400).json({
          error: 'The verified payment amount does not match this order.'
        });
      }

      const result = await pool.query(
        `UPDATE payments
         SET status = 'success',
             paid_at = NOW(),
             paystack_response = $1
         WHERE reference = $2 AND seller_id = $3
         RETURNING product_count, amount_kobo, products_created`,
        [JSON.stringify(data), reference, req.user.userId]
      );

      res.json({
        status: 'success',
        paid: true,
        productCount: result.rows[0].product_count,
        amount: Number(result.rows[0].amount_kobo) / 100,
        productsCreated: result.rows[0].products_created
      });
    } catch (error) {
      console.error('Payment verification error:', error.message);
      res.status(400).json({
        error: error.message || 'Payment could not be verified.'
      });
    }
  }
);

// SUBMIT PRODUCTS AFTER PAYMENT.
// A payment can only be used once and only for its exact product count.
app.post('/api/listings', requireSeller, async (req, res) => {
  const client = await pool.connect();

  try {
    const reference = cleanText(req.body.reference, 120);
    const products = req.body.products;

    if (!reference || !Array.isArray(products)) {
      return res.status(400).json({
        error: 'Payment reference and product list are required.'
      });
    }

    if (products.length < 5 || products.length > 100) {
      return res.status(400).json({
        error: 'Submit at least 5 products and no more than 100.'
      });
    }

    // Confirm payment directly with Paystack, not just the browser.
    const paymentResult = await pool.query(
      `SELECT * FROM payments
       WHERE reference = $1 AND seller_id = $2`,
      [reference, req.user.userId]
    );

    const payment = paymentResult.rows[0];

    if (!payment) {
      return res.status(404).json({ error: 'Payment order not found.' });
    }

    if (payment.products_created) {
      return res.status(409).json({
        error: 'Products have already been submitted for this payment.'
      });
    }

    if (products.length !== payment.product_count) {
      return res.status(400).json({
        error: `This payment covers exactly ${payment.product_count} products.`
      });
    }

    const verified = await verifyPaystackReference(reference);

    if (
      Number(verified.amount) !== Number(payment.amount_kobo) ||
      verified.currency !== payment.currency
    ) {
      return res.status(400).json({
        error: 'Payment amount or currency does not match this order.'
      });
    }

    await client.query('BEGIN');

    const locked = await client.query(
      `SELECT * FROM payments
       WHERE reference = $1 AND seller_id = $2
       FOR UPDATE`,
      [reference, req.user.userId]
    );

    const currentPayment = locked.rows[0];

    if (!currentPayment || currentPayment.products_created) {
      await client.query('ROLLBACK');
      return res.status(409).json({
        error: 'This payment has already been used or is unavailable.'
      });
    }

    await client.query(
      `UPDATE payments
       SET status = 'success',
           paid_at = COALESCE(paid_at, NOW()),
           paystack_response = $1
       WHERE reference = $2`,
      [JSON.stringify(verified), reference]
    );

    for (const item of products) {
      const title = cleanText(item.title || item.name, 180);
      const description = cleanText(item.description, 5000);
      const category = cleanText(item.category, 100);
      const imageUrl = cleanText(item.image_url || item.imageUrl, 2000);
      const contact = cleanText(item.contact || item.phone || item.whatsapp, 100);

      const rawPrice = String(item.price ?? '0').replace(/,/g, '');
      const price = Number(rawPrice);

      if (!title || !description || !Number.isFinite(price) || price < 0) {
        throw new Error('Each product needs a title, description and valid price.');
      }

      if (imageUrl && !/^https:\/\/\S+$/i.test(imageUrl)) {
        throw new Error('Product image links must use HTTPS.');
      }

      await client.query(
        `INSERT INTO products
         (seller_id, payment_reference, title, description, price,
          category, image_url, contact, status)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending')`,
        [
          req.user.userId,
          reference,
          title,
          description,
          price,
          category || null,
          imageUrl || null,
          contact || null
        ]
      );
    }

    await client.query(
      `UPDATE payments SET products_created = TRUE WHERE reference = $1`,
      [reference]
    );

    await client.query('COMMIT');

    res.status(201).json({
      success: true,
      message: 'Your products have been submitted for admin review.',
      submitted: products.length,
      status: 'pending'
    });
  } catch (error) {
    try {
      await client.query('ROLLBACK');
    } catch {}

    console.error('Product submission error:', error.message);
    res.status(400).json({
      error: error.message || 'Could not submit your products.'
    });
  } finally {
    client.release();
  }
});

// SELLER'S OWN PRODUCTS.
app.get('/api/seller/listings', requireSeller, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, title, description, price, category, image_url,
              contact, status, rejection_reason, created_at, reviewed_at
       FROM products
       WHERE seller_id = $1
       ORDER BY created_at DESC`,
      [req.user.userId]
    );

    res.json({ products: result.rows, listings: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Could not load your products.' });
  }
});

// ADMIN LOGIN.
app.post(
  '/api/admin/login',
  rateLimit(8, 15 * 60 * 1000),
  async (req, res) => {
    const username = String(req.body.username || '');
    const password = String(req.body.password || '');

    if (
      !safeEqual(username, ADMIN_USERNAME) ||
      !safeEqual(password, ADMIN_PASSWORD)
    ) {
      return res.status(401).json({ error: 'Invalid admin username or password.' });
    }

    const token = createToken({ role: 'admin' }, 8 * 60 * 60);
    res.json({ token });
  }
);

// ADMIN OVERVIEW.
app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        (SELECT COUNT(*) FROM sellers) AS total_sellers,
        (SELECT COUNT(*) FROM products) AS total_products,
        (SELECT COUNT(*) FROM products WHERE status = 'pending') AS pending_products,
        (SELECT COUNT(*) FROM products WHERE status = 'approved') AS approved_products,
        (SELECT COUNT(*) FROM products WHERE status = 'rejected') AS rejected_products,
        (SELECT COUNT(*) FROM payments WHERE status = 'success') AS successful_payments,
        (SELECT COALESCE(SUM(amount_kobo), 0)
         FROM payments WHERE status = 'success') AS total_revenue_kobo
    `);

    const row = result.rows[0];

    res.json({
      ...row,
      totalSellers: Number(row.total_sellers),
      totalProducts: Number(row.total_products),
      pendingProducts: Number(row.pending_products),
      approvedProducts: Number(row.approved_products),
      rejectedProducts: Number(row.rejected_products),
      successfulPayments: Number(row.successful_payments),
      totalRevenue: Number(row.total_revenue_kobo) / 100
    });
  } catch (error) {
    res.status(500).json({ error: 'Could not load admin statistics.' });
  }
});

// ADMIN PRODUCT REVIEW LIST.
app.get('/api/admin/products', requireAdmin, async (req, res) => {
  try {
    const status = cleanText(req.query.status, 20);
    const allowed = ['pending', 'approved', 'rejected'];

    const result = await pool.query(
      `SELECT p.id, p.seller_id, p.payment_reference, p.title,
              p.description, p.price, p.category, p.image_url, p.contact,
              p.status, p.rejection_reason, p.created_at, p.reviewed_at,
              s.name AS seller_name, s.email AS seller_email, s.phone AS seller_phone
       FROM products p
       JOIN sellers s ON s.id = p.seller_id
       WHERE ($1 = '' OR p.status = $1)
       ORDER BY p.created_at DESC
       LIMIT 500`,
      [allowed.includes(status) ? status : '']
    );

    res.json({ products: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Could not load products for review.' });
  }
});

// APPROVE OR REJECT A PRODUCT.
app.patch(
  '/api/admin/products/:id/status',
  requireAdmin,
  async (req, res) => {
    try {
      const id = String(req.params.id);
      const status = cleanText(req.body.status, 20);
      const reason = cleanText(req.body.reason || req.body.rejection_reason, 1000);

      if (!/^\d+$/.test(id) || !['approved', 'rejected'].includes(status)) {
        return res.status(400).json({ error: 'Invalid product or review status.' });
      }

      if (status === 'rejected' && !reason) {
        return res.status(400).json({
          error: 'Please provide a reason for rejecting this product.'
        });
      }

      const result = await pool.query(
        `UPDATE products
         SET status = $1,
             rejection_reason = $2,
             reviewed_at = NOW()
         WHERE id = $3
         RETURNING id, title, status, rejection_reason, reviewed_at`,
        [status, status === 'rejected' ? reason : null, id]
      );

      if (!result.rows[0]) {
        return res.status(404).json({ error: 'Product not found.' });
      }

      res.json({
        success: true,
        message: `Product ${status}.`,
        product: result.rows[0]
      });
    } catch (error) {
      res.status(500).json({ error: 'Could not update product status.' });
    }
  }
);

// ADMIN PAYMENT HISTORY.
app.get('/api/admin/payments', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT p.id, p.seller_id, p.reference, p.product_count,
              p.amount_kobo, p.currency, p.status, p.products_created,
              p.created_at, p.paid_at,
              s.name AS seller_name, s.email AS seller_email
       FROM payments p
       JOIN sellers s ON s.id = p.seller_id
       ORDER BY p.created_at DESC
       LIMIT 500`
    );

    const payments = result.rows.map(payment => ({
      ...payment,
      amount: Number(payment.amount_kobo) / 100
    }));

    res.json({ payments });
  } catch (error) {
    res.status(500).json({ error: 'Could not load payment history.' });
  }
});

// Serve the customer portal and admin dashboard.
const publicDirectory = path.join(__dirname, 'public');
app.use(express.static(publicDirectory));

app.get('/', (req, res) => {
  res.sendFile(path.join(publicDirectory, 'index.html'));
});

app.get('/admin.html', (req, res) => {
  res.sendFile(path.join(publicDirectory, 'admin.html'));
});

// Unknown API route.
app.use('/api', (req, res) => {
  res.status(404).json({ error: 'API endpoint not found.' });
});

// General error handler.
app.use((error, req, res, next) => {
  console.error('Server error:', error.message);
  if (res.headersSent) return next(error);
  res.status(500).json({ error: 'An unexpected server error occurred.' });
});

async function startServer() {
  try {
    await initializeDatabase();

    app.listen(PORT, '0.0.0.0', () => {
      console.log(`VendoSpot is running on port ${PORT}.`);
    });
  } catch (error) {
    console.error('VendoSpot startup failed:', error);
    process.exit(1);
  }
}

startServer();

