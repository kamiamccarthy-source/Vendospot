
'use strict';

require('dotenv').config();

const express = require('express');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const crypto = require('crypto');

const app = express();

const PORT = process.env.PORT || 3000;
const APP_URL = (process.env.APP_URL || '').replace(/\/$/, '');
const JWT_SECRET = process.env.JWT_SECRET;
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

const PRICE_PER_PRODUCT = 500;
const MIN_PRODUCTS = 5;
const MAX_PRODUCTS = 100;
const MIN_CUSTOMER_PASSWORD_LENGTH = 6;

const PAYMENT_MODE = PAYSTACK_SECRET_KEY?.startsWith('sk_live_')
  ? 'live'
  : PAYSTACK_SECRET_KEY?.startsWith('sk_test_')
    ? 'test'
    : 'unknown';

if (!process.env.DATABASE_URL) {
  throw new Error('DATABASE_URL is missing.');
}

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error('JWT_SECRET must contain at least 32 characters.');
}

if (!PAYSTACK_SECRET_KEY) {
  console.warn('WARNING: PAYSTACK_SECRET_KEY is not configured.');
}

if (!ADMIN_USERNAME || !ADMIN_PASSWORD || ADMIN_PASSWORD.length < 12) {
  throw new Error('Set ADMIN_USERNAME and an ADMIN_PASSWORD of at least 12 characters.');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === 'false'
    ? false
    : { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", 'https://js.paystack.co'],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https:'],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'", 'https://api.paystack.co'],
      frameSrc: ['https://checkout.paystack.com'],
      upgradeInsecureRequests: null
    }
  }
}));

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

app.use('/api', rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: 'draft-7',
  legacyHeaders: false
}));

app.use(express.static(path.join(__dirname, 'public')));

function clean(value, max = 500) {
  return String(value ?? '').trim().slice(0, max);
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function createToken(payload, expiresIn = '7d') {
  return jwt.sign(payload, JWT_SECRET, { expiresIn });
}

function authenticate(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';

  if (!token) {
    return res.status(401).json({ error: 'Please log in.' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    if (decoded.role !== 'seller') {
      return res.status(403).json({ error: 'Seller access required.' });
    }

    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({
      error: 'Your session has expired. Please log in again.'
    });
  }
}

function requireAdmin(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';

  if (!token) {
    return res.status(401).json({ error: 'Admin login required.' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    if (decoded.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required.' });
    }

    req.admin = decoded;
    next();
  } catch {
    return res.status(401).json({ error: 'Admin session expired.' });
  }
}

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      name VARCHAR(150) NOT NULL,
      email VARCHAR(255) NOT NULL UNIQUE,
      phone VARCHAR(30),
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS payments (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id),
      reference VARCHAR(100) NOT NULL UNIQUE,
      amount_kobo BIGINT NOT NULL,
      product_count INTEGER NOT NULL,
      email VARCHAR(255) NOT NULL,
      status VARCHAR(30) NOT NULL DEFAULT 'pending',
      used BOOLEAN NOT NULL DEFAULT FALSE,
      paid_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    ALTER TABLE payments
      ADD COLUMN IF NOT EXISTS payment_mode VARCHAR(20) NOT NULL DEFAULT 'unknown';

    CREATE TABLE IF NOT EXISTS products (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id),
      payment_reference VARCHAR(100) NOT NULL REFERENCES payments(reference),
      title VARCHAR(200) NOT NULL,
      description TEXT,
      category VARCHAR(100),
      price NUMERIC(14,2),
      image_url TEXT,
      product_url TEXT,
      whatsapp VARCHAR(40),
      location VARCHAR(150),
      status VARCHAR(30) NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS products_status_idx ON products(status);
    CREATE INDEX IF NOT EXISTS products_user_idx ON products(user_id);
    CREATE INDEX IF NOT EXISTS payments_user_idx ON payments(user_id);
    CREATE INDEX IF NOT EXISTS payments_mode_status_idx
      ON payments(payment_mode, status);

    CREATE TABLE IF NOT EXISTS admin_wallet_settings (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      bank_name VARCHAR(120) NOT NULL,
      account_number VARCHAR(10) NOT NULL,
      account_name VARCHAR(150) NOT NULL,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS admin_withdrawals (
      id BIGSERIAL PRIMARY KEY,
      amount_kobo BIGINT NOT NULL CHECK (amount_kobo > 0),
      bank_name VARCHAR(120) NOT NULL,
      account_number VARCHAR(10) NOT NULL,
      account_name VARCHAR(150) NOT NULL,
      status VARCHAR(30) NOT NULL DEFAULT 'pending',
      transfer_reference VARCHAR(200),
      notes TEXT,
      requested_at TIMESTAMPTZ DEFAULT NOW(),
      processed_at TIMESTAMPTZ
    );

    CREATE INDEX IF NOT EXISTS admin_withdrawals_status_idx
      ON admin_withdrawals(status);
  `);

  console.log('VendoSpot database initialized.');
}

async function paystackRequest(endpoint, method = 'GET', body) {
  if (!PAYSTACK_SECRET_KEY) {
    throw new Error('Paystack is not configured.');
  }

  const response = await fetch(`https://api.paystack.co${endpoint}`, {
    method,
    headers: {
      Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
      'Content-Type': 'application/json'
    },
    ...(body ? { body: JSON.stringify(body) } : {})
  });

  const result = await response.json();

  if (!response.ok || !result.status) {
    throw new Error(result.message || 'Paystack request failed.');
  }

  return result.data;
}

// ADMIN WALLET BALANCE CALCULATION
// Paid withdrawals remain deducted permanently.
// Pending withdrawals are reserved.
// Rejected withdrawals are released.
function walletAmounts(row) {
  const revenueKobo = Number(row.revenue_kobo || 0);
  const pendingKobo = Number(row.pending_kobo || 0);
  const paidKobo = Number(row.paid_kobo || 0);

  return {
    totalLiveRevenue: revenueKobo / 100,
    pendingWithdrawalAmount: pendingKobo / 100,
    availableBalance: Math.max(
      0,
      revenueKobo - pendingKobo - paidKobo
    ) / 100
  };
}

// HEALTH CHECK
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', service: 'VendoSpot' });
  } catch {
    res.status(503).json({ status: 'database_unavailable' });
  }
});

// SELLER REGISTRATION
app.post('/api/auth/register', async (req, res) => {
  try {
    const name = clean(req.body.name, 150);
    const email = clean(req.body.email, 255).toLowerCase();
    const phone = clean(req.body.phone, 30);
    const password = String(req.body.password || '');

    if (!name || !validEmail(email) ||
        password.length < MIN_CUSTOMER_PASSWORD_LENGTH) {
      return res.status(400).json({
        error: 'Enter your name, a valid email and a password of at least 6 characters.'
      });
    }

    if (password.length > 128) {
      return res.status(400).json({ error: 'Password is too long.' });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users (name, email, phone, password_hash)
       VALUES ($1, $2, $3, $4)
       RETURNING id, name, email, phone, created_at`,
      [name, email, phone || null, passwordHash]
    );

    const user = result.rows[0];
    const token = createToken({ id: String(user.id), role: 'seller' });

    res.status(201).json({ token, user });
  } catch (error) {
    if (error.code === '23505') {
      return res.status(409).json({
        error: 'An account with this email already exists.'
      });
    }

    console.error('Registration error:', error.message);
    res.status(500).json({ error: 'Could not create your account.' });
  }
});

// SELLER LOGIN
app.post('/api/auth/login', async (req, res) => {
  try {
    const email = clean(req.body.email, 255).toLowerCase();
    const password = String(req.body.password || '');

    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );

    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const token = createToken({ id: String(user.id), role: 'seller' });
    delete user.password_hash;

    res.json({ token, user });
  } catch (error) {
    console.error('Login error:', error.message);
    res.status(500).json({ error: 'Login failed.' });
  }
});

// CURRENT SELLER
app.get('/api/auth/me', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, email, phone, created_at FROM users WHERE id = $1',
      [req.user.id]
    );

    if (!result.rows.length) {
      return res.status(404).json({ error: 'Account not found.' });
    }

    res.json({ user: result.rows[0] });
  } catch {
    res.status(500).json({ error: 'Could not load account.' });
  }
});

// PUBLIC MARKETPLACE PRODUCTS
app.get('/api/products', async (req, res) => {
  try {
    const search = clean(req.query.search, 100);
    const category = clean(req.query.category, 100);

    const result = await pool.query(
      `SELECT p.id, p.title, p.description, p.category, p.price,
              p.image_url, p.product_url, p.whatsapp, p.location,
              p.created_at, u.name AS seller_name
       FROM products p
       JOIN users u ON u.id = p.user_id
       WHERE p.status = 'approved'
         AND ($1 = '' OR p.title ILIKE '%' || $1 || '%' OR p.description ILIKE '%' || $1 || '%')
         AND ($2 = '' OR p.category = $2)
       ORDER BY p.created_at DESC
       LIMIT 200`,
      [search, category]
    );

    res.json({ products: result.rows });
  } catch (error) {
    console.error('Marketplace error:', error.message);
    res.status(500).json({ error: 'Could not load marketplace.' });
  }
});

// INITIALIZE PAYSTACK PAYMENT
app.post('/api/payments/initialize', authenticate, async (req, res) => {
  try {
    const productCount = Number(req.body.productCount);

    if (!Number.isInteger(productCount) ||
        productCount < MIN_PRODUCTS ||
        productCount > MAX_PRODUCTS) {
      return res.status(400).json({
        error: `You must advertise between ${MIN_PRODUCTS} and ${MAX_PRODUCTS} products per order.`
      });
    }

    const userResult = await pool.query(
      'SELECT email FROM users WHERE id = $1',
      [req.user.id]
    );

    if (!userResult.rows.length) {
      return res.status(404).json({ error: 'Seller account not found.' });
    }

    const email = userResult.rows[0].email;
    const amountKobo = productCount * PRICE_PER_PRODUCT * 100;
    const reference = `VSP-${crypto.randomUUID()}`;

    await pool.query(
      `INSERT INTO payments
       (user_id, reference, amount_kobo, product_count, email, payment_mode)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [req.user.id, reference, amountKobo, productCount, email, PAYMENT_MODE]
    );

    const payment = await paystackRequest('/transaction/initialize', 'POST', {
      email,
      amount: amountKobo,
      currency: 'NGN',
      reference,
      callback_url: `${APP_URL || `https://${req.get('host')}`}/api/payments/callback`,
      metadata: {
        seller_id: String(req.user.id),
        product_count: productCount,
        custom_fields: [{
          display_name: 'Product advertising',
          variable_name: 'product_advertising',
          value: `${productCount} products`
        }]
      }
    });

    res.json({
      authorization_url: payment.authorization_url,
      reference: payment.reference,
      amount: amountKobo / 100,
      productCount
    });
  } catch (error) {
    console.error('Payment initialization error:', error.message);
    res.status(500).json({
      error: error.message || 'Could not initialize payment.'
    });
  }
});

// VERIFY PAYMENT WITH PAYSTACK
async function verifyPayment(reference, sellerId) {
  const result = await pool.query(
    'SELECT * FROM payments WHERE reference = $1',
    [reference]
  );

  const payment = result.rows[0];

  if (!payment || (sellerId && String(payment.user_id) !== String(sellerId))) {
    throw new Error('Payment reference not found for this account.');
  }

  if (payment.status === 'success') {
    return payment;
  }

  const verified = await paystackRequest(
    `/transaction/verify/${encodeURIComponent(reference)}`
  );

  if (
    verified.reference !== payment.reference ||
    verified.status !== 'success' ||
    verified.currency !== 'NGN' ||
    Number(verified.amount) !== Number(payment.amount_kobo) ||
    String(verified.customer?.email || '').toLowerCase() !== payment.email.toLowerCase()
  ) {
    throw new Error('Payment could not be verified. Please contact support if you were charged.');
  }

  const updated = await pool.query(
    `UPDATE payments
     SET status = 'success', paid_at = NOW()
     WHERE reference = $1 AND status = 'pending'
     RETURNING *`,
    [reference]
  );

  return updated.rows[0] || payment;
}

app.get('/api/payments/verify/:reference', authenticate, async (req, res) => {
  try {
    const reference = clean(req.params.reference, 100);
    const payment = await verifyPayment(reference, req.user.id);

    res.json({
      status: payment.status,
      paid: payment.status === 'success',
      productCount: payment.product_count,
      reference: payment.reference
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// PAYSTACK CALLBACK
app.get('/api/payments/callback', async (req, res) => {
  const reference = clean(req.query.reference, 100);

  if (!reference) {
    return res.redirect('/?payment=missing');
  }

  try {
    await verifyPayment(reference);
    res.redirect(`/?reference=${encodeURIComponent(reference)}`);
  } catch (error) {
    console.error('Payment callback error:', error.message);
    res.redirect(`/?payment=failed&reference=${encodeURIComponent(reference)}`);
  }
});

// SUBMIT PAID PRODUCTS FOR ADMIN REVIEW
app.post('/api/listings', authenticate, async (req, res) => {
  const client = await pool.connect();

  try {
    const reference = clean(req.body.reference, 100);
    const products = req.body.products;

    if (!reference || !Array.isArray(products)) {
      return res.status(400).json({
        error: 'Payment reference and products are required.'
      });
    }

    await client.query('BEGIN');

    const paymentResult = await client.query(
      `SELECT * FROM payments
       WHERE reference = $1 AND user_id = $2
       FOR UPDATE`,
      [reference, req.user.id]
    );

    const payment = paymentResult.rows[0];

    if (!payment || payment.status !== 'success' || payment.used) {
      await client.query('ROLLBACK');
      return res.status(400).json({
        error: 'A valid, unused successful payment is required.'
      });
    }

    if (products.length !== payment.product_count) {
      await client.query('ROLLBACK');
      return res.status(400).json({
        error: `This payment covers exactly ${payment.product_count} products.`
      });
    }

    for (const item of products) {
      const title = clean(item.title, 200);
      const description = clean(item.description, 5000);
      const category = clean(item.category, 100);
      const imageUrl = clean(item.image_url, 2000);
      const productUrl = clean(item.product_url, 2000);
      const whatsapp = clean(item.whatsapp, 40);
      const location = clean(item.location, 150);

      const price = item.price === '' || item.price == null
        ? null
        : Number(item.price);

      if (!title) {
        throw new Error('Every product must have a title.');
      }

      if (price !== null && (!Number.isFinite(price) || price < 0)) {
        throw new Error('Enter a valid product price.');
      }

      for (const url of [imageUrl, productUrl]) {
        if (url && !/^https?:\/\//i.test(url)) {
          throw new Error('Product image and product links must use valid HTTP or HTTPS URLs.');
        }
      }

      await client.query(
        `INSERT INTO products
         (user_id, payment_reference, title, description, category,
          price, image_url, product_url, whatsapp, location)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
        [
          req.user.id, reference, title, description, category,
          price, imageUrl, productUrl, whatsapp, location
        ]
      );
    }

    await client.query(
      'UPDATE payments SET used = TRUE WHERE reference = $1',
      [reference]
    );

    await client.query('COMMIT');

    res.status(201).json({
      success: true,
      message: 'Your products have been submitted for admin review.'
    });
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('Listing submission error:', error.message);
    res.status(400).json({
      error: error.message || 'Could not submit products.'
    });
  } finally {
    client.release();
  }
});

// SELLER'S OWN PRODUCTS
app.get('/api/seller/listings', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, title, description, category, price, image_url,
              product_url, whatsapp, location, status, created_at
       FROM products
       WHERE user_id = $1
       ORDER BY created_at DESC`,
      [req.user.id]
    );

    res.json({ products: result.rows });
  } catch {
    res.status(500).json({ error: 'Could not load your products.' });
  }
});

// ADMIN LOGIN
app.post('/api/admin/login', rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false
}), async (req, res) => {
  const username = clean(req.body.username, 100);
  const password = String(req.body.password || '');

  const usernameMatches = username === ADMIN_USERNAME;
  const expected = Buffer.from(ADMIN_PASSWORD);
  const supplied = Buffer.from(password);

  const passwordValid = expected.length === supplied.length &&
    crypto.timingSafeEqual(expected, supplied);

  if (!usernameMatches || !passwordValid) {
    return res.status(401).json({
      error: 'Invalid admin username or password.'
    });
  }

  const token = createToken(
    { role: 'admin', username: ADMIN_USERNAME },
    '8h'
  );

  res.json({ token });
});

// ADMIN OVERVIEW
app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        (SELECT COUNT(*) FROM users) AS total_sellers,
        (SELECT COUNT(*) FROM products) AS total_products,
        (SELECT COUNT(*) FROM products WHERE status = 'pending') AS pending_products,
        (SELECT COUNT(*) FROM products WHERE status = 'approved') AS approved_products,
        (SELECT COUNT(*) FROM products WHERE status = 'rejected') AS rejected_products,
        (SELECT COUNT(*) FROM payments WHERE status = 'success') AS successful_payments,
        (SELECT COALESCE(SUM(amount_kobo), 0) / 100
         FROM payments WHERE status = 'success') AS total_revenue
    `);

    const row = result.rows[0];

    res.json({
      totalSellers: Number(row.total_sellers),
      totalProducts: Number(row.total_products),
      pendingProducts: Number(row.pending_products),
      approvedProducts: Number(row.approved_products),
      rejectedProducts: Number(row.rejected_products),
      successfulPayments: Number(row.successful_payments),
      totalRevenue: Number(row.total_revenue),
      stats: row
    });
  } catch (error) {
    console.error('Admin stats error:', error.message);
    res.status(500).json({
      error: 'Could not load dashboard statistics.'
    });
  }
});

// ADMIN PRODUCT MANAGEMENT
app.get('/api/admin/products', requireAdmin, async (req, res) => {
  try {
    const status = clean(req.query.status, 30);
    const allowed = ['pending', 'approved', 'rejected'];

    const result = await pool.query(
      `SELECT p.*, u.name AS seller_name, u.email AS seller_email
       FROM products p
       JOIN users u ON u.id = p.user_id
       WHERE ($1 = '' OR p.status = $1)
       ORDER BY p.created_at DESC
       LIMIT 500`,
      [allowed.includes(status) ? status : '']
    );

    res.json({ products: result.rows });
  } catch (error) {
    console.error('Admin products error:', error.message);
    res.status(500).json({ error: 'Could not load products.' });
  }
});

// APPROVE OR REJECT PRODUCT
app.patch('/api/admin/products/:id/status', requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const status = clean(req.body.status, 30);

    if (!/^\d+$/.test(id) || !['approved', 'rejected'].includes(status)) {
      return res.status(400).json({
        error: 'Invalid product ID or status.'
      });
    }

    const result = await pool.query(
      `UPDATE products
       SET status = $1, updated_at = NOW()
       WHERE id = $2
       RETURNING *`,
      [status, id]
    );

    if (!result.rows.length) {
      return res.status(404).json({ error: 'Product not found.' });
    }

    res.json({
      success: true,
      message: `Product ${status}.`,
      product: result.rows[0]
    });
  } catch (error) {
    console.error('Product status error:', error.message);
    res.status(500).json({
      error: 'Could not update product status.'
    });
  }
});

// ADMIN PAYMENT HISTORY
app.get('/api/admin/payments', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT p.id, p.reference, p.amount_kobo,
              p.amount_kobo / 100.0 AS amount,
              p.product_count, p.email, p.status,
              p.payment_mode, p.used, p.paid_at, p.created_at,
              u.name AS seller_name
       FROM payments p
       JOIN users u ON u.id = p.user_id
       ORDER BY p.created_at DESC
       LIMIT 500`
    );

    res.json({ payments: result.rows });
  } catch (error) {
    console.error('Admin payments error:', error.message);
    res.status(500).json({
      error: 'Could not load payment history.'
    });
  }
});

// ADMIN WALLET SUMMARY AND WITHDRAWAL HISTORY
app.get('/api/admin/wallet', requireAdmin, async (req, res) => {
  try {
    const summaryResult = await pool.query(`
      SELECT
        COALESCE((
          SELECT SUM(amount_kobo)
          FROM payments
          WHERE status = 'success' AND payment_mode = 'live'
        ), 0) AS revenue_kobo,

        COALESCE((
          SELECT SUM(amount_kobo)
          FROM admin_withdrawals
          WHERE status = 'pending'
        ), 0) AS pending_kobo,

        COALESCE((
          SELECT SUM(amount_kobo)
          FROM admin_withdrawals
          WHERE status = 'paid'
        ), 0) AS paid_kobo
    `);

    const bankResult = await pool.query(
      `SELECT bank_name, account_number, account_name
       FROM admin_wallet_settings
       WHERE id = 1`
    );

    const withdrawalsResult = await pool.query(
      `SELECT id, amount_kobo / 100.0 AS amount,
              bank_name, account_number, account_name,
              status, transfer_reference, notes,
              requested_at, processed_at
       FROM admin_withdrawals
       ORDER BY requested_at DESC
       LIMIT 200`
    );

    const amounts = walletAmounts(summaryResult.rows[0]);
    const bank = bankResult.rows[0] || null;

    res.json({
      ...amounts,
      bankAccount: bank ? {
        bankName: bank.bank_name,
        accountNumber: bank.account_number,
        accountName: bank.account_name
      } : null,
      withdrawals: withdrawalsResult.rows
    });
  } catch (error) {
    console.error('Wallet summary error:', error.message);
    res.status(500).json({ error: 'Could not load admin wallet.' });
  }
});

// SAVE OR UPDATE ADMIN RECEIVING BANK ACCOUNT
app.post('/api/admin/wallet/bank-account', requireAdmin, async (req, res) => {
  try {
    const bankName = clean(req.body.bankName, 120);
    const accountNumber = clean(req.body.accountNumber, 10);
    const accountName = clean(req.body.accountName, 150);

    if (!bankName || !/^\d{10}$/.test(accountNumber) || !accountName) {
      return res.status(400).json({
        error: 'Enter a bank name, valid 10-digit account number and account name.'
      });
    }

    await pool.query(
      `INSERT INTO admin_wallet_settings
       (id, bank_name, account_number, account_name, updated_at)
       VALUES (1, $1, $2, $3, NOW())
       ON CONFLICT (id)
       DO UPDATE SET
         bank_name = EXCLUDED.bank_name,
         account_number = EXCLUDED.account_number,
         account_name = EXCLUDED.account_name,
         updated_at = NOW()`,
      [bankName, accountNumber, accountName]
    );

    res.json({
      success: true,
      message: 'Bank account details saved.'
    });
  } catch (error) {
    console.error('Bank account save error:', error.message);
    res.status(500).json({
      error: 'Could not save bank account details.'
    });
  }
});

// CREATE MANUAL WITHDRAWAL REQUEST
app.post('/api/admin/wallet/withdrawals', requireAdmin, async (req, res) => {
  const client = await pool.connect();

  try {
    const amount = Number(req.body.amount);

    if (!Number.isFinite(amount) || amount <= 0 || amount > 1000000000) {
      return res.status(400).json({
        error: 'Enter a valid withdrawal amount.'
      });
    }

    const amountKobo = Math.round(amount * 100);

    if (!Number.isSafeInteger(amountKobo) || amountKobo <= 0) {
      return res.status(400).json({
        error: 'Enter a valid withdrawal amount.'
      });
    }

    await client.query('BEGIN');

    // Serialize withdrawal requests to prevent simultaneous over-withdrawal.
    await client.query(
      'SELECT pg_advisory_xact_lock($1)',
      [78124019]
    );

    const bankResult = await client.query(
      `SELECT bank_name, account_number, account_name
       FROM admin_wallet_settings
       WHERE id = 1`
    );

    const bank = bankResult.rows[0];

    if (!bank) {
      await client.query('ROLLBACK');
      return res.status(400).json({
        error: 'Save your bank account details before requesting a withdrawal.'
      });
    }

    const balanceResult = await client.query(`
      SELECT
        COALESCE((
          SELECT SUM(amount_kobo)
          FROM payments
          WHERE status = 'success' AND payment_mode = 'live'
        ), 0) AS revenue_kobo,

        COALESCE((
          SELECT SUM(amount_kobo)
          FROM admin_withdrawals
          WHERE status = 'pending'
        ), 0) AS pending_kobo,

        COALESCE((
          SELECT SUM(amount_kobo)
          FROM admin_withdrawals
          WHERE status = 'paid'
        ), 0) AS paid_kobo
    `);

    const amounts = walletAmounts(balanceResult.rows[0]);
    const availableKobo = Math.round(amounts.availableBalance * 100);

    if (amountKobo > availableKobo) {
      await client.query('ROLLBACK');
      return res.status(400).json({
        error: 'Insufficient available live revenue for this withdrawal.'
      });
    }

    const inserted = await client.query(
      `INSERT INTO admin_withdrawals
       (amount_kobo, bank_name, account_number, account_name)
       VALUES ($1, $2, $3, $4)
       RETURNING id, amount_kobo / 100.0 AS amount, status, requested_at`,
      [amountKobo, bank.bank_name, bank.account_number, bank.account_name]
    );

    await client.query('COMMIT');

    res.status(201).json({
      success: true,
      message: 'Withdrawal request submitted.',
      withdrawal: inserted.rows[0]
    });
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('Withdrawal request error:', error.message);
    res.status(500).json({
      error: 'Could not submit withdrawal request.'
    });
  } finally {
    client.release();
  }
});

// MARK A WITHDRAWAL AS PAID OR REJECTED
app.patch('/api/admin/wallet/withdrawals/:id', requireAdmin, async (req, res) => {
  const client = await pool.connect();

  try {
    const id = req.params.id;
    const status = clean(req.body.status, 30);
    const transferReference = clean(req.body.transferReference, 200);
    const notes = clean(req.body.notes, 1000);

    if (!/^\d+$/.test(id) || !['paid', 'rejected'].includes(status)) {
      return res.status(400).json({
        error: 'Invalid withdrawal ID or status.'
      });
    }

    if (status === 'paid' && !transferReference) {
      return res.status(400).json({
        error: 'A bank transfer reference is required before marking paid.'
      });
    }

    await client.query('BEGIN');

    await client.query(
      'SELECT pg_advisory_xact_lock($1)',
      [78124019]
    );

    const result = await client.query(
      `UPDATE admin_withdrawals
       SET status = $1,
           transfer_reference = CASE WHEN $1 = 'paid' THEN $2 ELSE transfer_reference END,
           notes = $3,
           processed_at = NOW()
       WHERE id = $4 AND status = 'pending'
       RETURNING id, amount_kobo / 100.0 AS amount, status,
                 transfer_reference, processed_at`,
      [status, transferReference || null, notes || null, id]
    );

    if (!result.rows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({
        error: 'Pending withdrawal not found. It may already have been processed.'
      });
    }

    await client.query('COMMIT');

    res.json({
      success: true,
      message: status === 'paid'
        ? 'Withdrawal marked as paid.'
        : 'Withdrawal rejected.',
      withdrawal: result.rows[0]
    });
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('Withdrawal processing error:', error.message);
    res.status(500).json({
      error: 'Could not process withdrawal.'
    });
  } finally {
    client.release();
  }
});

// FRONTEND ROUTES
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/admin.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// NOT FOUND
app.use('/api', (req, res) => {
  res.status(404).json({ error: 'API endpoint not found.' });
});

app.use((error, req, res, next) => {
  console.error('Server error:', error.message);
  res.status(500).json({
    error: 'An unexpected server error occurred.'
  });
});

// START SERVER
initializeDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`VendoSpot running on port ${PORT}`);
      console.log(`Paystack payment mode: ${PAYMENT_MODE}`);
    });
  })
  .catch(error => {
    console.error('Database initialization failed:', error);
    process.exit(1);
  });
