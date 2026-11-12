const express = require('express');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const ROOT_DIR = __dirname;
const UPLOADS_DIR = path.join(ROOT_DIR, 'uploads', 'categories');
try {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
} catch (_) {}

// Load environment variables from .env if present
try {
  const envPath = path.join(ROOT_DIR, '.env');
  if (fs.existsSync(envPath)) {
    const envLines = fs.readFileSync(envPath, 'utf8').split('\n');
    for (const line of envLines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const eq = trimmed.indexOf('=');
      if (eq > 0) {
        const k = trimmed.slice(0, eq).trim();
        const v = trimmed.slice(eq + 1).trim().replace(/^['"]|['"]$/g, '');
        if (!process.env[k]) process.env[k] = v;
      }
    }
  }
} catch (_) {}

// Security Hardening: Disable Express fingerprinting
app.disable('x-powered-by');

// Security Hardening: HTTP Security Headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// Security Hardening: Rate limiter to block DoS and brute-force flooding
const requestCounts = new Map();
function apiRateLimiter(limit = 60, windowMs = 60000) {
  return (req, res, next) => {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
    const now = Date.now();
    const clientData = requestCounts.get(ip) || { count: 0, resetTime: now + windowMs };
    if (now > clientData.resetTime) {
      clientData.count = 1;
      clientData.resetTime = now + windowMs;
    } else {
      clientData.count++;
    }
    requestCounts.set(ip, clientData);
    if (clientData.count > limit) {
      return res.status(429).json({ error: 'Too many requests, please slow down.' });
    }
    next();
  };
}

// Memory cleanup for rate limiter every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [ip, data] of requestCounts.entries()) {
    if (now > data.resetTime) requestCounts.delete(ip);
  }
}, 300000);

app.use(express.json({ limit: '15mb' }));

app.get('/favicon.ico', (req, res) => {
  res.sendFile(path.join(ROOT_DIR, 'favicon.ico'));
});

app.get('/sw.js', (req, res) => {
  res.setHeader('Content-Type', 'application/javascript');
  res.setHeader('Service-Worker-Allowed', '/');
  res.sendFile(path.join(ROOT_DIR, 'sw.js'));
});

// Helper: AWS Signature V4 for Cloudflare R2 S3-Compatible API
function signR2Request({ method, accountId, accessKeyId, secretAccessKey, bucket, objectKey, contentType, bodyBuffer }) {
  const host = `${accountId}.r2.cloudflarestorage.com`;
  const region = 'auto';
  const service = 's3';
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
  const dateStamp = amzDate.slice(0, 8);

  const encodedKey = objectKey.split('/').map( encodeURIComponent ).join('/');
  const canonicalUri = `/${bucket}/${encodedKey}`;
  const payloadHash = crypto.createHash('sha256').update(bodyBuffer || Buffer.alloc(0)).digest('hex');

  const headers = {
    host,
    'x-amz-content-sha256': payloadHash,
    'x-amz-date': amzDate
  };
  if (contentType && method === 'PUT') {
    headers['content-type'] = contentType;
  }

  const sortedHeaderKeys = Object.keys(headers).sort();
  const canonicalHeaders = sortedHeaderKeys.map(k => `${k}:${headers[k]}\n`).join('');
  const signedHeaders = sortedHeaderKeys.join(';');

  const canonicalRequest = [
    method,
    canonicalUri,
    '',
    canonicalHeaders,
    signedHeaders,
    payloadHash
  ].join('\n');

  const algorithm = 'AWS4-HMAC-SHA256';
  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = [
    algorithm,
    amzDate,
    credentialScope,
    crypto.createHash('sha256').update(canonicalRequest).digest('hex')
  ].join('\n');

  const kDate = crypto.createHmac('sha256', 'AWS4' + secretAccessKey).update(dateStamp).digest();
  const kRegion = crypto.createHmac('sha256', kDate).update(region).digest();
  const kService = crypto.createHmac('sha256', kRegion).update(service).digest();
  const kSigning = crypto.createHmac('sha256', kService).update('aws4_request').digest();
  const signature = crypto.createHmac('sha256', kSigning).update(stringToSign).digest('hex');

  const authorization = `${algorithm} Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

  return {
    url: `https://${host}${canonicalUri}`,
    headers: {
      ...headers,
      Authorization: authorization
    }
  };
}

// Helper: Get R2 credentials from environment variables (never hardcode secret keys in source)
function getR2Credentials(tenantId) {
  const isAltaqwa = !tenantId || String(tenantId).toLowerCase().includes('altaqwa') || String(tenantId) === 'default';
  if (isAltaqwa) {
    return {
      accountId: process.env.R2_ACCOUNT_ID || '',
      accessKeyId: process.env.R2_ACCESS_KEY_ID || '',
      secretAccessKey: process.env.R2_SECRET_ACCESS_KEY || '',
      bucket: process.env.ALTAQWA_R2_BUCKET_NAME || 'altaqwa-images',
      publicBaseUrl: (process.env.ALTAQWA_R2_PUBLIC_URL || 'https://cdn.altaqwafortrading.com').replace(/\/+$/, ''),
      isAltaqwa: true
    };
  }
  const envBucket = process.env.SAHALA_R2_BUCKET_NAME || process.env.R2_BUCKET_NAME || '';
  const envPublicUrl = process.env.SAHALA_R2_PUBLIC_URL || process.env.R2_PUBLIC_URL || '';
  return {
    accountId: process.env.R2_ACCOUNT_ID || '',
    accessKeyId: process.env.R2_ACCESS_KEY_ID || '',
    secretAccessKey: process.env.R2_SECRET_ACCESS_KEY || '',
    bucket: (envBucket && envBucket !== 'altaqwa-images') ? envBucket : 'sahala-images',
    publicBaseUrl: ((envPublicUrl && !envPublicUrl.includes('altaqwafortrading.com')) ? envPublicUrl : 'https://cdn.sahalacompany.com').replace(/\/+$/, ''),
    isAltaqwa: false
  };
}

const SUPABASE_URL = process.env.SUPABASE_URL || 'https://vjntfjbzjdzdqsdbwprc.supabase.co';
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InZqbnRmamJ6amR6ZHFzZGJ3cHJjIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODczMzQ1NTgsImV4cCI6MjEwMjkxMDU1OH0.6c2f0vRaMEacTSC-e3E1bh_b2r0hhiRQpLImED4yz9I';

// Security Hardening: Verify that the authenticated user owns the target tenant_id
async function verifyTenantOwnership(token, userEmail, tenantId) {
  if (!tenantId || !userEmail) return false;
  try {
    const cleanTenant = String(tenantId).trim();
    const url = `${SUPABASE_URL}/rest/v1/tenants?tenant_id=eq.${encodeURIComponent(cleanTenant)}&select=tenant_id,owner_email,status,expiry_date`;
    const res = await fetch(url, {
      headers: {
        'apikey': SUPABASE_ANON_KEY,
        'Authorization': `Bearer ${token}`
      }
    });
    if (!res.ok) return false;
    const rows = await res.json();
    if (!Array.isArray(rows) || rows.length === 0) return false;
    const row = rows[0];
    const ownerEmail = String(row.owner_email || '').trim().toLowerCase();
    const status = String(row.status || 'active').trim().toLowerCase();
    if (['suspended', 'disabled', 'expired', 'معلق', 'محظور', 'منتهي'].includes(status)) return false;
    if (row.expiry_date && new Date(row.expiry_date) < new Date()) return false;
    return ownerEmail === String(userEmail).trim().toLowerCase();
  } catch (_) {
    return false;
  }
}

// Security Hardening: Verify Supabase Auth JWT on sensitive server mutations
async function requireAdminAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization || '';
    if (!authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Unauthorized: Missing authentication token' });
    }
    const token = authHeader.slice(7).trim();
    if (!token) {
      return res.status(401).json({ error: 'Unauthorized: Empty authentication token' });
    }
    const verifyRes = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
      headers: {
        'apikey': SUPABASE_ANON_KEY,
        'Authorization': `Bearer ${token}`
      }
    });
    if (!verifyRes.ok) {
      return res.status(401).json({ error: 'Unauthorized: Invalid or expired session token' });
    }
    const userData = await verifyRes.json();
    if (!userData || !userData.email) {
      return res.status(401).json({ error: 'Unauthorized: User identity could not be verified' });
    }
    req.adminUser = userData;
    req.adminToken = token;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Unauthorized: Authentication verification failed' });
  }
}

// Upload compressed 50% WebP image to Cloudflare R2
app.post('/api/r2/upload', apiRateLimiter(60), requireAdminAuth, async (req, res) => {
  try {
    const { base64Data, fileName, tenantId, clientDomain, contentType = 'image/webp' } = req.body || {};
    if (!base64Data || !fileName) {
      return res.status(400).json({ error: 'Missing base64Data or fileName' });
    }

    // Security Hardening: Validate image file extension (disallow .svg to prevent stored XSS)
    const ext = path.extname(String(fileName)).toLowerCase();
    const allowedExts = ['.webp', '.png', '.jpg', '.jpeg', '.gif'];
    if (!allowedExts.includes(ext)) {
      return res.status(400).json({ error: 'Security alert: Only valid raster image extensions are permitted.' });
    }

    const cleanTenant = String(tenantId || 'default').replace(/[^a-zA-Z0-9_-]/g, '_');
    const cleanDomain = String(clientDomain || cleanTenant).replace(/^https?:\/\//i, '').replace(/[^a-zA-Z0-9._-]/g, '_');
    const safeFileName = String(fileName).replace(/(\.\.|\/|\\|\0)/g, '').replace(/[^a-zA-Z0-9._-]/g, '_');

    // Security Hardening: Verify the authenticated user owns this tenantId
    if (tenantId && !(await verifyTenantOwnership(req.adminToken, req.adminUser.email, cleanTenant))) {
      return res.status(403).json({ error: 'Forbidden: You do not own this tenant.' });
    }

    const workerUrl = process.env.R2_WORKER_URL;
    const workerSecret = process.env.R2_WORKER_SECRET || '';
    const r2Config = getR2Credentials(tenantId);
    const { accountId, accessKeyId, secretAccessKey, bucket, publicBaseUrl, isAltaqwa } = r2Config;

    // Ensure tenant isolation in objectKey:
    // - Al-Taqwa keeps flat keys in its dedicated bucket (altaqwa-images)
    // - Other Sahala SaaS customers get a dedicated folder per tenant (tenantId/fileName) inside sahala-images
    const objectKey = isAltaqwa
      ? (safeFileName.includes(cleanTenant) ? safeFileName : `${cleanTenant}-${safeFileName}`)
      : `${cleanTenant}/${safeFileName}`;

    const base64Clean = base64Data.replace(/^data:[^;]+;base64,/, '');
    const bodyBuffer = Buffer.from(base64Clean, 'base64');

    // Option 1: Upload via Cloudflare Worker if configured
    if (workerUrl) {
      const workerRes = await fetch(`${workerUrl.replace(/\/+$/, '')}/${objectKey}`, {
        method: 'PUT',
        headers: {
          'Content-Type': contentType,
          ...(workerSecret ? { 'X-Custom-Auth-Key': workerSecret, Authorization: `Bearer ${workerSecret}` } : {})
        },
        body: bodyBuffer
      });

      if (!workerRes.ok) {
        const errText = await workerRes.text();
        throw new Error(`Cloudflare Worker upload failed: ${errText}`);
      }

      const publicUrl = publicBaseUrl
        ? `${publicBaseUrl}/${objectKey}`
        : `${workerUrl.replace(/\/+$/, '')}/${objectKey}`;

      return res.json({
        success: true,
        provider: 'cloudflare_r2_worker',
        publicUrl,
        r2Key: objectKey,
        clientDomain: cleanDomain
      });
    }

    // Option 2: Upload directly to Cloudflare R2 S3 API if credentials are configured
    if (accountId && accessKeyId && secretAccessKey && bucket) {
      const signed = signR2Request({
        method: 'PUT',
        accountId,
        accessKeyId,
        secretAccessKey,
        bucket,
        objectKey,
        contentType,
        bodyBuffer
      });

      const r2Res = await fetch(signed.url, {
        method: 'PUT',
        headers: signed.headers,
        body: bodyBuffer
      });

      if (!r2Res.ok) {
        const errText = await r2Res.text();
        throw new Error(`Cloudflare R2 S3 upload failed (${r2Res.status}): ${errText}`);
      }

      const publicUrl = publicBaseUrl
        ? `${publicBaseUrl}/${objectKey}`
        : `https://${bucket}.${accountId}.r2.cloudflarestorage.com/${objectKey}`;

      return res.json({
        success: true,
        provider: 'cloudflare_r2_s3',
        publicUrl,
        r2Key: objectKey,
        clientDomain: cleanDomain
      });
    }

    // Option 3: Save compressed 50% WebP image directly in /uploads/categories when R2 env keys are not yet configured
    try {
      fs.mkdirSync(UPLOADS_DIR, { recursive: true });
      const localFilePath = path.join(UPLOADS_DIR, safeFileName);
      fs.writeFileSync(localFilePath, bodyBuffer);
      return res.status(200).json({
        success: true,
        provider: 'local_r2_storage',
        publicUrl: `/uploads/categories/${safeFileName}`,
        r2Key: objectKey,
        clientDomain: cleanDomain
      });
    } catch (fsErr) {
      return res.status(200).json({
        success: false,
        r2Configured: false,
        r2Key: objectKey,
        clientDomain: cleanDomain,
        message: fsErr.message
      });
    }
  } catch (err) {
    console.error('R2 upload error:', err);
    return res.status(500).json({ error: err.message || 'R2 upload error' });
  }
});

// Delete custom client image from Cloudflare R2 (never deletes Image Bank files)
app.post('/api/r2/delete', apiRateLimiter(60), requireAdminAuth, async (req, res) => {
  try {
    const { r2Key, imageUrl, imageSource } = req.body || {};

    // Safety Guard: NEVER delete from R2 if image belongs to the shared Image Bank
    if (imageSource === 'bank') {
      return res.json({
        success: true,
        deletedFromR2: false,
        reason: 'Image belongs to shared Image Bank; skipped R2 deletion.'
      });
    }

    // Clean up local fallback file if stored in /uploads/categories/
    if (imageUrl && String(imageUrl).includes('/uploads/categories/')) {
      try {
        const localFile = String(imageUrl).split('/uploads/categories/').pop().replace(/[^a-zA-Z0-9._-]/g, '_');
        const fullLocalPath = path.join(UPLOADS_DIR, localFile);
        if (fs.existsSync(fullLocalPath)) {
          fs.unlinkSync(fullLocalPath);
        }
      } catch (_) {}
    }

    let targetKey = r2Key || '';
    if (!targetKey && imageUrl) {
      try {
        const parsed = new URL(imageUrl);
        targetKey = parsed.pathname.replace(/^\/+/, '');
      } catch (_) {}
    }

    // Additional Safety Guard: Bank images stored at root numeric WebP (e.g., /1210.webp), placeholder.webp, sahala.webp, sahaladark.webp, or /bank/ are protected
    if (!targetKey || /^(\d+\.webp|placeholder\.webp|sahala\.webp|sahaladark\.webp|sahalalight\.webp|bank\/|shared\/)/i.test(targetKey)) {
      return res.json({
        success: true,
        deletedFromR2: false,
        reason: 'Protected Image Bank path; skipped R2 deletion.'
      });
    }

    // Security Hardening: Verify tenant ownership and ensure targetKey belongs to the tenant
    const reqTenantId = req.body && req.body.tenantId ? String(req.body.tenantId).replace(/[^a-zA-Z0-9_-]/g, '_') : '';
    if (reqTenantId) {
      const isOwner = await verifyTenantOwnership(req.adminToken, req.adminUser.email, reqTenantId);
      if (!isOwner || !targetKey.includes(reqTenantId)) {
        return res.status(403).json({ error: 'Forbidden: Cannot delete an object outside your tenant scope.' });
      }
    }

    const workerUrl = process.env.R2_WORKER_URL;
    const workerSecret = process.env.R2_WORKER_SECRET || '';
    const r2Config = getR2Credentials(req.body && req.body.tenantId);
    const { accountId, accessKeyId, secretAccessKey, bucket } = r2Config;

    if (workerUrl) {
      const workerRes = await fetch(`${workerUrl.replace(/\/+$/, '')}/${targetKey}`, {
        method: 'DELETE',
        headers: {
          ...(workerSecret ? { 'X-Custom-Auth-Key': workerSecret, Authorization: `Bearer ${workerSecret}` } : {})
        }
      });
      return res.json({
        success: workerRes.ok,
        deletedFromR2: workerRes.ok,
        r2Key: targetKey
      });
    }

    if (accountId && accessKeyId && secretAccessKey && bucket) {
      const signed = signR2Request({
        method: 'DELETE',
        accountId,
        accessKeyId,
        secretAccessKey,
        bucket,
        objectKey: targetKey,
        bodyBuffer: Buffer.alloc(0)
      });

      const r2Res = await fetch(signed.url, {
        method: 'DELETE',
        headers: signed.headers
      });

      return res.json({
        success: r2Res.ok,
        deletedFromR2: r2Res.ok,
        r2Key: targetKey
      });
    }

    return res.json({
      success: true,
      deletedFromR2: true,
      r2Configured: false,
      r2Key: targetKey
    });
  } catch (err) {
    console.error('R2 delete error:', err);
    return res.status(500).json({ error: err.message || 'R2 delete error' });
  }
});

// Root and index routes serve dashboard.html with strict no-cache headers so F5 always gets latest HTML
// Smart Multi-Language Web App Manifest
app.get(['/manifest.json', '/manifest-ar.json', '/manifest-en.json'], (req, res) => {
  res.setHeader('Content-Type', 'application/manifest+json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');

  const queryLang = (req.query.lang || '').toLowerCase();
  const acceptLang = (req.headers['accept-language'] || '').toLowerCase();
  const isEn = req.path.includes('-en') || queryLang === 'en' || (!queryLang && acceptLang.startsWith('en'));

  const manifest = {
    id: '/',
    name: isEn ? 'Sahala Platform' : 'منصة سهالة',
    short_name: isEn ? 'Sahala Platform' : 'منصة سهالة',
    start_url: '/dashboard.html',
    scope: '/',
    display: 'standalone',
    orientation: 'any',
    background_color: '#1b002c',
    theme_color: '#1b002c',
    lang: isEn ? 'en' : 'ar',
    dir: isEn ? 'ltr' : 'rtl',
    categories: ['business', 'productivity', 'utilities'],
    icons: [
      {
        src: '/icon-192.png?v=7',
        sizes: '192x192',
        type: 'image/png',
        purpose: 'any'
      },
      {
        src: '/icon-512.png?v=7',
        sizes: '512x512',
        type: 'image/png',
        purpose: 'any'
      },
      {
        src: '/icon-maskable-512.png?v=7',
        sizes: '512x512',
        type: 'image/png',
        purpose: 'maskable'
      }
    ]
  };

  return res.json(manifest);
});

app.get(['/', '/index.html', '/dashboard.html'], (req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.sendFile(path.join(ROOT_DIR, 'dashboard.html'));
});

app.get(['/privacy', '/privacy.html'], (req, res) => {
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.sendFile(path.join(ROOT_DIR, 'privacy.html'));
});

app.get(['/help', '/help.html'], (req, res) => {
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.sendFile(path.join(ROOT_DIR, 'help.html'));
});

// Security Hardening: Block access to sensitive server files, configs, and SQL scripts
app.use((req, res, next) => {
  const reqPath = decodeURIComponent(req.path || '').toLowerCase();
  const blockedPatterns = [
    /^\/server\.(js|ts)$/,
    /^\/package(-lock)?\.json$/,
    /^\/tsconfig\.json$/,
    /^\/metadata\.json$/,
    /^\/_headers$/,
    /^\/functions(\/|$)/,
    /\.sql$/,
    /\.env/,
    /^\/node_modules(\/|$)/,
    /^\/\.git(\/|$)/
  ];
  if (blockedPatterns.some(pattern => pattern.test(reqPath))) {
    return res.status(403).json({ error: 'Access denied' });
  }
  next();
});

// Serve static assets from root directory with dotfiles denied and instant revalidation on HTML/JS/CSS
app.use(express.static(ROOT_DIR, {
  dotfiles: 'deny',
  setHeaders: (res, filePath) => {
    if (/\.(html|js|css|json)$/i.test(filePath)) {
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
    }
  }
}));

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on http://0.0.0.0:${PORT}`);
});
