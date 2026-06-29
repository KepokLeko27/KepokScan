import express from 'express';
import { GoogleGenAI, Type } from '@google/genai';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());

import dns from 'dns/promises';

// Initialize Gemini API
const apiKey = process.env.GEMINI_API_KEY;
const ai = apiKey ? new GoogleGenAI({
  apiKey,
  httpOptions: {
    headers: {
      'User-Agent': 'aistudio-build',
    }
  }
}) : null;

// Helper to normalize URL
function normalizeUrl(input: string): string {
  let cleaned = input.trim();
  if (!cleaned) return '';
  if (!/^https?:\/\//i.test(cleaned)) {
    cleaned = 'https://' + cleaned;
  }
  return cleaned;
}

interface ExposureItem {
  name: string;
  url: string;
  status: 'secure' | 'warning' | 'danger';
  found: boolean;
  details: string;
  recommendation: string;
}

// Check exposures (exposed .git, robots.txt, sitemap.xml, common admin pages, and directory listing)
async function checkExposures(baseUrl: string): Promise<ExposureItem[]> {
  const results: ExposureItem[] = [];
  try {
    const parsed = new URL(baseUrl);
    const origin = parsed.origin;

    // Helper for quick requests with a short timeout
    const fetchWithTimeout = async (url: string, timeoutMs = 2500): Promise<{ status: number; text: string; ok: boolean }> => {
      const controller = new AbortController();
      const id = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const res = await fetch(url, {
          method: 'GET',
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) security-scanner',
          },
          signal: controller.signal,
        });
        clearTimeout(id);
        const text = await res.text();
        return { status: res.status, text, ok: res.ok };
      } catch (err) {
        clearTimeout(id);
        return { status: 0, text: '', ok: false };
      }
    };

    // 1. Check for exposed .git
    const gitUrl = `${origin}/.git/config`;
    const gitRes = await fetchWithTimeout(gitUrl);
    if (gitRes.ok && (gitRes.text.includes('[core]') || gitRes.text.includes('repositoryformatversion'))) {
      results.push({
        name: '.git Repository Exposure',
        url: gitUrl,
        status: 'danger',
        found: true,
        details: 'Exposed git configuration directory is fully accessible. This allows attackers to reconstruct the entire source code repository, including internal configurations and potentially hardcoded secrets.',
        recommendation: 'Block public web access to the .git directory in your server configuration (e.g. deny all in Nginx/Apache or remove the directory from production).'
      });
    } else {
      results.push({
        name: '.git Repository Exposure',
        url: gitUrl,
        status: 'secure',
        found: false,
        details: 'No exposed .git directory or configurations were detected on the public endpoint.',
        recommendation: 'Maintain strict server controls blocking access to hidden dot-folders (like .git, .env, .svn).'
      });
    }

    // 2. Check for robots.txt
    const robotsUrl = `${origin}/robots.txt`;
    const robotsRes = await fetchWithTimeout(robotsUrl);
    if (robotsRes.ok && robotsRes.status === 200 && (robotsRes.text.toLowerCase().includes('user-agent:') || robotsRes.text.toLowerCase().includes('disallow:'))) {
      results.push({
        name: 'Robots Exclusion Policy (robots.txt)',
        url: robotsUrl,
        status: 'secure',
        found: true,
        details: `Discovered active robots.txt file indicating crawler directories. Preview of directives found: ${robotsRes.text.slice(0, 100).replace(/\s+/g, ' ')}...`,
        recommendation: 'Ensure your robots.txt does not inadvertently list sensitive administrative, temporary, or staging folders that attackers could target.'
      });
    } else {
      results.push({
        name: 'Robots Exclusion Policy (robots.txt)',
        url: robotsUrl,
        status: 'warning',
        found: false,
        details: 'No active robots.txt exclusion file was found at the root of the server.',
        recommendation: 'Create and deploy a robots.txt file to guide search crawlers and secure administrative directories from automatic indexations.'
      });
    }

    // 3. Check for sitemap.xml
    const sitemapUrl = `${origin}/sitemap.xml`;
    const sitemapRes = await fetchWithTimeout(sitemapUrl);
    if (sitemapRes.ok && sitemapRes.status === 200 && (sitemapRes.text.includes('<urlset') || sitemapRes.text.includes('<sitemapindex') || sitemapRes.text.includes('sitemap'))) {
      results.push({
        name: 'XML Sitemap Configuration',
        url: sitemapUrl,
        status: 'secure',
        found: true,
        details: 'XML sitemap file is correctly configured and available at the root.',
        recommendation: 'Validate that all links in the sitemap use HTTPS and map to public production assets only.'
      });
    } else {
      results.push({
        name: 'XML Sitemap Configuration',
        url: sitemapUrl,
        status: 'warning',
        found: false,
        details: 'XML Sitemap was missing or returned non-valid schema at the standard root directory.',
        recommendation: 'Configure an XML sitemap to assist indexation bots and improve search engine crawl efficiency.'
      });
    }

    // 4. Check for Common Admin/Login Interfaces
    const adminEndpoints = ['/wp-admin/', '/admin/', '/administrator/', '/login'];
    let adminFound = false;
    let foundUrl = '';
    for (const endpoint of adminEndpoints) {
      const adminUrl = `${origin}${endpoint}`;
      const adminRes = await fetchWithTimeout(adminUrl, 2000);
      if (adminRes.status === 200 && (
        adminRes.text.toLowerCase().includes('login') || 
        adminRes.text.toLowerCase().includes('password') ||
        adminRes.text.toLowerCase().includes('username') ||
        adminRes.text.toLowerCase().includes('wp-submit')
      )) {
        adminFound = true;
        foundUrl = adminUrl;
        break;
      }
    }

    if (adminFound) {
      results.push({
        name: 'Exposed Admin/Login Portals',
        url: foundUrl,
        status: 'warning',
        found: true,
        details: `Discovered responsive login or admin interface at: ${foundUrl}. Exposed login panels can become targets for brute-force or credential stuffing attempts.`,
        recommendation: 'Restrict admin access to trusted IPs, deploy Multi-Factor Authentication (MFA), or put the admin routes behind a VPN/WAF protection layer.'
      });
    } else {
      results.push({
        name: 'Exposed Admin/Login Portals',
        url: `${origin}/admin/`,
        status: 'secure',
        found: false,
        details: 'No common administrative or login portals were exposed or responded directly at default endpoints (/admin, /wp-admin, /administrator).',
        recommendation: 'Use custom, non-standard administrative routes and implement rate-limiting or IP whitelisting.'
      });
    }

    // 5. Directory Listing Checks
    const directoryEndpoints = ['/images/', '/uploads/', '/assets/', '/static/'];
    let dirListingFound = false;
    let foundDirUrl = '';
    
    for (const dirPath of directoryEndpoints) {
      const dirUrl = `${origin}${dirPath}`;
      const dirRes = await fetchWithTimeout(dirUrl, 2000);
      if (dirRes.status === 200 && (
        dirRes.text.includes('Index of /') || 
        dirRes.text.toLowerCase().includes('parent directory') ||
        dirRes.text.includes('alt="[DIR]"') ||
        dirRes.text.includes('Last modified')
      )) {
        dirListingFound = true;
        foundDirUrl = dirUrl;
        break;
      }
    }

    if (dirListingFound) {
      results.push({
        name: 'Directory Listing Exposure',
        url: foundDirUrl,
        status: 'danger',
        found: true,
        details: `Active directory listing is enabled at ${foundDirUrl}. This allows arbitrary visitors to browse, explore, and download raw media and script assets of your application.`,
        recommendation: 'Configure your web server to disable directory indexing globally (e.g. "Options -Indexes" in Apache, or "autoindex off;" in Nginx).'
      });
    } else {
      results.push({
        name: 'Directory Listing Exposure',
        url: `${origin}/uploads/`,
        status: 'secure',
        found: false,
        details: 'No default directory listings or open folders (MIME listing indices) were detected.',
        recommendation: 'Ensure autoindex remains disabled across all web root folders to safeguard proprietary files.'
      });
    }
  } catch (err) {
    console.error('Error during checkExposures:', err);
  }
  return results;
}

// Security Headers Scan Endpoint
app.all('/scan/headers', async (req, res) => {
  try {
    let urlStr = (req.method === 'POST' ? req.body.url : req.query.url) as string;
    if (!urlStr) {
      return res.status(400).json({ error: 'URL parameter is required.' });
    }

    const normalizedUrl = normalizeUrl(urlStr);
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(normalizedUrl);
    } catch {
      return res.status(400).json({ error: 'Invalid URL format.' });
    }

    // Resolve IP address
    let ipAddress: string | null = null;
    try {
      const lookupResult = await dns.lookup(parsedUrl.hostname);
      ipAddress = lookupResult.address;
    } catch (dnsErr) {
      console.warn(`DNS lookup failed for ${parsedUrl.hostname}:`, dnsErr);
    }

    // Perform HTTP GET request
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000); // 8 second timeout

    let fetchResponse: Response;
    try {
      fetchResponse = await fetch(normalizedUrl, {
        method: 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.5',
        },
        signal: controller.signal,
        redirect: 'follow', // follow up to max redirects natively
      });
      clearTimeout(timeoutId);
    } catch (fetchErr: any) {
      clearTimeout(timeoutId);
      const isTimeout = fetchErr.name === 'AbortError';
      return res.status(502).json({
        url: normalizedUrl,
        status: 'error',
        error: isTimeout 
          ? 'Request timed out after 8 seconds.' 
          : `Failed to reach target server: ${fetchErr.message}`
      });
    }

    // Extract headers
    const rawHeaders: Record<string, string> = {};
    fetchResponse.headers.forEach((val, key) => {
      rawHeaders[key.toLowerCase()] = val;
    });

    const serverHeader = rawHeaders['server'] || null;
    const poweredByHeader = rawHeaders['x-powered-by'] || null;

    // Evaluate headers
    const headersAnalysis: any = {};
    let score = 100;
    const summary = { secure: 0, warning: 0, danger: 0, info: 0, total: 7 };

    // 1. Strict-Transport-Security (HSTS)
    const hsts = rawHeaders['strict-transport-security'];
    if (!hsts) {
      const isHttps = parsedUrl.protocol === 'https:';
      headersAnalysis['strict-transport-security'] = {
        name: 'Strict-Transport-Security (HSTS)',
        present: false,
        value: null,
        status: isHttps ? 'danger' : 'warning',
        rating: 'Missing',
        description: 'Restricts browser clients to HTTPS-only connections.',
        recommendation: 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload" to your server response headers.'
      };
      score -= isHttps ? 20 : 10;
      if (isHttps) summary.danger++; else summary.warning++;
    } else {
      let status: 'secure' | 'warning' = 'secure';
      let rating = 'Excellent';
      let recommendation = 'No action required.';
      const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
      const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;

      if (maxAge < 10368000) {
        status = 'warning';
        rating = 'Weak (Low Max-Age)';
        recommendation = 'Increase max-age to at least 31536000 (1 year).';
        score -= 5;
        summary.warning++;
      } else if (!hsts.toLowerCase().includes('includesubdomains')) {
        status = 'warning';
        rating = 'Incomplete';
        recommendation = 'Add "includeSubDomains" directive to cover all subdomains.';
        score -= 5;
        summary.warning++;
      } else {
        summary.secure++;
      }

      headersAnalysis['strict-transport-security'] = {
        name: 'Strict-Transport-Security (HSTS)',
        present: true,
        value: hsts,
        status,
        rating,
        description: 'Enforces SSL/TLS usage across all visits.',
        recommendation
      };
    }

    // 2. Content-Security-Policy (CSP)
    const csp = rawHeaders['content-security-policy'];
    if (!csp) {
      headersAnalysis['content-security-policy'] = {
        name: 'Content-Security-Policy (CSP)',
        present: false,
        value: null,
        status: 'danger',
        rating: 'Missing',
        description: 'Protects against Cross-Site Scripting (XSS) and code injection.',
        recommendation: 'Define a clean CSP specifying allowed scripts, stylesheets, and images. For starters, try: "default-src \'self\'; script-src \'self\'; style-src \'self\';".'
      };
      score -= 25;
      summary.danger++;
    } else {
      let status: 'secure' | 'warning' = 'secure';
      let rating = 'Excellent';
      let rec = 'No action required.';
      if (csp.includes("unsafe-inline") && !csp.includes("'nonce-") && !csp.includes("'sha256-")) {
        status = 'warning';
        rating = 'Configured (Permissive)';
        rec = "Avoid using 'unsafe-inline' without nonces or hashes, as it weakens protection against XSS.";
        score -= 5;
        summary.warning++;
      } else {
        summary.secure++;
      }
      headersAnalysis['content-security-policy'] = {
        name: 'Content-Security-Policy (CSP)',
        present: true,
        value: csp,
        status,
        rating,
        description: 'Restricts content, scripts, and asset loading to trusted origins.',
        recommendation: rec
      };
    }

    // 3. X-Frame-Options (XFO)
    const xfo = rawHeaders['x-frame-options'];
    if (!xfo) {
      headersAnalysis['x-frame-options'] = {
        name: 'X-Frame-Options (XFO)',
        present: false,
        value: null,
        status: 'danger',
        rating: 'Missing',
        description: 'Prevents clickjacking attacks by blocking iframe embedding.',
        recommendation: 'Set X-Frame-Options: SAMEORIGIN (recommended) or DENY on all responsive pages.'
      };
      score -= 15;
      summary.danger++;
    } else {
      const lowerXfo = xfo.toLowerCase();
      if (lowerXfo.includes('sameorigin') || lowerXfo.includes('deny')) {
        summary.secure++;
        headersAnalysis['x-frame-options'] = {
          name: 'X-Frame-Options (XFO)',
          present: true,
          value: xfo,
          status: 'secure',
          rating: 'Excellent',
          description: 'Configured securely to block embedding on external domains.',
          recommendation: 'No action required.'
        };
      } else {
        score -= 5;
        summary.warning++;
        headersAnalysis['x-frame-options'] = {
          name: 'X-Frame-Options (XFO)',
          present: true,
          value: xfo,
          status: 'warning',
          rating: 'Permissive',
          description: 'Present but uses an outdated or insecure configuration.',
          recommendation: 'Modify to use X-Frame-Options: SAMEORIGIN or DENY.'
        };
      }
    }

    // 4. X-Content-Type-Options
    const xcto = rawHeaders['x-content-type-options'];
    if (!xcto) {
      headersAnalysis['x-content-type-options'] = {
        name: 'X-Content-Type-Options',
        present: false,
        value: null,
        status: 'danger',
        rating: 'Missing',
        description: 'Blocks browsers from parsing files away from declared MIME types (prevents drive-by downloads).',
        recommendation: 'Add "X-Content-Type-Options: nosniff" to all server configurations.'
      };
      score -= 15;
      summary.danger++;
    } else if (xcto.toLowerCase().includes('nosniff')) {
      summary.secure++;
      headersAnalysis['x-content-type-options'] = {
        name: 'X-Content-Type-Options',
        present: true,
        value: xcto,
        status: 'secure',
        rating: 'Excellent',
        description: 'Successfully prevents MIME-sniffing.',
        recommendation: 'No action required.'
      };
    } else {
      score -= 5;
      summary.warning++;
      headersAnalysis['x-content-type-options'] = {
        name: 'X-Content-Type-Options',
        present: true,
        value: xcto,
        status: 'warning',
        rating: 'Invalid',
        description: 'Header exists but is not set to "nosniff".',
        recommendation: 'Correct the value to "nosniff".'
      };
    }

    // 5. Referrer-Policy
    const rp = rawHeaders['referrer-policy'];
    if (!rp) {
      headersAnalysis['referrer-policy'] = {
        name: 'Referrer-Policy',
        present: false,
        value: null,
        status: 'warning',
        rating: 'Missing',
        description: 'Restricts user referrer metadata passed during outbound links.',
        recommendation: 'Set Referrer-Policy: strict-origin-when-cross-origin to ensure private data is not leaked.'
      };
      score -= 10;
      summary.warning++;
    } else {
      const lowerRp = rp.toLowerCase();
      if (lowerRp.includes('unsafe-url')) {
        score -= 10;
        summary.danger++;
        headersAnalysis['referrer-policy'] = {
          name: 'Referrer-Policy',
          present: true,
          value: rp,
          status: 'danger',
          rating: 'Insecure Configuration',
          description: 'Configured to leak referrers globally, exposing user paths.',
          recommendation: 'Remove "unsafe-url" and configure Referrer-Policy: strict-origin-when-cross-origin.'
        };
      } else {
        summary.secure++;
        headersAnalysis['referrer-policy'] = {
          name: 'Referrer-Policy',
          present: true,
          value: rp,
          status: 'secure',
          rating: 'Excellent',
          description: 'Referrer headers are restricted to protect privacy.',
          recommendation: 'No action required.'
        };
      }
    }

    // 6. Permissions-Policy (Feature-Policy)
    const pp = rawHeaders['permissions-policy'] || rawHeaders['feature-policy'];
    if (!pp) {
      headersAnalysis['permissions-policy'] = {
        name: 'Permissions-Policy',
        present: false,
        value: null,
        status: 'warning',
        rating: 'Missing',
        description: 'Restricts access to local client hardware and APIs (camera, geolocation).',
        recommendation: 'Add Permissions-Policy response headers to isolate browser APIs.'
      };
      score -= 10;
      summary.warning++;
    } else {
      summary.secure++;
      headersAnalysis['permissions-policy'] = {
        name: 'Permissions-Policy',
        present: true,
        value: pp,
        status: 'secure',
        rating: 'Excellent',
        description: 'Browser API capabilities are scoped cleanly.',
        recommendation: 'No action required.'
      };
    }

    // 7. X-XSS-Protection
    const xxp = rawHeaders['x-xss-protection'];
    if (!xxp) {
      summary.info++;
      headersAnalysis['x-xss-protection'] = {
        name: 'X-XSS-Protection (Legacy)',
        present: false,
        value: null,
        status: 'info',
        rating: 'Not Configured',
        description: 'Legacy filter control. Mostly superseded by CSP guidelines.',
        recommendation: 'Humble recommendation: Ensure Content-Security-Policy is fully implemented.'
      };
    } else {
      summary.info++;
      headersAnalysis['x-xss-protection'] = {
        name: 'X-XSS-Protection (Legacy)',
        present: true,
        value: xxp,
        status: 'info',
        rating: 'Configured',
        description: 'Legacy cross-site scripting filter block config.',
        recommendation: 'This is a good backup for ancient browsers, though modern ones ignore it in favor of CSP.'
      };
    }

    // Clamp score
    score = Math.max(10, Math.min(100, score));

    // Assign letter grade
    let grade = 'F';
    if (score >= 95) grade = 'A+';
    else if (score >= 90) grade = 'A';
    else if (score >= 85) grade = 'B+';
    else if (score >= 80) grade = 'B';
    else if (score >= 70) grade = 'C';
    else if (score >= 60) grade = 'D';

    // Check exposures
    const exposures = await checkExposures(normalizedUrl);

    const report = {
      url: normalizedUrl,
      scannedAt: new Date().toISOString(),
      status: 'success',
      statusCode: fetchResponse.status,
      score,
      grade,
      summary,
      headers: headersAnalysis,
      rawHeaders,
      serverInfo: {
        server: serverHeader,
        poweredBy: poweredByHeader,
        ipAddress: ipAddress
      },
      exposures
    };

    res.json(report);
  } catch (error: any) {
    console.error('Scan error:', error);
    res.status(500).json({ error: error.message || 'Failed to scan headers.' });
  }
});

// Endpoint to check configuration status
app.get('/api/config', (req, res) => {
  res.json({ hasGemini: !!ai });
});

// Gemini-powered custom AI Security Audit endpoint
app.post('/api/ai-audit', async (req, res) => {
  try {
    const { report } = req.body;
    if (!report) {
      return res.status(400).json({ error: 'Report data is required.' });
    }

    if (!ai) {
      return res.status(500).json({ error: 'Gemini API key is not configured.' });
    }

    const prompt = `Perform a comprehensive, professional security headers audit for the website "${report.url}".
    
The website received a security score of ${report.score}/100 and a letter grade of "${report.grade}".
Here is the detailed header scanning report:
${JSON.stringify(report, null, 2)}

Provide an elegant markdown-formatted audit briefing:
1. Executive Summary: High-level overview of the server's security posture.
2. Major Gaps & Vulnerabilities: What is missing and what threats (like XSS, Clickjacking, MIME sniffing, session hijacking) are they exposed to as a result.
3. Priority Checklist: Clear, actionable implementation instructions for setting up the missing headers (specifically HSTS, CSP, X-Frame-Options, X-Content-Type-Options) with robust production-ready code examples (e.g. Nginx, Apache, or Express config snippets).
4. Privacy Analysis: How they handle Referrer and Feature Permissions.

Make the tone objective, technical, and educational. Keep the format beautiful and crisp.`;

    const response = await ai.models.generateContent({
      model: 'gemini-3.5-flash',
      contents: prompt,
      config: {
        systemInstruction: 'You are an elite web application penetration tester and security engineer. Return only highly actionable, beautifully formatted Markdown security briefs.'
      }
    });

    res.json({ text: response.text });
  } catch (error: any) {
    console.error('AI audit error:', error);
    res.status(500).json({ error: error.message || 'Failed to generate AI security audit.' });
  }
});

import PDFDocument from 'pdfkit';
import fs from 'fs';
import os from 'os';

function generatePdfWithPdfKit(data: any, stream: NodeJS.WritableStream): Promise<void> {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({
        size: 'LETTER',
        margins: { top: 36, bottom: 36, left: 36, right: 36 }
      });

      doc.pipe(stream);

      // Palettes
      const COLOR_PRIMARY = '#0f172a'; // Deep slate
      const COLOR_SECONDARY = '#4f46e5'; // Indigo
      const COLOR_ACCENT = '#0d9488'; // Teal
      const COLOR_SECURE = '#10b981'; // Emerald
      const COLOR_WARNING = '#f59e0b'; // Amber
      const COLOR_DANGER = '#f43f5e'; // Rose
      const COLOR_INFO = '#6366f1'; // Indigo 500
      const COLOR_BG_LIGHT = '#f8fafc'; // Slate 50
      const COLOR_BORDER = '#e2e8f0'; // Slate 200
      const COLOR_TEXT = '#334155'; // Slate 700
      const COLOR_MUTED = '#64748b'; // Slate 500

      // --- PAGE 1: HEADER & OVERVIEW ---
      // Draw background header block
      doc.rect(36, 36, 540, 80).fill(COLOR_PRIMARY);
      
      // Header Title
      doc.fillColor('#ffffff')
         .font('Helvetica-Bold')
         .fontSize(20)
         .text('KEPOKSCAN HEADER GUARD', 50, 50);
      
      doc.fillColor('#94a3b8')
         .font('Helvetica')
         .fontSize(8.5)
         .text('HTTP RESPONSE HEADER VULNERABILITY ANALYZER', 50, 75);

      // Grade & Score Badge inside header
      doc.fillColor('#ffffff')
         .font('Helvetica-Bold')
         .fontSize(30)
         .text(data.grade || 'F', 460, 48, { width: 100, align: 'center' });
      
      doc.fillColor('#94a3b8')
         .font('Helvetica-Bold')
         .fontSize(8)
         .text(`SCORE: ${data.score || 0}/100`, 460, 82, { width: 100, align: 'center' });

      doc.y = 135;

      // Scan Metadata Section
      doc.fillColor(COLOR_PRIMARY)
         .font('Helvetica-Bold')
         .fontSize(12)
         .text('Scan Metadata', 36, doc.y);
      
      doc.y += 15;
      
      const metaY = doc.y;
      doc.rect(36, metaY, 540, 75).fill(COLOR_BG_LIGHT).stroke(COLOR_BORDER);

      const urlVal = data.url || 'N/A';
      let scannedAt = data.scannedAt || 'N/A';
      try { scannedAt = scannedAt.replace('T', ' ').split('.')[0] + ' UTC'; } catch {}

      const serverInfo = data.serverInfo || {};
      const ip = serverInfo.ipAddress || 'Not resolved';
      const serverSoftware = serverInfo.server || 'None Disclosed';
      const poweredBy = serverInfo.poweredBy || 'None Disclosed';
      const status = data.statusCode || 'N/A';

      doc.fillColor(COLOR_MUTED).font('Helvetica-Bold').fontSize(8);
      doc.text('Target URL:', 46, metaY + 10);
      doc.text('Scan Timestamp:', 310, metaY + 10);
      doc.text('IP Address:', 46, metaY + 30);
      doc.text('Response Code:', 310, metaY + 30);
      doc.text('Server Software:', 46, metaY + 50);
      doc.text('Powered By:', 310, metaY + 50);

      doc.fillColor(COLOR_PRIMARY).font('Helvetica-Bold').fontSize(8.5);
      doc.text(urlVal, 130, metaY + 10, { width: 170, ellipsis: true });
      doc.text(scannedAt, 410, metaY + 10);
      doc.text(ip, 130, metaY + 30);
      doc.text(String(status), 410, metaY + 30);
      doc.text(serverSoftware, 130, metaY + 50, { width: 170, ellipsis: true });
      doc.text(poweredBy, 410, metaY + 50, { width: 150, ellipsis: true });

      doc.y = metaY + 105;

      // Executive Summary
      doc.fillColor(COLOR_PRIMARY)
         .font('Helvetica-Bold')
         .fontSize(12)
         .text('Compliance Overview', 36, doc.y);

      doc.y += 15;
      const summaryY = doc.y;
      
      const summary = data.summary || { secure: 0, warning: 0, danger: 0, info: 0 };
      doc.rect(36, summaryY, 540, 100).stroke(COLOR_BORDER);
      
      // Grid cells background for stats
      doc.rect(36, summaryY, 135, 30).fill(COLOR_BG_LIGHT);
      doc.rect(171, summaryY, 135, 30).fill(COLOR_BG_LIGHT);
      doc.rect(306, summaryY, 135, 30).fill(COLOR_BG_LIGHT);
      doc.rect(441, summaryY, 135, 30).fill(COLOR_BG_LIGHT);

      doc.fillColor(COLOR_SECURE).font('Helvetica-Bold').fontSize(10).text(`${summary.secure} Secure`, 36, summaryY + 10, { width: 135, align: 'center' });
      doc.fillColor(COLOR_WARNING).font('Helvetica-Bold').fontSize(10).text(`${summary.warning} Warnings`, 171, summaryY + 10, { width: 135, align: 'center' });
      doc.fillColor(COLOR_DANGER).font('Helvetica-Bold').fontSize(10).text(`${summary.danger} Critical`, 306, summaryY + 10, { width: 135, align: 'center' });
      doc.fillColor(COLOR_INFO).font('Helvetica-Bold').fontSize(10).text(`${summary.info} Info`, 441, summaryY + 10, { width: 135, align: 'center' });

      // Compliance description text
      let complianceText = "";
      if (data.score >= 90) {
        complianceText = "EXCELLENT COGNIZANCE: This site adheres to modern security baselines. Recommended headers are configured properly, minimizing potential vectors for clickjacking, drive-by downloads, or protocol degradation.";
      } else if (data.score >= 70) {
        complianceText = "MODERATE STATUS: This server has basic protection in place, but lacks critical HTTP features (like Content-Security-Policy or Strict-Transport-Security) that leave browser clients vulnerable to targeted attacks.";
      } else {
        complianceText = "CRITICAL COMPLIANCE ALERTS: Multiple key security headers are either missing or dangerously misconfigured. Immediate remediation is highly advised to avoid client-side exploitation.";
      }

      doc.fillColor(COLOR_TEXT).font('Helvetica').fontSize(9.5).text(complianceText, 48, summaryY + 45, { width: 516, lineGap: 3 });

      // Add Exposure Summary at the bottom of Page 1 if present
      if (data.exposures && data.exposures.length > 0) {
        doc.y = summaryY + 120;
        doc.fillColor(COLOR_PRIMARY).font('Helvetica-Bold').fontSize(11).text('Discovered Exposure Scanning Insights', 36, doc.y);
        doc.y += 12;

        const expSumY = doc.y;
        doc.rect(36, expSumY, 540, 55).fill(COLOR_BG_LIGHT).stroke(COLOR_BORDER);

        const dangers = data.exposures.filter((e: any) => e.status === 'danger');
        const warnings = data.exposures.filter((e: any) => e.status === 'warning');

        let expText = "Our continuous exposure detection analyzed exposed configuration dirs, crawlers, sitemaps, and default dashboards. ";
        if (dangers.length > 0 || warnings.length > 0) {
          expText += `Vulnerabilities were identified: we found ${dangers.length} high-severity exposures and ${warnings.length} moderate administrative exposures. Prompt isolation is advised.`;
        } else {
          expText += "Congratulations! All examined directory and administrative paths appear tightly locked down against public listing or leaks.";
        }

        doc.fillColor(COLOR_TEXT).font('Helvetica-Bold').fontSize(8.5).text(expText, 46, expSumY + 10, { width: 520, lineGap: 2 });
      }

      // --- PAGE 2: HEADERS MATRIX ---
      doc.addPage();
      
      doc.fillColor(COLOR_PRIMARY).font('Helvetica-Bold').fontSize(14).text('Security Header Matrix', 36, 36);
      doc.y = 55;

      // Draw table header
      doc.rect(36, doc.y, 540, 20).fill(COLOR_PRIMARY);
      doc.fillColor('#ffffff').font('Helvetica-Bold').fontSize(8.5);
      doc.text('Header / Name', 46, doc.y + 6);
      doc.text('Presence', 290, doc.y + 6);
      doc.text('Rating / Assessment', 390, doc.y + 6);

      doc.y += 20;

      const headersDict = data.headers || {};
      const headerKeys = Object.keys(headersDict);

      headerKeys.forEach((key, idx) => {
        const h = headersDict[key];
        const name = h.name || key;
        const present = h.present ? 'CONFIGURED' : 'MISSING';
        const rating = h.rating || 'Unknown';
        const status = h.status || 'info';

        // Background alternate shading
        if (idx % 2 === 1) {
          doc.rect(36, doc.y, 540, 24).fill(COLOR_BG_LIGHT);
        } else {
          doc.rect(36, doc.y, 540, 24).fill('#ffffff');
        }

        // Stroke line
        doc.rect(36, doc.y, 540, 24).stroke(COLOR_BORDER);

        // Print values
        doc.fillColor(COLOR_PRIMARY).font('Helvetica-Bold').fontSize(8.5);
        doc.text(name.split(' (')[0], 46, doc.y + 7, { width: 230, ellipsis: true });
        
        doc.fillColor(COLOR_MUTED).font('Helvetica').fontSize(7.5);
        doc.text(key, 46, doc.y + 15, { width: 230, ellipsis: true });

        // Presence column
        doc.fillColor(h.present ? COLOR_PRIMARY : COLOR_MUTED).font('Helvetica-Bold').fontSize(8);
        doc.text(present, 290, doc.y + 8);

        // Rating column (Color based on status)
        let ratingColor = COLOR_TEXT;
        if (status === 'secure') ratingColor = COLOR_SECURE;
        else if (status === 'warning') ratingColor = COLOR_WARNING;
        else if (status === 'danger') ratingColor = COLOR_DANGER;
        else if (status === 'info') ratingColor = COLOR_INFO;

        doc.fillColor(ratingColor).font('Helvetica-Bold').fontSize(8);
        doc.text(rating, 390, doc.y + 8, { width: 175, ellipsis: true });

        doc.y += 24;
      });

      // --- NEW: PAGE 3: EXPOSURES MATRIX & CHECKS ---
      if (data.exposures && data.exposures.length > 0) {
        doc.addPage();
        doc.fillColor(COLOR_PRIMARY).font('Helvetica-Bold').fontSize(14).text('Exposed Files & Endpoint Analysis', 36, 36);
        doc.y = 55;

        // Draw Table Header
        doc.rect(36, doc.y, 540, 20).fill(COLOR_PRIMARY);
        doc.fillColor('#ffffff').font('Helvetica-Bold').fontSize(8.5);
        doc.text('Inspected Scope', 46, doc.y + 6);
        doc.text('Status', 290, doc.y + 6);
        doc.text('Findings / Details', 380, doc.y + 6);

        doc.y += 20;

        data.exposures.forEach((exp: any, idx: number) => {
          // Shading
          if (idx % 2 === 1) {
            doc.rect(36, doc.y, 540, 42).fill(COLOR_BG_LIGHT);
          } else {
            doc.rect(36, doc.y, 540, 42).fill('#ffffff');
          }
          doc.rect(36, doc.y, 540, 42).stroke(COLOR_BORDER);

          // Details
          doc.fillColor(COLOR_PRIMARY).font('Helvetica-Bold').fontSize(8.5);
          doc.text(exp.name, 46, doc.y + 8, { width: 230, ellipsis: true });

          doc.fillColor(COLOR_MUTED).font('Courier').fontSize(7);
          doc.text(exp.url, 46, doc.y + 24, { width: 230, ellipsis: true });

          // Status Badge
          let statText = 'SECURE';
          let statColor = COLOR_SECURE;
          if (exp.status === 'danger') {
            statText = 'CRITICAL';
            statColor = COLOR_DANGER;
          } else if (exp.status === 'warning') {
            statText = 'WARNING';
            statColor = COLOR_WARNING;
          }

          doc.fillColor(statColor).font('Helvetica-Bold').fontSize(8);
          doc.text(statText, 290, doc.y + 12);

          // Findings paragraph
          doc.fillColor(COLOR_TEXT).font('Helvetica').fontSize(7.5);
          doc.text(exp.details, 380, doc.y + 6, { width: 185, lineGap: 1.5 });

          doc.y += 42;
        });
      }

      // --- PAGE 4+: DETAILED ANALYSIS ---
      doc.addPage();
      doc.fillColor(COLOR_PRIMARY).font('Helvetica-Bold').fontSize(14).text('Detailed Analysis & Recommendations', 36, 36);
      doc.y = 55;

      headerKeys.forEach((key) => {
        const h = headersDict[key];
        const name = h.name || key;
        const present = h.present;
        const val = h.value;
        const desc = h.description || '';
        const rec = h.recommendation || '';
        const status = h.status || 'info';

        // Check page overflow
        if (doc.y > 600) {
          doc.addPage();
          doc.y = 36;
        }

        // Header Title Block
        let tag = '[INFO]';
        let tagColor = COLOR_INFO;
        if (status === 'secure') { tag = '[SECURE]'; tagColor = COLOR_SECURE; }
        else if (status === 'warning') { tag = '[WARNING]'; tagColor = COLOR_WARNING; }
        else if (status === 'danger') { tag = '[CRITICAL]'; tagColor = COLOR_DANGER; }

        doc.fillColor(tagColor).font('Helvetica-Bold').fontSize(9.5);
        doc.text(tag, 36, doc.y, { continued: true });
        doc.fillColor(COLOR_PRIMARY).font('Helvetica-Bold').fontSize(9.5);
        doc.text(`  ${name} (${key})`);

        doc.y += 6;

        // Current Value
        if (present && val) {
          doc.fillColor(COLOR_MUTED).font('Helvetica-Bold').fontSize(7.5).text('Current Value:', 46, doc.y);
          doc.y += 10;
          
          // Draw standard light gray box for value
          doc.font('Courier').fontSize(7.5);
          const codeHeight = Math.min(60, doc.heightOfString(val, { width: 510 }) + 10);
          doc.rect(46, doc.y, 510, codeHeight).fill('#f1f5f9').stroke('#cbd5e1');
          
          doc.fillColor('#1e1b4b').font('Courier').fontSize(7.5);
          doc.text(val, 52, doc.y + 5, { width: 500, height: codeHeight - 8 });
          
          doc.y += codeHeight + 8;
        } else {
          doc.fillColor(COLOR_MUTED).font('Helvetica-Oblique').fontSize(8.5).text('Status: Missing or disabled on the target server.', 46, doc.y);
          doc.y += 14;
        }

        // Description
        doc.fillColor(COLOR_TEXT).fontSize(8.5);
        doc.font('Helvetica-Bold').text('Functional Impact: ', 36, doc.y, { continued: true });
        doc.font('Helvetica').text(desc);
        doc.y += 3;

        // Recommendation
        doc.fillColor(COLOR_TEXT).fontSize(8.5);
        doc.font('Helvetica-Bold').text('Remediation Advice: ', 36, doc.y, { continued: true });
        doc.font('Helvetica').text(rec);

        doc.y += 15;
        // Horizontal divider line
        doc.strokeColor(COLOR_BORDER).lineWidth(0.5).moveTo(36, doc.y).lineTo(576, doc.y).stroke();
        doc.y += 12;
      });

      // --- PAGE 5+: GEMINI SECURITY AUDIT (IF AVAILABLE) ---
      if (data.ai_audit_text) {
        doc.addPage();
        doc.fillColor(COLOR_PRIMARY).font('Helvetica-Bold').fontSize(14).text('Gemini Deep Security Audit', 36, 36);
        doc.y = 55;

        doc.fillColor(COLOR_TEXT).font('Helvetica').fontSize(9);
        const auditLines = data.ai_audit_text.split('\n');
        
        auditLines.forEach((line: string) => {
          const cleanLine = line.trim();
          if (!cleanLine) {
            doc.y += 6;
            return;
          }

          if (doc.y > 700) {
            doc.addPage();
            doc.y = 36;
          }

          if (cleanLine.startsWith('### ')) {
            doc.y += 4;
            doc.fillColor(COLOR_SECONDARY).font('Helvetica-Bold').fontSize(10).text(cleanLine.replace('### ', ''), 36, doc.y);
            doc.y += 4;
          } else if (cleanLine.startsWith('## ') || cleanLine.startsWith('# ')) {
            doc.y += 8;
            const title = cleanLine.replace('## ', '').replace('# ', '').replace(/\*/g, '');
            doc.fillColor(COLOR_PRIMARY).font('Helvetica-Bold').fontSize(11.5).text(title, 36, doc.y);
            doc.y += 6;
          } else if (cleanLine.startsWith('- ') || cleanLine.startsWith('* ')) {
            doc.fillColor(COLOR_TEXT).font('Helvetica').fontSize(8.5);
            doc.text(`• ${cleanLine.substring(2).replace(/\*/g, '')}`, 46, doc.y, { width: 520, lineGap: 2 });
          } else {
            doc.fillColor(COLOR_TEXT).font('Helvetica').fontSize(8.5);
            doc.text(cleanLine.replace(/\*/g, ''), 36, doc.y, { width: 530, lineGap: 2 });
          }
        });
      }

      doc.end();
      resolve();
    } catch (e) {
      reject(e);
    }
  });
}

// PDF Download Endpoint using PDFKit (Pure TS/JS, zero Python reportlab runtime issues)
app.post('/api/download-pdf', async (req, res) => {
  try {
    const { report, aiAuditText } = req.body;
    if (!report) {
      return res.status(400).json({ error: 'Report data is required.' });
    }

    // Attach AI audit if present so the PDF can display it too
    const fullReport = {
      ...report,
      ai_audit_text: aiAuditText || null
    };

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="kepokscan-security-report-${new URL(report.url).hostname}.pdf"`);

    await generatePdfWithPdfKit(fullReport, res);

  } catch (err: any) {
    console.error('PDF generation endpoint error:', err);
    // If not already sent, return 500 error
    if (!res.headersSent) {
      res.status(500).json({ error: err.message || 'An error occurred during PDF compiling.' });
    }
  }
});

// Initialize Gemini API (kept for existing endpoint dependencies)
const aiInstance = ai;

// API routes
app.post('/api/generate-content', async (req, res) => {
  try {
    const { prompt, systemInstruction } = req.body;
    if (!ai) {
      return res.status(500).json({ error: 'Gemini API key is not configured.' });
    }

    const response = await ai.models.generateContent({
      model: 'gemini-3.5-flash',
      contents: prompt,
      config: systemInstruction ? { systemInstruction } : undefined,
    });

    res.json({ text: response.text });
  } catch (error: any) {
    console.error('Error generating content:', error);
    res.status(500).json({ error: error.message || 'Failed to generate content.' });
  }
});

// JSON API routes for structured brainstorming
app.post('/api/generate-structured', async (req, res) => {
  try {
    const { prompt, schema, systemInstruction } = req.body;
    if (!ai) {
      return res.status(500).json({ error: 'Gemini API key is not configured.' });
    }

    const response = await ai.models.generateContent({
      model: 'gemini-3.5-flash',
      contents: prompt,
      config: {
        systemInstruction,
        responseMimeType: 'application/json',
        responseSchema: schema,
      }
    });

    res.json({ text: response.text });
  } catch (error: any) {
    console.error('Error generating structured content:', error);
    res.status(500).json({ error: error.message || 'Failed to generate structured content.' });
  }
});

// Serve frontend
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, 'dist')));
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'dist', 'index.html'));
  });
} else {
  // Integrate Vite dev server in development
  const { createServer: createViteServer } = await import('vite');
  const vite = await createViteServer({
    server: { middlewareMode: true },
    appType: 'spa',
  });
  app.use(vite.middlewares);
}

const PORT = 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});
