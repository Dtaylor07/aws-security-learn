'use strict';

const express = require('express');
const path = require('path');
const { createLogger, format, transports } = require('winston');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Structured logger (CloudWatch picks this up via stdout) ─────────────────
const logger = createLogger({
  level: 'info',
  format: format.combine(
    format.timestamp(),
    format.json()
  ),
  transports: [new transports.Console()]
});

// ── Middleware ──────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '../public')));

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' https://cognito-idp.*.amazonaws.com; style-src 'self' 'unsafe-inline'; connect-src 'self' https://*.amazoncognito.com https://*.execute-api.*.amazonaws.com;");
  next();
});

// Request logging middleware
app.use((req, res, next) => {
  logger.info('incoming_request', {
    method: req.method,
    path: req.path,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    requestId: req.get('X-Request-ID') || 'none'
  });
  next();
});

// ── Routes ──────────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/dashboard.html'));
});

// Health check for ALB target group
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// Config endpoint – returns Cognito + API Gateway config to the frontend
app.get('/config', (req, res) => {
  res.json({
    cognito: {
      region:       process.env.AWS_REGION          || 'us-east-1',
      userPoolId:   process.env.COGNITO_USER_POOL_ID,
      clientId:     process.env.COGNITO_CLIENT_ID,
      hostedUiDomain: process.env.COGNITO_HOSTED_UI_DOMAIN,
      redirectUri:  process.env.COGNITO_REDIRECT_URI || 'http://localhost:3000/dashboard',
      logoutUri:    process.env.COGNITO_LOGOUT_URI   || 'http://localhost:3000'
    },
    apiGateway: {
      endpoint: process.env.API_GATEWAY_ENDPOINT
    }
  });
});

// ── Error handler ────────────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  logger.error('unhandled_error', { error: err.message, stack: err.stack });
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  logger.info('server_started', { port: PORT });
});

module.exports = app;
