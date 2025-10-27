require('dotenv').config();

module.exports = {
  // Server
  NODE_ENV: process.env.NODE_ENV || 'development',
  PORT: process.env.PORT || 5000,
  
  // Database
  MONGO_URI: process.env.MONGO_URI || 'mongodb://localhost:27017/smart-contract-analyzer',
  
  // JWT
  JWT_SECRET: process.env.JWT_SECRET || 'fallback-secret-change-this',
  JWT_EXPIRE: process.env.JWT_EXPIRE || '7d',
  JWT_REFRESH_SECRET: process.env.JWT_REFRESH_SECRET || 'fallback-refresh-secret',
  JWT_REFRESH_EXPIRE: process.env.JWT_REFRESH_EXPIRE || '30d',
  
  // File Upload
  UPLOAD_PATH: process.env.UPLOAD_PATH || './uploads',
  MAX_FILE_SIZE: parseInt(process.env.MAX_FILE_SIZE) || 5242880, // 5MB
  
  // Analyzer Service
  ANALYZER_API_URL: process.env.ANALYZER_API_URL || 'http://localhost:8001',
  ANALYZER_TIMEOUT: parseInt(process.env.ANALYZER_TIMEOUT) || 300000, // 5 minutes
  
  // Payment
  PAYMENT_WEBHOOK_SECRET: process.env.PAYMENT_WEBHOOK_SECRET,
  
  // Email
  SMTP_HOST: process.env.SMTP_HOST,
  SMTP_PORT: process.env.SMTP_PORT,
  SMTP_USER: process.env.SMTP_USER,
  SMTP_PASS: process.env.SMTP_PASS,
  
  // Rate Limiting
  RATE_LIMIT_WINDOW: parseInt(process.env.RATE_LIMIT_WINDOW) || 15,
  RATE_LIMIT_MAX: parseInt(process.env.RATE_LIMIT_MAX) || 100
};
