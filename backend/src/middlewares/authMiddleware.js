const jwt = require('jsonwebtoken');
const User = require('../models/User');
const config = require('../config');
const logger = require('../utils/logger');

// Protect routes - verify JWT token
exports.protect = async (req, res, next) => {
  let token;

  // Check for token in headers
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  }

  // Check for token in cookies (if implementing cookie auth)
  else if (req.cookies && req.cookies.token) {
    token = req.cookies.token;
  }

  // Make sure token exists
  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Not authorized to access this route'
    });
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, config.JWT_SECRET);

    // Get user from database
    const user = await User.findById(decoded.id);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'No user found with this token'
      });
    }

    req.user = user;
    next();
  } catch (error) {
    logger.error(`Auth middleware error: ${error.message}`);
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        message: 'Token has expired'
      });
    }
    
    return res.status(401).json({
      success: false,
      message: 'Not authorized to access this route'
    });
  }
};

// Grant access to specific roles
exports.authorize = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: `User role ${req.user.role} is not authorized to access this route`
      });
    }
    next();
  };
};

// Check if user has sufficient credits
exports.checkCredits = (requiredCredits = 1) => {
  return async (req, res, next) => {
    try {
      const user = await User.findById(req.user.id);
      
      if (!user.hasCredits(requiredCredits)) {
        return res.status(402).json({
          success: false,
          message: 'Insufficient credits to perform this action',
          data: {
            currentCredits: user.credits,
            requiredCredits
          }
        });
      }
      
      req.user = user; // Update user object with fresh data
      next();
    } catch (error) {
      logger.error(`Credit check middleware error: ${error.message}`);
      return res.status(500).json({
        success: false,
        message: 'Error checking user credits'
      });
    }
  };
};

// Optional auth - don't fail if no token
exports.optionalAuth = async (req, res, next) => {
  let token;

  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (token) {
    try {
      const decoded = jwt.verify(token, config.JWT_SECRET);
      const user = await User.findById(decoded.id);
      if (user) {
        req.user = user;
      }
    } catch (error) {
      // Log but don't fail the request
      logger.warn(`Optional auth warning: ${error.message}`);
    }
  }

  next();
};
