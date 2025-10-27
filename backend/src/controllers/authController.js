const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('../models/User');
const config = require('../config');
const logger = require('../utils/logger');
const { validationResult } = require('express-validator');

// @desc    Register user
// @route   POST /api/auth/register
// @access  Public
exports.register = async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { username, email, password } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({
      $or: [{ email }, { username }]
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: existingUser.email === email 
          ? 'User with this email already exists'
          : 'Username is already taken'
      });
    }

    // Create user
    const user = await User.create({
      username,
      email,
      password,
      credits: 3 // New users get 3 free credits
    });

    // Generate token
    const token = user.getSignedJwtToken();
    const refreshToken = user.getRefreshToken();

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    logger.info(`New user registered: ${email}`);

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      token,
      refreshToken,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        credits: user.credits,
        role: user.role,
        plan: user.plan,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    logger.error(`Registration error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Server error during registration'
    });
  }
};

// @desc    Login user
// @route   POST /api/auth/login
// @access  Public
exports.login = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { email, password } = req.body;

    // Check for user (include password for comparison)
    const user = await User.findOne({ email }).select('+password');

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Check if password matches
    const isMatch = await user.matchPassword(password);

    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // Generate tokens
    const token = user.getSignedJwtToken();
    const refreshToken = user.getRefreshToken();

    logger.info(`User logged in: ${email}`);

    res.status(200).json({
      success: true,
      message: 'Login successful',
      token,
      refreshToken,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        credits: user.credits,
        role: user.role,
        plan: user.plan,
        walletAddress: user.walletAddress,
        lastLogin: user.lastLogin
      }
    });
  } catch (error) {
    logger.error(`Login error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Server error during login'
    });
  }
};

// @desc    Logout user
// @route   POST /api/auth/logout
// @access  Private
exports.logout = async (req, res) => {
  try {
    // In a more sophisticated setup, you might want to blacklist the token
    // For now, we'll just send a success response
    logger.info(`User logged out: ${req.user.email}`);

    res.status(200).json({
      success: true,
      message: 'Logout successful'
    });
  } catch (error) {
    logger.error(`Logout error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Server error during logout'
    });
  }
};

// @desc    Get current logged in user
// @route   GET /api/auth/me
// @access  Private
exports.getMe = async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    
    res.status(200).json({
      success: true,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        credits: user.credits,
        role: user.role,
        plan: user.plan,
        walletAddress: user.walletAddress,
        totalScans: user.totalScans,
        createdAt: user.createdAt,
        lastLogin: user.lastLogin
      }
    });
  } catch (error) {
    logger.error(`Get me error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Refresh JWT token
// @route   POST /api/auth/refresh
// @access  Private
exports.refreshToken = async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(401).json({
        success: false,
        message: 'Refresh token is required'
      });
    }

    // Verify refresh token
    const decoded = jwt.verify(refreshToken, config.JWT_REFRESH_SECRET);
    
    // Get user
    const user = await User.findById(decoded.id);
    
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid refresh token'
      });
    }

    // Generate new tokens
    const newToken = user.getSignedJwtToken();
    const newRefreshToken = user.getRefreshToken();

    res.status(200).json({
      success: true,
      token: newToken,
      refreshToken: newRefreshToken
    });
  } catch (error) {
    logger.error(`Refresh token error: ${error.message}`);
    res.status(401).json({
      success: false,
      message: 'Invalid refresh token'
    });
  }
};

// @desc    Forgot password
// @route   POST /api/auth/forgot-password
// @access  Public
exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'No user found with that email'
      });
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(20).toString('hex');

    // Hash token and set to resetPasswordToken field
    user.passwordResetToken = crypto
      .createHash('sha256')
      .update(resetToken)
      .digest('hex');

    // Set expire
    user.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes

    await user.save({ validateBeforeSave: false });

    // In production, you would send an email here
    // For now, we'll just log it
    logger.info(`Password reset token generated for ${email}: ${resetToken}`);

    res.status(200).json({
      success: true,
      message: 'Password reset email sent',
      // In development only - remove in production
      resetToken: process.env.NODE_ENV === 'development' ? resetToken : undefined
    });
  } catch (error) {
    logger.error(`Forgot password error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Email could not be sent'
    });
  }
};

// @desc    Reset password
// @route   POST /api/auth/reset-password
// @access  Public
exports.resetPassword = async (req, res) => {
  try {
    const { token, password } = req.body;

    // Get hashed token
    const resetPasswordToken = crypto
      .createHash('sha256')
      .update(token)
      .digest('hex');

    const user = await User.findOne({
      passwordResetToken: resetPasswordToken,
      passwordResetExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired token'
      });
    }

    // Set new password
    user.password = password;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    // Generate JWT token
    const jwtToken = user.getSignedJwtToken();

    logger.info(`Password reset successful for user: ${user.email}`);

    res.status(200).json({
      success: true,
      message: 'Password reset successful',
      token: jwtToken
    });
  } catch (error) {
    logger.error(`Reset password error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Server error during password reset'
    });
  }
};

// @desc    Change password
// @route   POST /api/auth/change-password
// @access  Private
exports.changePassword = async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    // Get user with password
    const user = await User.findById(req.user.id).select('+password');

    // Check current password
    if (!(await user.matchPassword(currentPassword))) {
      return res.status(400).json({
        success: false,
        message: 'Current password is incorrect'
      });
    }

    user.password = newPassword;
    await user.save();

    logger.info(`Password changed for user: ${user.email}`);

    res.status(200).json({
      success: true,
      message: 'Password updated successfully'
    });
  } catch (error) {
    logger.error(`Change password error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Server error during password change'
    });
  }
};
