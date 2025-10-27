const User = require('../models/User');
const ScanReport = require('../models/ScanReport');
const Transaction = require('../models/Transaction');
const logger = require('../utils/logger');
const { validationResult } = require('express-validator');
const crypto = require('crypto');

// @desc    Get user profile
// @route   GET /api/user/profile
// @access  Private
exports.getProfile = async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    
    const dashboardStats = await user.getDashboardStats();

    res.status(200).json({
      success: true,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        credits: user.credits,
        plan: user.plan,
        walletAddress: user.walletAddress,
        totalScans: user.totalScans,
        isEmailVerified: user.isEmailVerified,
        createdAt: user.createdAt,
        lastLogin: user.lastLogin
      },
      credits: user.credits,
      stats: dashboardStats
    });
  } catch (error) {
    logger.error(`Get profile error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error fetching user profile'
    });
  }
};

// @desc    Update user profile
// @route   PUT /api/user/profile
// @access  Private
exports.updateProfile = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { username, email } = req.body;
    const userId = req.user.id;

    // Check if username or email is already taken by another user
    const existingUser = await User.findOne({
      _id: { $ne: userId },
      $or: [{ email }, { username }]
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: existingUser.email === email 
          ? 'Email is already taken' 
          : 'Username is already taken'
      });
    }

    // Update user
    const user = await User.findByIdAndUpdate(
      userId,
      { username, email },
      {
        new: true,
        runValidators: true
      }
    );

    logger.info(`Profile updated for user: ${user.email}`);

    res.status(200).json({
      success: true,
      message: 'Profile updated successfully',
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        credits: user.credits,
        plan: user.plan,
        walletAddress: user.walletAddress,
        totalScans: user.totalScans,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    logger.error(`Update profile error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error updating profile'
    });
  }
};

// @desc    Connect wallet
// @route   POST /api/user/connect-wallet
// @access  Private
exports.connectWallet = async (req, res) => {
  try {
    const { walletAddress, signature } = req.body;

    if (!walletAddress || !signature) {
      return res.status(400).json({
        success: false,
        message: 'Wallet address and signature are required'
      });
    }

    // Basic wallet address validation
    if (!/^0x[a-fA-F0-9]{40}$/.test(walletAddress)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid wallet address format'
      });
    }

    // Check if wallet is already connected to another user
    const existingUser = await User.findOne({
      walletAddress,
      _id: { $ne: req.user.id }
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'This wallet is already connected to another account'
      });
    }

    // In production, you would verify the signature here
    // For now, we'll just save the wallet address

    const user = await User.findByIdAndUpdate(
      req.user.id,
      { walletAddress },
      { new: true }
    );

    logger.info(`Wallet connected for user ${user.email}: ${walletAddress}`);

    res.status(200).json({
      success: true,
      message: 'Wallet connected successfully',
      walletAddress: user.walletAddress
    });
  } catch (error) {
    logger.error(`Connect wallet error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error connecting wallet'
    });
  }
};

// @desc    Disconnect wallet
// @route   POST /api/user/disconnect-wallet
// @access  Private
exports.disconnectWallet = async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.user.id,
      { walletAddress: null },
      { new: true }
    );

    logger.info(`Wallet disconnected for user: ${user.email}`);

    res.status(200).json({
      success: true,
      message: 'Wallet disconnected successfully'
    });
  } catch (error) {
    logger.error(`Disconnect wallet error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error disconnecting wallet'
    });
  }
};

// @desc    Get user credits
// @route   GET /api/user/credits
// @access  Private
exports.getCredits = async (req, res) => {
  try {
    const user = await User.findById(req.user.id);

    res.status(200).json({
      success: true,
      credits: user.credits,
      plan: user.plan
    });
  } catch (error) {
    logger.error(`Get credits error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error fetching credits'
    });
  }
};

// @desc    Get dashboard stats
// @route   GET /api/user/dashboard-stats
// @access  Private
exports.getDashboardStats = async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    const stats = await user.getDashboardStats();

    res.status(200).json({
      success: true,
      data: stats
    });
  } catch (error) {
    logger.error(`Get dashboard stats error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error fetching dashboard stats'
    });
  }
};

// @desc    Get user transaction history
// @route   GET /api/user/transactions
// @access  Private
exports.getTransactions = async (req, res) => {
  try {
    const page = parseInt(req.query.page, 10) || 1;
    const limit = parseInt(req.query.limit, 10) || 10;

    const transactions = await Transaction.getUserTransactions(req.user.id, page, limit);

    const total = await Transaction.countDocuments({ user: req.user.id });

    res.status(200).json({
      success: true,
      data: transactions,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    logger.error(`Get transactions error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error fetching transactions'
    });
  }
};

// @desc    Change password
// @route   POST /api/user/change-password
// @access  Private
exports.changePassword = async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        success: false,
        message: 'Current password and new password are required'
      });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'New password must be at least 6 characters long'
      });
    }

    // Get user with password
    const user = await User.findById(req.user.id).select('+password');

    // Check current password
    if (!(await user.matchPassword(currentPassword))) {
      return res.status(400).json({
        success: false,
        message: 'Current password is incorrect'
      });
    }

    // Update password
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
      message: 'Error changing password'
    });
  }
};

// @desc    Delete user account
// @route   DELETE /api/user/account
// @access  Private
exports.deleteAccount = async (req, res) => {
  try {
    const { password } = req.body;

    if (!password) {
      return res.status(400).json({
        success: false,
        message: 'Password is required to delete account'
      });
    }

    // Get user with password
    const user = await User.findById(req.user.id).select('+password');

    // Verify password
    if (!(await user.matchPassword(password))) {
      return res.status(400).json({
        success: false,
        message: 'Invalid password'
      });
    }

    // Delete user's scan reports
    await ScanReport.deleteMany({ user: req.user.id });

    // Delete user's transactions
    await Transaction.deleteMany({ user: req.user.id });

    // Delete user
    await User.findByIdAndDelete(req.user.id);

    logger.info(`Account deleted for user: ${user.email}`);

    res.status(200).json({
      success: true,
      message: 'Account deleted successfully'
    });
  } catch (error) {
    logger.error(`Delete account error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error deleting account'
    });
  }
};
