const express = require('express');
const { body } = require('express-validator');
const {
  getProfile,
  updateProfile,
  connectWallet,
  disconnectWallet,
  getCredits,
  getDashboardStats,
  getTransactions,
  changePassword,
  deleteAccount
} = require('../controllers/userController');
const { protect } = require('../middlewares/authMiddleware');

const router = express.Router();

// All routes are protected
router.use(protect);

// Profile routes
router.get('/profile', getProfile);
router.put('/profile', [
  body('username')
    .trim()
    .isLength({ min: 3, max: 20 })
    .withMessage('Username must be between 3 and 20 characters')
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Username can only contain letters, numbers, and underscores'),
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email')
], updateProfile);

// Wallet routes
router.post('/connect-wallet', [
  body('walletAddress')
    .matches(/^0x[a-fA-F0-9]{40}$/)
    .withMessage('Invalid wallet address format'),
  body('signature')
    .notEmpty()
    .withMessage('Signature is required')
], connectWallet);
router.post('/disconnect-wallet', disconnectWallet);

// Credits and stats
router.get('/credits', getCredits);
router.get('/dashboard-stats', getDashboardStats);
router.get('/transactions', getTransactions);

// Account management
router.post('/change-password', [
  body('currentPassword').notEmpty().withMessage('Current password is required'),
  body('newPassword').isLength({ min: 6 }).withMessage('New password must be at least 6 characters long')
], changePassword);
router.delete('/account', [
  body('password').notEmpty().withMessage('Password is required to delete account')
], deleteAccount);

module.exports = router;
