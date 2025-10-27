const express = require('express');
const { body } = require('express-validator');
const {
  processCryptoPayment,
  getPaymentStatus,
  getPaymentPlans,
  paymentWebhook
} = require('../controllers/paymentController');
const { protect } = require('../middlewares/authMiddleware');

const router = express.Router();

// Public routes
router.get('/plans', getPaymentPlans);
router.post('/webhook', paymentWebhook); // Webhook for payment confirmations

// Protected routes
router.use(protect);

router.post('/crypto', [
  body('planId')
    .isIn(['basic', 'pro', 'enterprise'])
    .withMessage('Invalid plan ID'),
  body('amount')
    .isFloat({ min: 0 })
    .withMessage('Amount must be a positive number'),
  body('walletAddress')
    .matches(/^0x[a-fA-F0-9]{40}$/)
    .withMessage('Invalid wallet address format'),
  body('transactionHash')
    .matches(/^0x[a-fA-F0-9]{64}$/)
    .withMessage('Invalid transaction hash format')
], processCryptoPayment);

router.get('/:transactionId/status', getPaymentStatus);

module.exports = router;
