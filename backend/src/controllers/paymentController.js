const User = require('../models/User');
const Transaction = require('../models/Transaction');
const logger = require('../utils/logger');
const crypto = require('crypto');

// Payment plans configuration
const PAYMENT_PLANS = {
  basic: {
    name: 'Basic Pack',
    credits: 10,
    price: 0.01, // ETH
    priceUSD: 25
  },
  pro: {
    name: 'Professional Pack',
    credits: 25,
    price: 0.02, // ETH
    priceUSD: 50
  },
  enterprise: {
    name: 'Enterprise Pack',
    credits: 100,
    price: 0.05, // ETH
    priceUSD: 125
  }
};

// @desc    Process crypto payment
// @route   POST /api/payment/crypto
// @access  Private
exports.processCryptoPayment = async (req, res) => {
  try {
    const {
      planId,
      amount,
      walletAddress,
      transactionHash
    } = req.body;

    // Validate input
    if (!planId || !amount || !walletAddress || !transactionHash) {
      return res.status(400).json({
        success: false,
        message: 'Missing required payment information'
      });
    }

    // Validate plan
    const plan = PAYMENT_PLANS[planId];
    if (!plan) {
      return res.status(400).json({
        success: false,
        message: 'Invalid payment plan'
      });
    }

    // Check if transaction already exists
    const existingTransaction = await Transaction.findOne({ transactionHash });
    if (existingTransaction) {
      return res.status(400).json({
        success: false,
        message: 'Transaction already processed'
      });
    }

    // Validate user's wallet
    const user = await User.findById(req.user.id);
    if (!user.walletAddress) {
      return res.status(400).json({
        success: false,
        message: 'No wallet connected to account'
      });
    }

    if (user.walletAddress.toLowerCase() !== walletAddress.toLowerCase()) {
      return res.status(400).json({
        success: false,
        message: 'Wallet address mismatch'
      });
    }

    // Create transaction record
    const transaction = await Transaction.create({
      user: req.user.id,
      transactionHash,
      walletAddress,
      amount,
      currency: 'ETH',
      amountUSD: plan.priceUSD,
      credits: plan.credits,
      planId,
      planName: plan.name,
      status: 'pending'
    });

    // In a real implementation, you would:
    // 1. Verify the transaction on the blockchain
    // 2. Check if the amount matches the plan price
    // 3. Wait for sufficient confirmations
    
    // For demo purposes, we'll simulate a successful payment
    setTimeout(async () => {
      try {
        await simulatePaymentConfirmation(transaction._id);
      } catch (error) {
        logger.error(`Payment confirmation error: ${error.message}`);
      }
    }, 3000); // Simulate 3 second delay

    logger.info(`Payment initiated for user ${req.user.id}: ${transaction._id}`);

    res.status(200).json({
      success: true,
      message: 'Payment initiated successfully',
      data: {
        transactionId: transaction._id,
        status: transaction.status,
        credits: plan.credits,
        estimatedConfirmationTime: '1-3 minutes'
      }
    });
  } catch (error) {
    logger.error(`Crypto payment error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error processing payment'
    });
  }
};

// @desc    Get payment status
// @route   GET /api/payment/:transactionId/status
// @access  Private
exports.getPaymentStatus = async (req, res) => {
  try {
    const transaction = await Transaction.findOne({
      _id: req.params.transactionId,
      user: req.user.id
    });

    if (!transaction) {
      return res.status(404).json({
        success: false,
        message: 'Transaction not found'
      });
    }

    res.status(200).json({
      success: true,
      data: {
        transactionId: transaction._id,
        status: transaction.status,
        transactionHash: transaction.transactionHash,
        amount: transaction.amount,
        currency: transaction.currency,
        credits: transaction.credits,
        planName: transaction.planName,
        confirmations: transaction.confirmations,
        createdAt: transaction.createdAt
      }
    });
  } catch (error) {
    logger.error(`Get payment status error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error fetching payment status'
    });
  }
};

// @desc    Get payment plans
// @route   GET /api/payment/plans
// @access  Public
exports.getPaymentPlans = async (req, res) => {
  try {
    const plans = Object.keys(PAYMENT_PLANS).map(key => ({
      id: key,
      ...PAYMENT_PLANS[key]
    }));

    res.status(200).json({
      success: true,
      data: plans
    });
  } catch (error) {
    logger.error(`Get payment plans error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error fetching payment plans'
    });
  }
};

// @desc    Payment webhook (for real blockchain integration)
// @route   POST /api/payment/webhook
// @access  Public
exports.paymentWebhook = async (req, res) => {
  try {
    // Verify webhook signature (in production)
    const signature = req.headers['x-webhook-signature'];
    if (!verifyWebhookSignature(req.body, signature)) {
      return res.status(401).json({
        success: false,
        message: 'Invalid webhook signature'
      });
    }

    const { transactionHash, status, blockNumber, gasUsed, gasPrice } = req.body;

    const transaction = await Transaction.findOne({ transactionHash });
    if (!transaction) {
      return res.status(404).json({
        success: false,
        message: 'Transaction not found'
      });
    }

    if (status === 'confirmed') {
      await transaction.confirmTransaction(blockNumber, gasUsed, gasPrice);
      logger.info(`Payment confirmed via webhook: ${transaction._id}`);
    } else if (status === 'failed') {
      await transaction.failTransaction('Blockchain transaction failed');
      logger.info(`Payment failed via webhook: ${transaction._id}`);
    }

    res.status(200).json({ success: true });
  } catch (error) {
    logger.error(`Payment webhook error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Webhook processing error'
    });
  }
};

// Simulate payment confirmation for demo purposes
const simulatePaymentConfirmation = async (transactionId) => {
  try {
    const transaction = await Transaction.findById(transactionId);
    if (!transaction) return;

    // Simulate successful payment
    await transaction.confirmTransaction(
      Math.floor(Math.random() * 1000000) + 18000000, // Mock block number
      '21000', // Mock gas used
      '20000000000' // Mock gas price
    );

    logger.info(`Payment confirmed (simulated): ${transaction._id}`);
  } catch (error) {
    logger.error(`Simulated payment confirmation error: ${error.message}`);
  }
};

// Verify webhook signature (placeholder implementation)
const verifyWebhookSignature = (payload, signature) => {
  if (!process.env.PAYMENT_WEBHOOK_SECRET) return true; // Skip verification in development
  
  const expectedSignature = crypto
    .createHmac('sha256', process.env.PAYMENT_WEBHOOK_SECRET)
    .update(JSON.stringify(payload))
    .digest('hex');
  
  return signature === `sha256=${expectedSignature}`;
};
