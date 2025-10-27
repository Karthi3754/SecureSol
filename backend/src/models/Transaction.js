const mongoose = require('mongoose');

const transactionSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.ObjectId,
    ref: 'User',
    required: true
  },
  transactionHash: {
    type: String,
    required: true,
    unique: true
  },
  walletAddress: {
    type: String,
    required: true
  },
  amount: {
    type: Number,
    required: true
  },
  currency: {
    type: String,
    required: true,
    default: 'ETH'
  },
  amountUSD: {
    type: Number,
    required: true
  },
  credits: {
    type: Number,
    required: true
  },
  planId: {
    type: String,
    required: true
  },
  planName: {
    type: String,
    required: true
  },
  status: {
    type: String,
    enum: ['pending', 'confirmed', 'failed', 'cancelled'],
    default: 'pending'
  },
  blockNumber: Number,
  gasUsed: String,
  gasPrice: String,
  confirmations: {
    type: Number,
    default: 0
  },
  metadata: {
    type: mongoose.Schema.Types.Mixed
  }
}, {
  timestamps: true
});

// Indexes
transactionSchema.index({ user: 1, createdAt: -1 });
transactionSchema.index({ transactionHash: 1 });
transactionSchema.index({ status: 1 });
transactionSchema.index({ walletAddress: 1 });

// Method to confirm transaction
transactionSchema.methods.confirmTransaction = async function(blockNumber, gasUsed, gasPrice) {
  this.status = 'confirmed';
  this.blockNumber = blockNumber;
  this.gasUsed = gasUsed;
  this.gasPrice = gasPrice;
  this.confirmations = 1;
  
  await this.save();
  
  // Add credits to user
  const User = mongoose.model('User');
  const user = await User.findById(this.user);
  if (user) {
    await user.addCredits(this.credits);
  }
};

// Method to fail transaction
transactionSchema.methods.failTransaction = async function(reason) {
  this.status = 'failed';
  this.metadata = { ...this.metadata, failureReason: reason };
  await this.save();
};

// Static method to get user transaction history
transactionSchema.statics.getUserTransactions = function(userId, page = 1, limit = 10) {
  return this.find({ user: userId })
    .sort({ createdAt: -1 })
    .limit(limit * 1)
    .skip((page - 1) * limit)
    .populate('user', 'username email');
};

module.exports = mongoose.model('Transaction', transactionSchema);
