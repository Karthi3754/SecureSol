const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('../config');
 
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: [true, 'Please provide a username'],
    unique: true,
    trim: true,
    minlength: [3, 'Username must be at least 3 characters'],
    maxlength: [20, 'Username cannot exceed 20 characters']
  },
  email: {
    type: String,
    required: [true, 'Please provide an email'],
    unique: true,
    lowercase: true,
    match: [
      /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/,
      'Please provide a valid email'
    ]
  },
  password: {
    type: String,
    required: [true, 'Please provide a password'],
    minlength: [6, 'Password must be at least 6 characters'],
    select: false
  },
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user'
  },
  credits: {
    type: Number,
    default: 3, // New users get 3 free premium scans
    min: 0
  },
  walletAddress: {
    type: String,
    unique: true,
    sparse: true,
    default: undefined   // ✅ avoids duplicate null errors
  },
  isEmailVerified: {
    type: Boolean,
    default: false
  },
  emailVerificationToken: String,
  passwordResetToken: String,
  passwordResetExpires: Date,
  lastLogin: Date,
  totalScans: {
    type: Number,
    default: 0
  },
  plan: {
    type: String,
    enum: ['free', 'basic', 'pro', 'enterprise'],
    default: 'free'
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes
userSchema.index({ email: 1 });
userSchema.index({ username: 1 });
userSchema.index({ walletAddress: 1 }, { unique: true, sparse: true }); // ✅ safe unique index

// Virtual for user's scan reports
userSchema.virtual('scanReports', {
  ref: 'ScanReport',
  localField: '_id',
  foreignField: 'user',
  justOne: false
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next(); // ✅ prevent double-calling next()

  const salt = await bcrypt.genSalt(12);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// Update lastLogin on first save
userSchema.pre('save', function(next) {
  if (this.isNew) {
    this.lastLogin = Date.now();
  }
  next();
});

// Compare password
userSchema.methods.matchPassword = async function(enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

// Generate JWT token
userSchema.methods.getSignedJwtToken = function() {
  return jwt.sign(
    {
      id: this._id,
      email: this.email,
      role: this.role
    },
    config.JWT_SECRET,
    { expiresIn: config.JWT_EXPIRE }
  );
};

// Generate refresh token
userSchema.methods.getRefreshToken = function() {
  return jwt.sign(
    { id: this._id },
    config.JWT_REFRESH_SECRET,
    { expiresIn: config.JWT_REFRESH_EXPIRE }
  );
};

// Deduct credits
userSchema.methods.deductCredits = async function(amount = 1) {
  if (this.credits >= amount) {
    this.credits -= amount;
    await this.save();
    return true;
  }
  return false;
};

// Add credits
userSchema.methods.addCredits = async function(amount) {
  this.credits += amount;
  await this.save();
};

// Check if user has sufficient credits
userSchema.methods.hasCredits = function(amount = 1) {
  return this.credits >= amount;
};

// Get user dashboard stats
userSchema.methods.getDashboardStats = async function() {
  const ScanReport = mongoose.model('ScanReport');
  const reports = await ScanReport.find({ user: this._id });
  const completedReports = reports.filter(r => r.status === 'completed');

  let totalVulnerabilities = 0;
  completedReports.forEach(r => {
    totalVulnerabilities += r.vulnerabilities ? r.vulnerabilities.length : 0;
  });

  return {
    totalScans: reports.length,
    completedScans: completedReports.length,
    vulnerabilitiesFound: totalVulnerabilities,
    contractsSecured: completedReports.length,
    lastScanDate: reports.length > 0 ? reports[reports.length - 1].createdAt : null
  };
};

module.exports = mongoose.model('User', userSchema);
