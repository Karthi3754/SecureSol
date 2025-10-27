const mongoose = require('mongoose');

const vulnerabilitySchema = new mongoose.Schema({
  id: {
    type: String,
    required: true
  },
  title: {
    type: String,
    required: true
  },
  description: {
    type: String,
    required: true
  },
  severity: {
    type: String,
    enum: ['Critical', 'High', 'Medium', 'Low', 'Info'],
    required: true
  },
  category: {
    type: String,
    required: true
  },
  location: {
    line: Number,
    column: Number,
    function: String,
    contract: String
  },
  vulnerableCode: String,
  fixedCode: String,
  recommendation: String,
  impact: String,
  references: [{
    title: String,
    url: String
  }],
  confidence: {
    type: String,
    enum: ['High', 'Medium', 'Low'],
    default: 'Medium'
  }
}, { _id: false });

const scanReportSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.ObjectId,
    ref: 'User',
    required: true
  },
  contractName: {
    type: String,
    required: true
  },
  contractContent: {
    type: String,
    required: true,
    select: false // Don't return contract content by default
  },
  solidityVersion: String,
  status: {
    type: String,
    enum: ['queued', 'processing', 'completed', 'failed'],
    default: 'queued'
  },
  progress: {
    type: Number,
    default: 0,
    min: 0,
    max: 100
  },
  currentStep: {
    type: String,
    default: 'queued'
  },
  scanType: {
    type: String,
    enum: ['basic', 'premium'],
    default: 'premium'
  },
  vulnerabilities: [vulnerabilitySchema],
  analysisResults: {
    staticAnalysis: {
      completed: { type: Boolean, default: false },
      findings: [mongoose.Schema.Types.Mixed]
    },
    symbolicExecution: {
      completed: { type: Boolean, default: false },
      findings: [mongoose.Schema.Types.Mixed]
    },
    fuzzTesting: {
      completed: { type: Boolean, default: false },
      findings: [mongoose.Schema.Types.Mixed]
    },
    aiAnalysis: {
      completed: { type: Boolean, default: false },
      findings: [mongoose.Schema.Types.Mixed]
    }
  },
  securityScore: {
    type: Number,
    min: 0,
    max: 100
  },
  gasOptimization: String,
  complexityScore: String,
  functionsAnalyzed: Number,
  linesOfCode: Number,
  analysisTime: String,
  recommendations: [{
    title: String,
    description: String,
    priority: {
      type: String,
      enum: ['High', 'Medium', 'Low']
    }
  }],
  reportFiles: {
    pdf: String,
    json: String
  },
  errorMessage: String,
  analyzerResponse: {
    type: mongoose.Schema.Types.Mixed,
    select: false
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes
scanReportSchema.index({ user: 1, createdAt: -1 });
scanReportSchema.index({ status: 1 });
scanReportSchema.index({ scanType: 1 });

// Virtual for vulnerability count by severity
scanReportSchema.virtual('vulnerabilityStats').get(function() {
  const stats = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  
  this.vulnerabilities.forEach(vuln => {
    const severity = vuln.severity.toLowerCase();
    if (stats.hasOwnProperty(severity)) {
      stats[severity]++;
    }
  });
  
  return stats;
});

// Method to update scan progress
scanReportSchema.methods.updateProgress = async function(progress, step) {
  this.progress = progress;
  this.currentStep = step;
  await this.save();
};

// Method to complete scan
scanReportSchema.methods.completeScan = async function(results) {
  this.status = 'completed';
  this.progress = 100;
  this.currentStep = 'completed';
  this.vulnerabilities = results.vulnerabilities || [];
  this.securityScore = results.securityScore;
  this.analysisResults = results.analysisResults;
  this.gasOptimization = results.gasOptimization;
  this.complexityScore = results.complexityScore;
  this.functionsAnalyzed = results.functionsAnalyzed;
  this.linesOfCode = results.linesOfCode;
  this.analysisTime = results.analysisTime;
  this.recommendations = results.recommendations || [];
  this.analyzerResponse = results;
  
  await this.save();
};

// Method to fail scan
scanReportSchema.methods.failScan = async function(errorMessage) {
  this.status = 'failed';
  this.errorMessage = errorMessage;
  await this.save();
};

// Method to get vulnerability summary
scanReportSchema.methods.getVulnerabilitySummary = function() {
  const summary = {
    total: this.vulnerabilities.length,
    bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    byCategory: {}
  };

  this.vulnerabilities.forEach(vuln => {
    // Count by severity
    const severity = vuln.severity.toLowerCase();
    if (summary.bySeverity.hasOwnProperty(severity)) {
      summary.bySeverity[severity]++;
    }

    // Count by category
    if (!summary.byCategory[vuln.category]) {
      summary.byCategory[vuln.category] = 0;
    }
    summary.byCategory[vuln.category]++;
  });

  return summary;
};

module.exports = mongoose.model('ScanReport', scanReportSchema);
