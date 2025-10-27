const mongoose = require('mongoose');
const ScanReport = require('../models/ScanReport');
const User = require('../models/User');
const analyzerApiService = require('../services/analyzerApiService');
const reportGeneratorService = require('../services/reportGeneratorService');
const logger = require('../utils/logger');
const fs = require('fs').promises;

// @desc    Upload contract and start scan
// @route   POST /api/scan/upload
// @access  Private
exports.uploadContract = async (req, res) => {
  try {
    const { scanType = 'premium' } = req.body;

    if (!req.file) {
      return res.status(400).json({ success: false, message: 'No contract file uploaded' });
    }

    // Check user credits
    if (scanType === 'premium' && req.user.credits < 1) {
      return res.status(402).json({
        success: false,
        message: 'Insufficient credits for premium scan',
        data: { currentCredits: req.user.credits, requiredCredits: 1 }
      });
    }

    // Extract contract name
    const contractName = req.file.originalname.replace(/\.[^/.]+$/, '');

    // ✅ Safely handle both memoryStorage and diskStorage
    let contractContent = '';
    if (req.file.buffer) {
      // memory storage
      contractContent = req.file.buffer.toString('utf8');
    } else if (req.file.path) {
      // disk storage
      contractContent = await fs.readFile(req.file.path, 'utf-8');
    } else {
      throw new Error('Uploaded file is missing buffer and path');
    }

    // Create scan report
    const scanReport = await ScanReport.create({
      user: req.user._id,
      contractName,
      contractContent,
      scanType,
      status: 'queued',
      progress: 0
    });

    // Deduct credits if premium
    if (scanType === 'premium') {
      req.user.credits -= 1;
      await req.user.save();
    }

    // Increment total scans
    req.user.totalScans = (req.user.totalScans || 0) + 1;
    await req.user.save();

    // Start analysis in background
    processContractAnalysis(scanReport._id, contractContent, scanType);

    logger.info(`Scan started for user ${req.user._id}: ${scanReport._id}`);

    return res.status(201).json({
      success: true,
      message: 'Contract uploaded successfully. Analysis started.',
      data: {
        scanId: scanReport._id,
        status: scanReport.status,
        progress: scanReport.progress,
        scanType: scanReport.scanType,
        contractName: scanReport.contractName,
        estimatedTime: '2-5 minutes'
      }
    });
  } catch (error) {
    logger.error(`Upload contract error: ${error.message}`);
    return res.status(500).json({ success: false, message: 'Error uploading contract' });
  }
};


// @desc    Get scan status
// @route   GET /api/scan/:id/status
// @access  Private
exports.getScanStatus = async (req, res) => {
  try {
    const { id } = req.params;

    if (id === 'new') {
      return res.status(200).json({
        success: true,
        data: { status: 'ready', message: 'Ready to start new scan' }
      });
    }

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: 'Invalid scan ID format' });
    }

    const scanReport = await ScanReport.findOne({ _id: id, user: req.user._id });
    if (!scanReport) {
      return res.status(404).json({ success: false, message: 'Scan not found' });
    }

    return res.status(200).json({
      success: true,
      data: {
        scanId: scanReport._id,
        status: scanReport.status,
        progress: scanReport.progress,
        currentStep: scanReport.currentStep,
        errorMessage: scanReport.errorMessage
      }
    });
  } catch (error) {
    logger.error(`Get scan status error: ${error.message}`);
    return res.status(500).json({ success: false, message: 'Error fetching scan status' });
  }
};

// @desc    Get scan report
// @route   GET /api/scan/:id/report
// @access  Private
exports.getScanReport = async (req, res) => {
  try {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: 'Invalid scan ID format' });
    }

    const scanReport = await ScanReport.findOne({ _id: id, user: req.user._id });
    if (!scanReport) {
      return res.status(404).json({ success: false, message: 'Scan report not found' });
    }

    if (scanReport.status !== 'completed') {
      return res.status(400).json({ success: false, message: 'Scan is not completed yet' });
    }

    return res.status(200).json({
      success: true,
      data: {
        id: scanReport._id,
        contractName: scanReport.contractName,
        status: scanReport.status,
        scanType: scanReport.scanType,
        vulnerabilities: scanReport.vulnerabilities || [],
        securityScore: scanReport.securityScore,
        vulnerabilityStats: scanReport.vulnerabilityStats,
        gasOptimization: scanReport.gasOptimization,
        complexityScore: scanReport.complexityScore,
        functionsAnalyzed: scanReport.functionsAnalyzed,
        linesOfCode: scanReport.linesOfCode,
        analysisTime: scanReport.analysisTime,
        recommendations: scanReport.recommendations,
        solidityVersion: scanReport.solidityVersion,
        createdAt: scanReport.createdAt,
        updatedAt: scanReport.updatedAt
      }
    });
  } catch (error) {
    logger.error(`Get scan report error: ${error.message}`);
    return res.status(500).json({ success: false, message: 'Error fetching scan report' });
  }
};

// @desc    Get user's scan history
// @route   GET /api/scan/history
// @access  Private
exports.getScanHistory = async (req, res) => {
  try {
    const page = parseInt(req.query.page, 10) || 1;
    const limit = parseInt(req.query.limit, 10) || 10;
    const status = req.query.status;

    const query = { user: req.user._id };
    if (status) query.status = status;

    const scans = await ScanReport.find(query)
      .sort({ createdAt: -1 })
      .limit(limit)
      .skip((page - 1) * limit)
      .select('-contractContent -analyzerResponse');

    const total = await ScanReport.countDocuments(query);

    return res.status(200).json({
      success: true,
      data: scans,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) }
    });
  } catch (error) {
    logger.error(`Get scan history error: ${error.message}`);
    return res.status(500).json({ success: false, message: 'Error fetching scan history' });
  }
};

// @desc    Download scan report
// @route   GET /api/scan/:id/download/:format
// @access  Private
exports.downloadReport = async (req, res) => {
  try {
    const { id, format } = req.params;
    if (!['pdf', 'json'].includes(format)) {
      return res.status(400).json({ success: false, message: 'Invalid format. Supported formats: pdf, json' });
    }

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: 'Invalid scan ID format' });
    }

    const scanReport = await ScanReport.findOne({ _id: id, user: req.user._id });
    if (!scanReport) return res.status(404).json({ success: false, message: 'Scan report not found' });
    if (scanReport.status !== 'completed') {
      return res.status(400).json({ success: false, message: 'Scan is not completed yet' });
    }

    let reportBuffer = await reportGeneratorService.generateReport(scanReport, format);
    if (typeof reportBuffer === 'string') reportBuffer = Buffer.from(reportBuffer);

    const filename = `security-report-${scanReport._id}.${format}`;
    const mimeType = format === 'pdf' ? 'application/pdf' : 'application/json';

    res.setHeader('Content-Type', mimeType);
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Length', reportBuffer.length);

    return res.send(reportBuffer);
  } catch (error) {
    logger.error(`Download report error: ${error.message}`);
    return res.status(500).json({ success: false, message: 'Error downloading report' });
  }
};

// @desc    Delete scan
// @route   DELETE /api/scan/:id
// @access  Private
exports.deleteScan = async (req, res) => {
  try {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: 'Invalid scan ID format' });
    }

    const scanReport = await ScanReport.findOne({ _id: id, user: req.user._id });
    if (!scanReport) return res.status(404).json({ success: false, message: 'Scan not found' });

    await ScanReport.findByIdAndDelete(id);
    logger.info(`Scan deleted: ${id} by user ${req.user._id}`);

    return res.status(200).json({ success: true, message: 'Scan deleted successfully' });
  } catch (error) {
    logger.error(`Delete scan error: ${error.message}`);
    return res.status(500).json({ success: false, message: 'Error deleting scan' });
  }
};

// @desc    Get vulnerability statistics
// @route   GET /api/scan/vulnerability-stats
// @access  Private
exports.getVulnerabilityStats = async (req, res) => {
  try {
    const scans = await ScanReport.find({ user: req.user._id, status: 'completed' }).select('vulnerabilities');

    const stats = {
      totalVulnerabilities: 0,
      byType: {},
      bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      trend: 0
    };

    scans.forEach(scan => {
      (scan.vulnerabilities || []).forEach(vuln => {
        stats.totalVulnerabilities++;
        if (!stats.byType[vuln.title]) stats.byType[vuln.title] = { name: vuln.title, count: 0, severity: vuln.severity };
        stats.byType[vuln.title].count++;
        const severity = vuln.severity.toLowerCase();
        if (stats.bySeverity[severity] !== undefined) stats.bySeverity[severity]++;
      });
    });

    stats.byType = Object.values(stats.byType);
    stats.bySeverity = [
      { name: 'Critical', count: stats.bySeverity.critical, color: '#dc2626' },
      { name: 'High', count: stats.bySeverity.high, color: '#ea580c' },
      { name: 'Medium', count: stats.bySeverity.medium, color: '#ca8a04' },
      { name: 'Low', count: stats.bySeverity.low, color: '#2563eb' },
      { name: 'Info', count: stats.bySeverity.info, color: '#6b7280' }
    ];

    return res.status(200).json({ success: true, data: stats });
  } catch (error) {
    logger.error(`Get vulnerability stats error: ${error.message}`);
    return res.status(500).json({ success: false, message: 'Error fetching vulnerability statistics' });
  }
};

// Background contract analysis
const processContractAnalysis = async (scanId, contractContent, scanType) => {
  try {
    const scanReport = await ScanReport.findById(scanId);
    if (!scanReport) return;

    await scanReport.updateProgress(5, 'processing');

    const analysisResult = await analyzerApiService.analyzeContract({
      contractContent,
      scanType,
      contractName: scanReport.contractName
    });

    await scanReport.completeScan(analysisResult);
    logger.info(`Scan completed: ${scanId}`);
  } catch (error) {
    logger.error(`Analysis processing error for scan ${scanId}: ${error.message}`);
    const scanReport = await ScanReport.findById(scanId);
    if (scanReport) await scanReport.failScan(error.message);
  }
};
