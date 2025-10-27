const express = require('express');
const { 
  uploadContract, 
  getScanStatus, 
  getScanReport, 
  getScanHistory, 
  downloadReport, 
  deleteScan, 
  getVulnerabilityStats 
} = require('../controllers/scanController');

const { protect, checkCredits } = require('../middlewares/authMiddleware');
const { uploadContract: uploadMiddleware, cleanupFile } = require('../middlewares/uploadMiddleware');

const router = express.Router();

// All routes are protected
router.use(protect);

// Upload route
router.post(
  '/upload',
  checkCredits(1), // Ensure user has at least 1 credit for premium scans
  uploadMiddleware,
  cleanupFile,
  uploadContract
);

// Static routes first
router.get('/history', getScanHistory);
router.get('/vulnerability-stats', getVulnerabilityStats);

// Dynamic routes
router.get('/:id/status', getScanStatus);
router.get('/:id/report', getScanReport);
router.get('/:id/download/:format', downloadReport);
router.delete('/:id', deleteScan);

module.exports = router;
