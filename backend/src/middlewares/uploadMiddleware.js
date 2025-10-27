const multer = require('multer');
const path = require('path');
const fs = require('fs');
const config = require('../config');
const logger = require('../utils/logger');

// Ensure upload directory exists
const ensureUploadDir = (dir) => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
};

// Configure storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = path.join(config.UPLOAD_PATH, 'contracts');
    ensureUploadDir(uploadPath);
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    // Generate unique filename
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const filename = `contract-${req.user.id}-${uniqueSuffix}${path.extname(file.originalname)}`;
    cb(null, filename);
  }
});

// File filter function
const fileFilter = (req, file, cb) => {
  // Check file extension
  const allowedExtensions = ['.sol', '.txt'];
  const fileExtension = path.extname(file.originalname).toLowerCase();
  
  if (allowedExtensions.includes(fileExtension)) {
    cb(null, true);
  } else {
    cb(new Error('Only Solidity (.sol) files are allowed'), false);
  }
};

// Configure multer
const upload = multer({
  storage: storage,
  limits: {
    fileSize: config.MAX_FILE_SIZE, // 5MB default
    files: 1 // Only allow single file upload
  },
  fileFilter: fileFilter
});

// Middleware for single contract file upload
exports.uploadContract = (req, res, next) => {
  const uploadSingle = upload.single('contract');
  
  uploadSingle(req, res, (err) => {
    if (err instanceof multer.MulterError) {
      logger.error(`Multer error: ${err.message}`);
      
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({
          success: false,
          message: 'File too large. Maximum size is 5MB.'
        });
      }
      
      if (err.code === 'LIMIT_FILE_COUNT') {
        return res.status(400).json({
          success: false,
          message: 'Too many files. Only one file allowed.'
        });
      }
      
      return res.status(400).json({
        success: false,
        message: `Upload error: ${err.message}`
      });
    } else if (err) {
      logger.error(`Upload error: ${err.message}`);
      return res.status(400).json({
        success: false,
        message: err.message
      });
    }
    
    // Check if file was uploaded
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: 'No file uploaded. Please select a Solidity (.sol) file.'
      });
    }
    
    // Validate file content
    try {
      const fileContent = fs.readFileSync(req.file.path, 'utf8');
      
      // Basic validation for Solidity content
      if (!fileContent.includes('pragma solidity') && !fileContent.includes('contract')) {
        // Clean up uploaded file
        fs.unlinkSync(req.file.path);
        
        return res.status(400).json({
          success: false,
          message: 'Invalid Solidity file. File must contain pragma statement or contract definition.'
        });
      }
      
      // Add file content to request for processing
      req.fileContent = fileContent;
      
    } catch (error) {
      logger.error(`File validation error: ${error.message}`);
      
      // Clean up uploaded file
      if (fs.existsSync(req.file.path)) {
        fs.unlinkSync(req.file.path);
      }
      
      return res.status(400).json({
        success: false,
        message: 'Error reading uploaded file'
      });
    }
    
    logger.info(`File uploaded successfully: ${req.file.filename} by user ${req.user.id}`);
    next();
  });
};

// Middleware to clean up uploaded files after processing
exports.cleanupFile = (req, res, next) => {
  // Store original end function
  const originalEnd = res.end;
  
  // Override end function to cleanup file
  res.end = function(chunk, encoding) {
    // Call original end function
    originalEnd.call(this, chunk, encoding);
    
    // Clean up uploaded file
    if (req.file && req.file.path && fs.existsSync(req.file.path)) {
      try {
        fs.unlinkSync(req.file.path);
        logger.info(`Cleaned up uploaded file: ${req.file.filename}`);
      } catch (error) {
        logger.error(`Error cleaning up file: ${error.message}`);
      }
    }
  };
  
  next();
};

// Middleware for report file uploads (PDF, JSON)
const reportStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const reportsPath = path.join(config.UPLOAD_PATH, 'reports');
    ensureUploadDir(reportsPath);
    cb(null, reportsPath);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, `report-${uniqueSuffix}${path.extname(file.originalname)}`);
  }
});

exports.uploadReport = multer({
  storage: reportStorage,
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB for reports
  }
});
