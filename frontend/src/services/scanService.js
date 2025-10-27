import api from '../lib/axios';

// Constants
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB
const ALLOWED_FILE_TYPES = ['.sol'];
const REQUEST_TIMEOUT = 30000; // 30 seconds
const DOWNLOAD_TIMEOUT = 60000; // 60 seconds for downloads

// Utility functions
const validateScanId = (scanId) => {
  if (!scanId || typeof scanId !== 'string' || scanId.trim().length === 0) {
    throw new Error('Invalid scan ID provided');
  }
  return scanId.trim();
};

const validateFile = (file) => {
  if (!file) throw new Error('No file provided');
  if (!(file instanceof File)) throw new Error('Invalid file object');
  if (file.size === 0) throw new Error('File is empty');
  if (file.size > MAX_FILE_SIZE)
    throw new Error(`File size exceeds maximum limit of ${MAX_FILE_SIZE / (1024 * 1024)}MB`);

  const fileName = file.name.toLowerCase();
  const hasValidExtension = ALLOWED_FILE_TYPES.some((ext) => fileName.endsWith(ext));
  if (!hasValidExtension) {
    throw new Error(`Invalid file type. Allowed types: ${ALLOWED_FILE_TYPES.join(', ')}`);
  }

  return true;
};

const validateScanType = (scanType) => {
  const validTypes = ['basic', 'premium', 'enterprise'];
  if (!validTypes.includes(scanType)) {
    throw new Error(`Invalid scan type. Valid types: ${validTypes.join(', ')}`);
  }
  return scanType;
};

const handleApiError = (error, operation = 'API request') => {
  console.error(`${operation} failed:`, error);

  if (!error.response) {
    if (error.code === 'ECONNABORTED') {
      throw new Error('Request timeout. Please check your connection and try again.');
    }
    if (error.code === 'NETWORK_ERROR') {
      throw new Error('Network error. Please check your internet connection.');
    }
    throw new Error('Unable to connect to server. Please try again later.');
  }

  const status = error.response.status;
  const data = error.response.data;

  switch (status) {
    case 400:
      throw new Error(data?.message || 'Invalid request. Please check your input.');
    case 401:
      throw new Error('Authentication required. Please log in again.');
    case 403:
      throw new Error("Access denied. You don't have permission for this action.");
    case 404:
      throw new Error('Resource not found. The scan may have been deleted.');
    case 413:
      throw new Error('File too large. Please choose a smaller file.');
    case 429:
      throw new Error('Too many requests. Please wait a moment and try again.');
    case 500:
      throw new Error(data?.message || 'Server error. Please try again later.');
    case 502:
    case 503:
    case 504:
      throw new Error('Service temporarily unavailable. Please try again later.');
    default:
      throw new Error(data?.message || `Request failed with status ${status}`);
  }
};

const validateResponse = (response, requiredFields = []) => {
  // First check if we have a response
  if (!response) throw new Error('No response received from server');
  
  // Extract data - handle both direct response and nested data structures
  let data;
  
  if (response.data) {
    // If response has axios wrapper, get the actual data
    if (response.data.data && typeof response.data.data === 'object') {
      // Backend sends: { success: true, data: { scanId: "...", status: "..." } }
      data = response.data.data;
    } else if (response.data.success !== undefined) {
      // Direct backend response: { success: true, scanId: "...", status: "..." }
      data = response.data;
    } else {
      // Fallback for other response structures
      data = response.data;
    }
  } else {
    // Direct response object
    data = response;
  }

  if (!data) throw new Error('No data received from server');

  // Map MongoDB _id to scanId if missing
  if (!data.scanId && data._id) {
    data.scanId = data._id;
  }

  // Check required fields
  for (const field of requiredFields) {
    if (!(field in data)) {
      console.error('Validation failed. Response data:', data);
      console.error('Missing field:', field);
      throw new Error(`Missing required field: ${field}`);
    }
  }

  return data;
};

export const scanService = {
  async uploadContract(file, scanType = 'premium') {
    try {
      validateFile(file);
      const validatedScanType = validateScanType(scanType);

      const formData = new FormData();
      formData.append('contract', file);
      formData.append('scanType', validatedScanType);
      formData.append('fileName', file.name);
      formData.append('fileSize', file.size.toString());
      formData.append('uploadTimestamp', Date.now().toString());

      console.log(`Uploading file: ${file.name}`);

      const response = await api.post('/scan/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
        timeout: REQUEST_TIMEOUT,
        maxBodyLength: Infinity,
        maxContentLength: Infinity,
      });

      console.log('Upload response:', response.data);

      const data = validateResponse(response, ['status']);
      
      // Ensure we have a scanId
      if (!data.scanId) {
        console.error('No scanId in response:', data);
        throw new Error('Server did not return a scan ID');
      }

      console.log('✅ Upload successful:', { scanId: data.scanId, status: data.status });
      return data;
      
    } catch (error) {
      console.error('❌ Upload error:', error);
      handleApiError(error, 'Contract upload');
      throw error;
    }
  },

  async getScanStatus(scanId) {
    try {
      const validatedScanId = validateScanId(scanId);

      const response = await api.get(`/scan/${encodeURIComponent(validatedScanId)}/status`, {
        timeout: REQUEST_TIMEOUT,
      });

      const data = validateResponse(response, ['status']);
      const validStatuses = [
        'queued', 'processing', 'compiling', 'static_analysis',
        'symbolic_execution', 'fuzz_testing', 'ai_analysis',
        'generating_report', 'completed', 'failed'
      ];
      
      if (data.status && !validStatuses.includes(data.status)) {
        console.warn(`Unknown status received: ${data.status}`);
      }

      // Ensure progress is number
      if (typeof data.progress === 'string') data.progress = parseFloat(data.progress) || 0;
      if (typeof data.progress === 'number') data.progress = Math.max(0, Math.min(100, data.progress));
      else data.progress = 0;

      return data;
    } catch (error) {
      handleApiError(error, 'Get scan status');
      throw error;
    }
  },

  async getScanReport(scanId) {
    try {
      const validatedScanId = validateScanId(scanId);

      const response = await api.get(`/scan/${encodeURIComponent(validatedScanId)}/report`, {
        timeout: REQUEST_TIMEOUT,
      });

      const data = validateResponse(response);

      if (data.vulnerabilities && !Array.isArray(data.vulnerabilities)) {
        console.warn('Vulnerabilities field is not an array, converting...');
        data.vulnerabilities = [];
      }

      return data;
    } catch (error) {
      handleApiError(error, 'Get scan report');
      throw error;
    }
  },

  async getAllScans(limit = 50, offset = 0) {
    try {
      const validatedLimit = Math.max(1, Math.min(100, parseInt(limit) || 50));
      const validatedOffset = Math.max(0, parseInt(offset) || 0);

      const response = await api.get('/scan/history', {
        params: { limit: validatedLimit, offset: validatedOffset },
        timeout: REQUEST_TIMEOUT,
      });

      const data = validateResponse(response);
      if (!Array.isArray(data.scans)) data.scans = [];
      return data;
    } catch (error) {
      handleApiError(error, 'Get scan history');
      throw error;
    }
  },

  async deleteScan(scanId) {
    try {
      const validatedScanId = validateScanId(scanId);

      const response = await api.delete(`/scan/${encodeURIComponent(validatedScanId)}`, {
        timeout: REQUEST_TIMEOUT,
      });

      return validateResponse(response);
    } catch (error) {
      handleApiError(error, 'Delete scan');
      throw error;
    }
  },

  async downloadReport(scanId, format = 'pdf') {
    try {
      const validatedScanId = validateScanId(scanId);
      const validFormats = ['pdf', 'json', 'csv', 'html'];
      if (!validFormats.includes(format.toLowerCase())) {
        throw new Error(`Invalid format. Valid formats: ${validFormats.join(', ')}`);
      }

      const response = await api.get(
        `/scan/${encodeURIComponent(validatedScanId)}/download/${encodeURIComponent(format)}`,
        { responseType: 'blob', timeout: DOWNLOAD_TIMEOUT }
      );

      if (!response.data || response.data.size === 0) {
        throw new Error('Empty file received from server');
      }

      if (response.data.type === 'application/json') {
        const text = await response.data.text();
        try {
          const errorData = JSON.parse(text);
          throw new Error(errorData.message || 'Download failed');
        } catch {}
      }

      return response.data;
    } catch (error) {
      handleApiError(error, 'Download report');
      throw error;
    }
  },

  async getVulnerabilityStats(timeRange = '30d') {
    try {
      const validRanges = ['7d', '30d', '90d', '1y', 'all'];
      if (!validRanges.includes(timeRange)) {
        throw new Error(`Invalid time range. Valid ranges: ${validRanges.join(', ')}`);
      }

      const response = await api.get('/scan/vulnerability-stats', {
        params: { timeRange },
        timeout: REQUEST_TIMEOUT,
      });

      const data = validateResponse(response);
      if (!data.stats || typeof data.stats !== 'object') {
        data.stats = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      }

      return data;
    } catch (error) {
      handleApiError(error, 'Get vulnerability statistics');
      throw error;
    }
  },

  async retryScanStatus(scanId, maxRetries = 3) {
    let lastError;
    for (let i = 0; i < maxRetries; i++) {
      try {
        return await this.getScanStatus(scanId);
      } catch (error) {
        lastError = error;
        if (error.message.includes('Invalid scan ID') ||
            error.message.includes('not found') ||
            error.message.includes('Authentication required')) {
          throw error;
        }
        if (i < maxRetries - 1) await new Promise((r) => setTimeout(r, Math.pow(2, i) * 1000));
      }
    }
    throw lastError;
  },

  async healthCheck() {
    try {
      const response = await api.get('/health', { timeout: 5000 });
      return response.data;
    } catch (error) {
      handleApiError(error, 'Health check');
      throw error;
    }
  }
};

// Export utilities for testing
export { validateScanId, validateFile, validateScanType };
