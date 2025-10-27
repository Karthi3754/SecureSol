import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { ArrowLeft, RefreshCw } from 'lucide-react';
import { Button } from '../components/ui/Button';
import ScanStatusIndicator from '../components/scan/ScanStatusIndicator';
import ReportView from '../components/scan/ReportView';
import { scanService } from '../services/scanService';

const ScanResultsPage = () => {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const [scanStatus, setScanStatus] = useState('processing');
  const [reportData, setReportData] = useState(null);
  const [error, setError] = useState(null);

  const handleScanComplete = (response) => {
    setScanStatus('completed');
    setReportData(response.report);
  };

  const handleScanError = (errorMessage) => {
    setScanStatus('failed');
    setError(errorMessage);
  };

  const refreshScan = async () => {
    try {
      const response = await scanService.getScanStatus(scanId);
      setScanStatus(response.status);
      if (response.status === 'completed') {
        const reportResponse = await scanService.getScanReport(scanId);
        setReportData(reportResponse);
      }
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="space-y-6"
        >
          {/* Header */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <Button
                variant="outline"
                onClick={() => navigate('/dashboard')}
                className="flex items-center gap-2"
              >
                <ArrowLeft className="h-4 w-4" />
                Back to Dashboard
              </Button>
              <div>
                <h1 className="text-3xl font-bold text-gray-900">
                  Security Analysis Results
                </h1>
                <p className="text-gray-600">
                  Scan ID: {scanId}
                </p>
              </div>
            </div>
            
            {scanStatus !== 'completed' && (
              <Button
                variant="outline"
                onClick={refreshScan}
                className="flex items-center gap-2"
              >
                <RefreshCw className="h-4 w-4" />
                Refresh
              </Button>
            )}
          </div>

          {/* Content */}
          {scanStatus === 'completed' ? (
            <ReportView scanId={scanId} />
          ) : (
            <ScanStatusIndicator
              scanId={scanId}
              onComplete={handleScanComplete}
              onError={handleScanError}
            />
          )}

          {/* Error State */}
          {error && scanStatus === 'failed' && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="bg-red-50 border border-red-200 rounded-lg p-6 text-center"
            >
              <h3 className="text-lg font-semibold text-red-900 mb-2">
                Analysis Failed
              </h3>
              <p className="text-red-700 mb-4">{error}</p>
              <div className="flex gap-3 justify-center">
                <Button
                  variant="outline"
                  onClick={() => navigate('/dashboard')}
                >
                  Back to Dashboard
                </Button>
                <Button onClick={refreshScan}>
                  Try Again
                </Button>
              </div>
            </motion.div>
          )}
        </motion.div>
      </div>
    </div>
  );
};

export default ScanResultsPage;
