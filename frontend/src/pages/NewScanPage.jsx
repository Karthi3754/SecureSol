import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import FileUpload from '../components/scan/FileUpload';
import ScanStatusIndicator from '../components/scan/ScanStatusIndicator';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/Card';
import { scanService } from '../services/scanService'; // Fixed import

const NewScanPage = () => {
  const [selectedFile, setSelectedFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [scanId, setScanId] = useState(null);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleFileSelect = (file) => {
    setSelectedFile(file);
    setError('');
  };

  const handleUpload = async (file) => {
    if (!file) {
      setError('No file selected');
      return;
    }

    setUploading(true);
    setError('');

    try {
      // Upload and start analysis - pass the file directly, not FormData
      console.log('🔍 Uploading file:', file.name);
      
      // The scanService.uploadContract method expects (file, scanType)
      // It will create the FormData internally
      const response = await scanService.uploadContract(file, 'premium');
      
      console.log('📤 Upload response:', response);

      // Check if response contains scanId directly
      if (response && response.scanId) {
        setScanId(response.scanId);
        console.log('✅ Scan started with ID:', response.scanId);
      } else if (response && response.data && response.data.scanId) {
        setScanId(response.data.scanId);
        console.log('✅ Scan started with ID:', response.data.scanId);
      } else {
        setError('Upload succeeded but no scan ID received');
      }
    } catch (err) {
      console.error('❌ Upload error:', err);
      setError(err.message || 'Upload failed. Please try again.');
    } finally {
      setUploading(false);
    }
  };

  const handleScanComplete = (result) => {
  console.log('🎉 Scan completed:', result);
  
  // Use scanId from result if available, otherwise use state scanId
  const resultScanId = result?.scanId || scanId;
  
  if (resultScanId) {
    console.log('🚀 Navigating to results page with scanId:', resultScanId);
    navigate(`/scan/${resultScanId}/results`);
  } else {
    console.error('❌ No scanId available for navigation');
    setError('Cannot navigate to results - missing scan ID');
  }
};


  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="space-y-8"
        >
          {/* Header */}
          <div className="text-center">
            <h1 className="text-3xl font-bold text-gray-900 mb-4">
              Smart Contract Security Analysis
            </h1>
            <p className="text-lg text-gray-600">
              Upload your Solidity contract for comprehensive security analysis
            </p>
          </div>

          {/* File Upload */}
          <FileUpload
            onFileSelect={handleFileSelect}
            onUpload={handleUpload}
            uploading={uploading}
            error={error}
          />

          {/* Scan Status */}
          {scanId && (
            <Card>
              <CardHeader>
                <CardTitle>Analysis Progress</CardTitle>
              </CardHeader>
              <CardContent>
                <ScanStatusIndicator 
                  scanId={scanId} 
                  onComplete={handleScanComplete}
                />
              </CardContent>
            </Card>
          )}
        </motion.div>
      </div>
    </div>
  );
};

export default NewScanPage;
