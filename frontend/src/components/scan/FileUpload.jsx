import React, { useCallback, useState } from 'react';
import { useDropzone } from 'react-dropzone';
import { motion } from 'framer-motion';
import { 
  Upload, 
  FileText, 
  X, 
  AlertCircle,
  CheckCircle,
  Code
} from 'lucide-react';
import { Button } from '../ui/Button';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/Card';
import { formatFileSize } from '../../lib/utils';

const FileUpload = ({ onFileSelect, onUpload, uploading, error }) => {
  const [selectedFile, setSelectedFile] = useState(null);
  const [preview, setPreview] = useState('');
  const [dropError, setDropError] = useState(''); // Local error state for file validation

  const onDrop = useCallback((acceptedFiles, rejectedFiles) => {
    // Clear any previous errors
    setDropError('');

    if (rejectedFiles.length > 0) {
      const rejection = rejectedFiles[0];
      const errors = rejection.errors.map(err => {
        switch (err.code) {
          case 'file-too-large':
            return 'File is too large. Maximum size is 5MB.';
          case 'file-invalid-type':
            return 'Invalid file type. Only .sol files are supported.';
          case 'too-many-files':
            return 'Only one file can be uploaded at a time.';
          default:
            return err.message;
        }
      });
      setDropError(errors.join(' '));
      return;
    }

    const file = acceptedFiles[0];
    if (file) {
      setSelectedFile(file);
      onFileSelect?.(file);

      // Read file content for preview
      const reader = new FileReader();
      reader.onload = (e) => {
        try {
          const content = e.target.result;
          setPreview(content);
        } catch (err) {
          console.error('Error reading file:', err);
          setDropError('Error reading file content.');
        }
      };
      reader.onerror = () => {
        setDropError('Error reading file.');
      };
      reader.readAsText(file);
    }
  }, [onFileSelect]);

  const { getRootProps, getInputProps, isDragActive, isDragReject } = useDropzone({
    onDrop,
    accept: {
      'text/plain': ['.sol'],
      'application/octet-stream': ['.sol']
    },
    maxFiles: 1,
    maxSize: 5 * 1024 * 1024, // 5MB
  });

  const removeFile = () => {
    setSelectedFile(null);
    setPreview('');
    setDropError(''); // Clear local errors
    onFileSelect?.(null);
  };

  const handleUpload = () => {
    if (selectedFile && !uploading) {
      setDropError(''); // Clear any previous errors
      onUpload?.(selectedFile);
    }
  };

  const truncatePreview = (content, maxLines = 20) => {
    const lines = content.split('\n');
    if (lines.length > maxLines) {
      return lines.slice(0, maxLines).join('\n') + '\n\n// ... (truncated)';
    }
    return content;
  };

  // Determine which error to show (upload error takes precedence)
  const displayError = error || dropError;

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Upload className="h-5 w-5" />
            Upload Smart Contract
          </CardTitle>
        </CardHeader>
        <CardContent>
          {!selectedFile ? (
            <>
              <motion.div
                {...getRootProps()}
                className={`border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-all ${
                  isDragActive && !isDragReject
                    ? 'border-blue-500 bg-blue-50'
                    : isDragReject
                    ? 'border-red-500 bg-red-50'
                    : displayError
                    ? 'border-red-300 bg-red-25'
                    : 'border-gray-300 hover:border-gray-400 hover:bg-gray-50'
                }`}
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
              >
                <input {...getInputProps()} />
                
                <div className="space-y-4">
                  <div className={`mx-auto w-16 h-16 rounded-full flex items-center justify-center ${
                    displayError ? 'bg-red-100' : 'bg-blue-100'
                  }`}>
                    {displayError ? (
                      <AlertCircle className="h-8 w-8 text-red-600" />
                    ) : (
                      <Upload className="h-8 w-8 text-blue-600" />
                    )}
                  </div>
                  
                  <div>
                    <h3 className={`text-lg font-semibold mb-2 ${
                      displayError ? 'text-red-900' : 'text-gray-900'
                    }`}>
                      {isDragActive 
                        ? isDragReject 
                          ? 'File type not supported' 
                          : 'Drop your Solidity file here'
                        : displayError
                        ? 'Upload Error'
                        : 'Upload Solidity Contract'
                      }
                    </h3>
                    <p className={`mb-4 ${
                      displayError ? 'text-red-600' : 'text-gray-600'
                    }`}>
                      {displayError || 'Drag and drop a .sol file, or click to browse'}
                    </p>
                  </div>

                  {!displayError && (
                    <div className="text-sm text-gray-500">
                      <p>Supported: .sol files up to 5MB</p>
                      <p>We support Solidity versions 0.4.x - 0.8.x</p>
                    </div>
                  )}
                </div>
              </motion.div>

              {/* Error Display for file validation */}
              {displayError && (
                <motion.div
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="mt-4 p-3 bg-red-50 border border-red-200 rounded-md flex items-center gap-2 text-red-600"
                >
                  <AlertCircle className="h-4 w-4 flex-shrink-0" />
                  <span className="text-sm">{displayError}</span>
                </motion.div>
              )}
            </>
          ) : (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="space-y-4"
            >
              {/* File Info */}
              <div className="flex items-center justify-between p-4 bg-green-50 border border-green-200 rounded-lg">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 bg-green-100 rounded-full flex items-center justify-center">
                    <FileText className="h-5 w-5 text-green-600" />
                  </div>
                  <div>
                    <div className="font-medium text-green-900">
                      {selectedFile.name}
                    </div>
                    <div className="text-sm text-green-700">
                      {formatFileSize(selectedFile.size)} • Solidity Contract
                    </div>
                  </div>
                </div>
                <button
                  onClick={removeFile}
                  disabled={uploading}
                  className="p-2 hover:bg-green-100 rounded-full transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <X className="h-4 w-4 text-green-600" />
                </button>
              </div>

              {/* Code Preview */}
              {preview && (
                <Card>
                  <CardHeader className="pb-3">
                    <div className="flex items-center gap-2">
                      <Code className="h-4 w-4" />
                      <span className="text-sm font-medium">Code Preview</span>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <pre className="bg-gray-900 text-gray-100 p-4 rounded-lg overflow-x-auto text-sm max-h-96 overflow-y-auto">
                      <code>{truncatePreview(preview)}</code>
                    </pre>
                  </CardContent>
                </Card>
              )}

              {/* Error Display */}
              {displayError && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="p-3 bg-red-50 border border-red-200 rounded-md flex items-center gap-2 text-red-600"
                >
                  <AlertCircle className="h-4 w-4" />
                  <span className="text-sm">{displayError}</span>
                </motion.div>
              )}

              {/* Upload Actions */}
              <div className="flex gap-3">
                <Button
                  onClick={handleUpload}
                  disabled={uploading}
                  className="flex-1"
                  size="lg"
                >
                  {uploading ? (
                    <div className="flex items-center gap-2">
                      <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                      Analyzing Contract...
                    </div>
                  ) : (
                    <div className="flex items-center gap-2">
                      <Upload className="h-4 w-4" />
                      Start Security Analysis
                    </div>
                  )}
                </Button>
                
                <Button
                  variant="outline"
                  onClick={removeFile}
                  disabled={uploading}
                  className="px-6"
                >
                  <X className="h-4 w-4 mr-2" />
                  Remove
                </Button>
              </div>
            </motion.div>
          )}

          {/* Analysis Info */}
          <div className="mt-6 p-4 bg-blue-50 border border-blue-200 rounded-lg">
            <h4 className="font-medium text-blue-900 mb-2">What happens next?</h4>
            <ul className="text-sm text-blue-700 space-y-1">
              <li>• Static analysis for common vulnerabilities</li>
              <li>• Symbolic execution for deep logic analysis</li>
              <li>• Fuzz testing for edge case detection</li>
              <li>• AI-powered intent vs. implementation analysis</li>
              <li>• Comprehensive report generation</li>
            </ul>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default FileUpload;
