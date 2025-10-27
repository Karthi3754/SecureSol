import React, { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { 
  Clock, 
  CheckCircle, 
  AlertCircle, 
  Loader2,
  FileText,
  Shield,
  Zap,
  Brain
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/Card';
import { scanService } from '../../services/scanService';

const ScanStatusIndicator = ({ scanId, onComplete, onError }) => {
  const [status, setStatus] = useState('queued');
  const [progress, setProgress] = useState(0);
  const [currentStep, setCurrentStep] = useState('');
  const [startTime, setStartTime] = useState(Date.now());
  const [elapsedTime, setElapsedTime] = useState(0);

  const steps = [
    { id: 'queued', label: 'Queued', icon: Clock, description: 'Scan request received' },
    { id: 'compiling', label: 'Compiling', icon: FileText, description: 'Compiling Solidity code' },
    { id: 'static_analysis', label: 'Static Analysis', icon: Shield, description: 'Analyzing code structure' },
    { id: 'symbolic_execution', label: 'Symbolic Execution', icon: Zap, description: 'Deep logic analysis' },
    { id: 'fuzz_testing', label: 'Fuzz Testing', icon: Brain, description: 'Testing edge cases' },
    { id: 'ai_analysis', label: 'AI Analysis', icon: Brain, description: 'Intent detection' },
    { id: 'generating_report', label: 'Generating Report', icon: FileText, description: 'Creating final report' },
    { id: 'completed', label: 'Completed', icon: CheckCircle, description: 'Analysis complete' }
  ];

  useEffect(() => {
    if (!scanId) return;

    const pollStatus = async () => {
      try {
        const response = await scanService.getScanStatus(scanId);
        setStatus(response.status);
        setProgress(response.progress || 0);
        setCurrentStep(response.currentStep || '');

        if (response.status === 'completed') {
          onComplete?.(response);
          return false; // Stop polling
        } else if (response.status === 'failed') {
          onError?.(response.error || 'Scan failed');
          return false; // Stop polling
        }
        return true; // Continue polling
      } catch (error) {
        console.error('Error polling scan status:', error);
        onError?.(error.message);
        return false; // Stop polling
      }
    };

    const interval = setInterval(async () => {
      const shouldContinue = await pollStatus();
      if (!shouldContinue) {
        clearInterval(interval);
      }
    }, 2000);

    // Initial poll
    pollStatus();

    return () => clearInterval(interval);
  }, [scanId, onComplete, onError]);

  useEffect(() => {
    const timer = setInterval(() => {
      setElapsedTime(Date.now() - startTime);
    }, 1000);

    return () => clearInterval(timer);
  }, [startTime]);

  const formatTime = (ms) => {
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    return `${minutes}:${remainingSeconds.toString().padStart(2, '0')}`;
  };

  const getCurrentStepIndex = () => {
    return steps.findIndex(step => step.id === status || step.id === currentStep);
  };

  const currentStepIndex = getCurrentStepIndex();

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Loader2 className={`h-5 w-5 ${status === 'completed' ? 'text-green-600' : status === 'failed' ? 'text-red-600' : 'text-blue-600 animate-spin'}`} />
            Security Analysis Progress
          </div>
          <div className="text-sm text-gray-600">
            {formatTime(elapsedTime)}
          </div>
        </CardTitle>
      </CardHeader>
      
      <CardContent className="space-y-6">
        {/* Overall Progress Bar */}
        <div className="space-y-2">
          <div className="flex justify-between text-sm">
            <span className="text-gray-600">Overall Progress</span>
            <span className="font-medium">{Math.round(progress)}%</span>
          </div>
          <div className="w-full bg-gray-200 rounded-full h-2">
            <motion.div
              className={`h-2 rounded-full ${
                status === 'completed' ? 'bg-green-600' : 
                status === 'failed' ? 'bg-red-600' : 
                'bg-blue-600'
              }`}
              initial={{ width: 0 }}
              animate={{ width: `${progress}%` }}
              transition={{ duration: 0.5, ease: "easeOut" }}
            />
          </div>
        </div>

        {/* Step Indicator */}
        <div className="space-y-4">
          {steps.map((step, index) => {
            const isActive = index === currentStepIndex;
            const isCompleted = index < currentStepIndex || status === 'completed';
            const isFailed = status === 'failed' && isActive;
            
            return (
              <motion.div
                key={step.id}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: index * 0.1 }}
                className={`flex items-center gap-4 p-3 rounded-lg transition-all ${
                  isActive && !isFailed ? 'bg-blue-50 border border-blue-200' : 
                  isCompleted ? 'bg-green-50 border border-green-200' :
                  isFailed ? 'bg-red-50 border border-red-200' :
                  'bg-gray-50 border border-gray-200'
                }`}
              >
                <div className={`flex-shrink-0 w-10 h-10 rounded-full flex items-center justify-center ${
                  isActive && !isFailed ? 'bg-blue-100' : 
                  isCompleted ? 'bg-green-100' :
                  isFailed ? 'bg-red-100' :
                  'bg-gray-100'
                }`}>
                  {isActive && !isFailed ? (
                    <motion.div
                      animate={{ rotate: 360 }}
                      transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
                    >
                      <step.icon className="h-5 w-5 text-blue-600" />
                    </motion.div>
                  ) : isCompleted ? (
                    <CheckCircle className="h-5 w-5 text-green-600" />
                  ) : isFailed ? (
                    <AlertCircle className="h-5 w-5 text-red-600" />
                  ) : (
                    <step.icon className="h-5 w-5 text-gray-400" />
                  )}
                </div>
                
                <div className="flex-1">
                  <div className={`font-medium ${
                    isActive && !isFailed ? 'text-blue-900' : 
                    isCompleted ? 'text-green-900' :
                    isFailed ? 'text-red-900' :
                    'text-gray-500'
                  }`}>
                    {step.label}
                  </div>
                  <div className={`text-sm ${
                    isActive && !isFailed ? 'text-blue-700' : 
                    isCompleted ? 'text-green-700' :
                    isFailed ? 'text-red-700' :
                    'text-gray-500'
                  }`}>
                    {step.description}
                  </div>
                </div>

                {/* Status Indicator */}
                <div className="flex-shrink-0">
                  {isActive && !isFailed && (
                    <div className="flex items-center gap-2">
                      <div className="w-2 h-2 bg-blue-600 rounded-full animate-pulse" />
                      <span className="text-xs text-blue-600 font-medium">Running</span>
                    </div>
                  )}
                  {isCompleted && (
                    <span className="text-xs text-green-600 font-medium">Done</span>
                  )}
                  {isFailed && (
                    <span className="text-xs text-red-600 font-medium">Failed</span>
                  )}
                </div>
              </motion.div>
            );
          })}
        </div>

        {/* Status Messages */}
        {status === 'completed' && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="p-4 bg-green-50 border border-green-200 rounded-lg"
          >
            <div className="flex items-center gap-2 text-green-600 mb-2">
              <CheckCircle className="h-5 w-5" />
              <span className="font-medium">Analysis Complete!</span>
            </div>
            <p className="text-sm text-green-700">
              Your smart contract has been thoroughly analyzed. The security report is now ready for review.
            </p>
          </motion.div>
        )}

        {status === 'failed' && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="p-4 bg-red-50 border border-red-200 rounded-lg"
          >
            <div className="flex items-center gap-2 text-red-600 mb-2">
              <AlertCircle className="h-5 w-5" />
              <span className="font-medium">Analysis Failed</span>
            </div>
            <p className="text-sm text-red-700">
              There was an error analyzing your contract. Please try uploading again or contact support if the issue persists.
            </p>
          </motion.div>
        )}

        {['processing', 'queued'].includes(status) && (
          <div className="p-4 bg-blue-50 border border-blue-200 rounded-lg">
            <div className="flex items-center gap-2 text-blue-600 mb-2">
              <Loader2 className="h-5 w-5 animate-spin" />
              <span className="font-medium">
                {status === 'queued' ? 'Scan Queued' : 'Analysis in Progress'}
              </span>
            </div>
            <p className="text-sm text-blue-700">
              {status === 'queued' 
                ? 'Your scan is in the queue and will begin shortly.'
                : 'Our security engines are analyzing your smart contract. This typically takes 2-5 minutes.'
              }
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
};

export default ScanStatusIndicator;
