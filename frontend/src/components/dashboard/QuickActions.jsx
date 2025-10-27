import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { 
  Upload, 
  CreditCard, 
  History, 
  Zap,
  FileText,
  Shield
} from 'lucide-react';
import { Button } from '../ui/Button';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/Card';
import { useAuth } from '../../hooks/useAuth';
import { useNavigate } from 'react-router-dom';
import PaymentModal from '../payment/PaymentModal';

const QuickActions = () => {
  const { credits } = useAuth();
  const navigate = useNavigate();
  const [showPaymentModal, setShowPaymentModal] = useState(false);

  const handleRunScan = () => {
    if (credits > 0) {
      // Navigate to scan upload
      navigate('/scan/new');
    } else {
      // Show payment modal
      setShowPaymentModal(true);
    }
  };

  const actions = [
    {
      title: 'Run Security Scan',
      description: 'Upload and analyze a smart contract',
      icon: Upload,
      color: 'text-blue-600',
      bgColor: 'bg-blue-50',
      borderColor: 'border-blue-200',
      action: handleRunScan,
      disabled: false
    },
    {
      title: 'View Scan History',
      description: 'Browse your previous security reports',
      icon: History,
      color: 'text-green-600',
      bgColor: 'bg-green-50',
      borderColor: 'border-green-200',
      action: () => navigate('/profile?tab=history'),
      disabled: false
    },
    {
      title: 'Buy Credits',
      description: 'Purchase additional premium scans',
      icon: CreditCard,
      color: 'text-purple-600',
      bgColor: 'bg-purple-50',
      borderColor: 'border-purple-200',
      action: () => setShowPaymentModal(true),
      disabled: false
    }
  ];

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: 0.1
      }
    }
  };

  const itemVariants = {
    hidden: { opacity: 0, y: 20 },
    visible: { 
      opacity: 1, 
      y: 0,
      transition: {
        duration: 0.5,
        ease: "easeOut"
      }
    }
  };

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Zap className="h-5 w-5 text-yellow-600" />
            Quick Actions
          </CardTitle>
        </CardHeader>
        <CardContent>
          <motion.div
            variants={containerVariants}
            initial="hidden"
            animate="visible"
            className="grid grid-cols-1 md:grid-cols-3 gap-4"
          >
            {actions.map((action, index) => (
              <motion.div
                key={action.title}
                variants={itemVariants}
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
              >
                <button
                  onClick={action.action}
                  disabled={action.disabled}
                  className={`w-full p-4 rounded-lg border-2 ${action.borderColor} ${action.bgColor} 
                    hover:shadow-md transition-all duration-200 text-left
                    ${action.disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}
                  `}
                >
                  <div className="flex items-start space-x-3">
                    <div className={`p-2 rounded-lg bg-white`}>
                      <action.icon className={`h-5 w-5 ${action.color}`} />
                    </div>
                    <div className="flex-1">
                      <h3 className="font-semibold text-gray-900 mb-1">
                        {action.title}
                      </h3>
                      <p className="text-sm text-gray-600">
                        {action.description}
                      </p>
                    </div>
                  </div>
                </button>
              </motion.div>
            ))}
          </motion.div>

          {/* Quick Stats Bar */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4 }}
            className="mt-6 pt-4 border-t border-gray-200"
          >
            <div className="flex items-center justify-between text-sm">
              <div className="flex items-center space-x-4">
                <div className="flex items-center space-x-2">
                  <Shield className="h-4 w-4 text-green-600" />
                  <span className="text-gray-600">Premium Features Active</span>
                </div>
                <div className="flex items-center space-x-2">
                  <FileText className="h-4 w-4 text-blue-600" />
                  <span className="text-gray-600">PDF & JSON Reports</span>
                </div>
              </div>
              <div className={`px-3 py-1 rounded-full text-xs font-medium
                ${credits > 5 
                  ? 'bg-green-100 text-green-700' 
                  : credits > 0 
                  ? 'bg-yellow-100 text-yellow-700'
                  : 'bg-red-100 text-red-700'
                }
              `}>
                {credits} Credits Remaining
              </div>
            </div>
          </motion.div>
        </CardContent>
      </Card>

      {/* Payment Modal */}
      <PaymentModal
        isOpen={showPaymentModal}
        onClose={() => setShowPaymentModal(false)}
        onSuccess={() => {
          setShowPaymentModal(false);
          // Refresh credits
          window.location.reload();
        }}
      />
    </>
  );
};

export default QuickActions;
