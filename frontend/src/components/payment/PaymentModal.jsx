import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  X, 
  CreditCard, 
  Zap, 
  CheckCircle,
  AlertCircle,
  Loader2 
} from 'lucide-react';
import { Button } from '../ui/Button';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/Card';
import { useAuth } from '../../hooks/useAuth';
import { useWallet } from '../../hooks/useWallet';
import { useMutation } from '../../hooks/useApi';
import api from '../../lib/axios';

const PaymentModal = ({ isOpen, onClose, onSuccess }) => {
  const [selectedPlan, setSelectedPlan] = useState('basic');
  const [paymentStep, setPaymentStep] = useState('select'); // select, confirm, processing, success, error
  const [error, setError] = useState('');
  
  const { updateCredits } = useAuth();
  const { walletAddress, connectMetaMask, isConnected } = useWallet();
  const { mutate, loading } = useMutation();

  const plans = [
    {
      id: 'basic',
      name: 'Basic Pack',
      credits: 10,
      price: 0.01, // ETH
      priceUSD: 25,
      popular: false,
      features: [
        '10 Premium Scans',
        'PDF & JSON Reports',
        'Vulnerability Analysis',
        'Email Support'
      ]
    },
    {
      id: 'pro',
      name: 'Professional Pack',
      credits: 25,
      price: 0.02,
      priceUSD: 50,
      popular: true,
      features: [
        '25 Premium Scans',
        'PDF & JSON Reports',
        'Advanced Analysis',
        'Priority Support',
        'API Access'
      ]
    },
    {
      id: 'enterprise',
      name: 'Enterprise Pack',
      credits: 100,
      price: 0.05,
      priceUSD: 125,
      popular: false,
      features: [
        '100 Premium Scans',
        'All Report Formats',
        'Custom Analysis Rules',
        'Dedicated Support',
        'Team Collaboration',
        'White-label Reports'
      ]
    }
  ];

  const selectedPlanData = plans.find(p => p.id === selectedPlan);

  const handlePayment = async () => {
    try {
      setPaymentStep('processing');
      setError('');

      if (!isConnected) {
        await connectMetaMask();
      }

      // Mock payment process - in real app, this would integrate with Web3
      const paymentData = {
        planId: selectedPlan,
        credits: selectedPlanData.credits,
        amount: selectedPlanData.price,
        walletAddress: walletAddress,
        transactionHash: `0x${Math.random().toString(16).substr(2, 64)}` // Mock hash
      };

      await mutate(async () => {
        const response = await api.post('/payment/crypto', paymentData);
        return response.data;
      });

      // Update user credits
      updateCredits(selectedPlanData.credits);
      
      setPaymentStep('success');
      
      setTimeout(() => {
        onSuccess?.();
      }, 2000);

    } catch (err) {
      setError(err.message || 'Payment failed. Please try again.');
      setPaymentStep('error');
    }
  };

  const modalVariants = {
    hidden: { opacity: 0, scale: 0.8 },
    visible: { opacity: 1, scale: 1 },
    exit: { opacity: 0, scale: 0.8 }
  };

  const overlayVariants = {
    hidden: { opacity: 0 },
    visible: { opacity: 1 },
    exit: { opacity: 0 }
  };

  if (!isOpen) return null;

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
        <motion.div
          variants={overlayVariants}
          initial="hidden"
          animate="visible"
          exit="exit"
          className="absolute inset-0 bg-black/50 backdrop-blur-sm"
          onClick={onClose}
        />
        
        <motion.div
          variants={modalVariants}
          initial="hidden"
          animate="visible"
          exit="exit"
          className="relative z-10 w-full max-w-4xl max-h-[90vh] overflow-y-auto"
        >
          <Card>
            <CardHeader className="border-b">
              <div className="flex items-center justify-between">
                <CardTitle className="flex items-center gap-2">
                  <CreditCard className="h-5 w-5" />
                  Purchase Credits
                </CardTitle>
                <button
                  onClick={onClose}
                  className="p-2 hover:bg-gray-100 rounded-full"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
            </CardHeader>
            
            <CardContent className="p-6">
              {paymentStep === 'select' && (
                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="space-y-6"
                >
                  <div className="text-center mb-6">
                    <h2 className="text-2xl font-bold mb-2">Choose Your Plan</h2>
                    <p className="text-gray-600">
                      Select the number of credits that best fits your needs
                    </p>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    {plans.map((plan) => (
                      <motion.div
                        key={plan.id}
                        whileHover={{ scale: 1.02 }}
                        whileTap={{ scale: 0.98 }}
                        className={`relative p-6 rounded-lg border-2 cursor-pointer transition-all ${
                          selectedPlan === plan.id
                            ? 'border-blue-500 bg-blue-50'
                            : 'border-gray-200 hover:border-gray-300'
                        } ${plan.popular ? 'ring-2 ring-blue-500' : ''}`}
                        onClick={() => setSelectedPlan(plan.id)}
                      >
                        {plan.popular && (
                          <div className="absolute -top-3 left-1/2 transform -translate-x-1/2">
                            <span className="bg-blue-500 text-white px-3 py-1 text-xs font-bold rounded-full">
                              POPULAR
                            </span>
                          </div>
                        )}
                        
                        <div className="text-center">
                          <h3 className="text-lg font-bold mb-2">{plan.name}</h3>
                          <div className="mb-4">
                            <span className="text-3xl font-bold">{plan.credits}</span>
                            <span className="text-gray-600 ml-1">credits</span>
                          </div>
                          <div className="text-center mb-4">
                            <span className="text-2xl font-bold">{plan.price} ETH</span>
                            <div className="text-sm text-gray-600">≈ ${plan.priceUSD} USD</div>
                          </div>
                        </div>

                        <ul className="space-y-2 text-sm">
                          {plan.features.map((feature, index) => (
                            <li key={index} className="flex items-center gap-2">
                              <CheckCircle className="h-4 w-4 text-green-500" />
                              <span>{feature}</span>
                            </li>
                          ))}
                        </ul>
                      </motion.div>
                    ))}
                  </div>

                  <div className="flex justify-center">
                    <Button
                      onClick={() => setPaymentStep('confirm')}
                      size="lg"
                      className="px-8"
                    >
                      Continue to Payment
                    </Button>
                  </div>
                </motion.div>
              )}

              {paymentStep === 'confirm' && (
                <motion.div
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  className="space-y-6"
                >
                  <div className="text-center">
                    <h2 className="text-2xl font-bold mb-2">Confirm Purchase</h2>
                    <p className="text-gray-600">
                      Review your order and complete the payment
                    </p>
                  </div>

                  <div className="bg-gray-50 p-6 rounded-lg">
                    <div className="flex justify-between items-start mb-4">
                      <div>
                        <h3 className="text-lg font-bold">{selectedPlanData.name}</h3>
                        <p className="text-gray-600">{selectedPlanData.credits} Premium Credits</p>
                      </div>
                      <div className="text-right">
                        <div className="text-xl font-bold">{selectedPlanData.price} ETH</div>
                        <div className="text-sm text-gray-600">≈ ${selectedPlanData.priceUSD} USD</div>
                      </div>
                    </div>
                  </div>

                  {!isConnected && (
                    <div className="bg-yellow-50 border border-yellow-200 p-4 rounded-lg">
                      <div className="flex items-center gap-2 text-yellow-800">
                        <AlertCircle className="h-5 w-5" />
                        <span className="font-medium">Wallet Connection Required</span>
                      </div>
                      <p className="text-sm text-yellow-700 mt-1">
                        Connect your wallet to proceed with the payment
                      </p>
                    </div>
                  )}

                  <div className="flex gap-3">
                    <Button
                      variant="outline"
                      onClick={() => setPaymentStep('select')}
                      className="flex-1"
                    >
                      Back to Plans
                    </Button>
                    <Button
                      onClick={handlePayment}
                      disabled={loading}
                      className="flex-1"
                    >
                      {!isConnected ? 'Connect & Pay' : 'Complete Payment'}
                    </Button>
                  </div>
                </motion.div>
              )}

              {paymentStep === 'processing' && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="text-center py-12"
                >
                  <Loader2 className="h-16 w-16 animate-spin text-blue-600 mx-auto mb-4" />
                  <h2 className="text-xl font-bold mb-2">Processing Payment...</h2>
                  <p className="text-gray-600">
                    Please confirm the transaction in your wallet
                  </p>
                </motion.div>
              )}

              {paymentStep === 'success' && (
                <motion.div
                  initial={{ opacity: 0, scale: 0.8 }}
                  animate={{ opacity: 1, scale: 1 }}
                  className="text-center py-12"
                >
                  <CheckCircle className="h-16 w-16 text-green-500 mx-auto mb-4" />
                  <h2 className="text-xl font-bold mb-2">Payment Successful!</h2>
                  <p className="text-gray-600 mb-4">
                    {selectedPlanData.credits} credits have been added to your account
                  </p>
                  <div className="bg-green-50 border border-green-200 p-4 rounded-lg inline-block">
                    <p className="text-green-700 font-medium">
                      You can now run {selectedPlanData.credits} premium scans
                    </p>
                  </div>
                </motion.div>
              )}

              {paymentStep === 'error' && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="text-center py-12"
                >
                  <AlertCircle className="h-16 w-16 text-red-500 mx-auto mb-4" />
                  <h2 className="text-xl font-bold mb-2">Payment Failed</h2>
                  <p className="text-red-600 mb-6">{error}</p>
                  <div className="flex gap-3 justify-center">
                    <Button
                      variant="outline"
                      onClick={() => setPaymentStep('confirm')}
                    >
                      Try Again
                    </Button>
                    <Button onClick={onClose}>
                      Close
                    </Button>
                  </div>
                </motion.div>
              )}
            </CardContent>
          </Card>
        </motion.div>
      </div>
    </AnimatePresence>
  );
};

export default PaymentModal;
