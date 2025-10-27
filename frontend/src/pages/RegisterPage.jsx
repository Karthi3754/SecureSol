import React from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Shield } from 'lucide-react';
import RegisterForm from '../components/auth/RegisterForm';

const RegisterPage = () => {
  const navigate = useNavigate();

  const handleRegisterSuccess = () => {
    navigate('/dashboard');
  };

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
      <div className="sm:mx-auto sm:w-full sm:max-w-md">
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex justify-center"
        >
          <div className="flex items-center space-x-2">
            <Shield className="h-10 w-10 text-blue-600" />
            <span className="text-2xl font-bold text-gray-900">SecureAnalyzer</span>
          </div>
        </motion.div>
      </div>

      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
        <RegisterForm onSuccess={handleRegisterSuccess} />
        
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.3 }}
          className="mt-6 text-center"
        >
          <p className="text-sm text-gray-600">
            Already have an account?{' '}
            <button
              onClick={() => navigate('/login')}
              className="font-medium text-blue-600 hover:text-blue-500"
            >
              Sign in here
            </button>
          </p>
        </motion.div>
      </div>
    </div>
  );
};

export default RegisterPage;
