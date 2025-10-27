import React from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { 
  Shield, 
  Zap, 
  Brain, 
  FileText,
  CheckCircle,
  ArrowRight,
  Users,
  Star,
  Download
} from 'lucide-react';
import { Button } from '../components/ui/Button';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/Card';
import { useAuth } from '../hooks/useAuth';

const HomePage = () => {
  const { isAuthenticated } = useAuth();

  const features = [
    {
      icon: Shield,
      title: 'Multi-Layer Analysis',
      description: 'Combines static analysis, symbolic execution, and fuzz testing for comprehensive security coverage.'
    },
    {
      icon: Brain,
      title: 'AI-Powered Detection',
      description: 'Advanced ML models detect intent vs. implementation mismatches and subtle vulnerabilities.'
    },
    {
      icon: Zap,
      title: 'Fast Results',
      description: 'Get detailed security reports in minutes, not hours. Optimized for developer workflows.'
    },
    {
      icon: FileText,
      title: 'Detailed Reports',
      description: 'Professional PDF and JSON reports with code snippets, fixes, and actionable recommendations.'
    }
  ];

  const testimonials = [
    {
      name: 'Alex Chen',
      role: 'DeFi Developer',
      avatar: '/api/placeholder/40/40',
      content: 'SecureAnalyzer caught critical vulnerabilities that other tools missed. Saved our protocol from potential exploits.',
      rating: 5
    },
    {
      name: 'Sarah Johnson',
      role: 'Security Auditor',
      avatar: '/api/placeholder/40/40',
      content: 'The AI-powered analysis provides insights that complement manual auditing. Great tool for initial screening.',
      rating: 5
    },
    {
      name: 'Mike Rodriguez',
      role: 'Smart Contract Developer',
      avatar: '/api/placeholder/40/40',
      content: 'Easy to use interface and comprehensive reports. The before/after code examples are particularly helpful.',
      rating: 5
    }
  ];

  const stats = [
    { label: 'Contracts Analyzed', value: '50,000+' },
    { label: 'Vulnerabilities Found', value: '125,000+' },
    { label: 'Developers Trust Us', value: '10,000+' },
    { label: 'Success Rate', value: '99.9%' }
  ];

  return (
    <div className="min-h-screen">
      {/* Hero Section */}
      <section className="bg-gradient-to-br from-blue-600 via-blue-700 to-blue-800 text-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
            className="text-center"
          >
            <h1 className="text-5xl md:text-7xl font-bold mb-6 bg-gradient-to-r from-white to-blue-200 bg-clip-text text-transparent">
              Secure Your Smart Contracts
            </h1>
            <p className="text-xl md:text-2xl text-blue-100 mb-8 max-w-3xl mx-auto">
              Advanced AI-powered security analysis for Solidity smart contracts. 
              Detect vulnerabilities before deployment with military-grade precision.
            </p>
            
            <div className="flex flex-col sm:flex-row gap-4 justify-center items-center">
              {isAuthenticated ? (
                <Link to="/dashboard">
                  <Button size="lg" className="bg-white text-blue-600 hover:bg-blue-50 px-8 py-4 text-lg">
                    Go to Dashboard
                    <ArrowRight className="ml-2 h-5 w-5" />
                  </Button>
                </Link>
              ) : (
                <>
                  <Link to="/register">
                    <Button size="lg" className="bg-white text-blue-600 hover:bg-blue-50 px-8 py-4 text-lg">
                      Start Free Analysis
                      <ArrowRight className="ml-2 h-5 w-5" />
                    </Button>
                  </Link>
                  <Link to="/login">
                    <Button 
                    size="lg" 
                    className="border border-white bg-transparent text-white hover:bg-white hover:text-blue-600 px-8 py-4 text-lg"
                    >
                    Sign In
                    </Button>
                  </Link>
                </>
              )}
            </div>

            {/* Free Trial Badge */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.5 }}
              className="mt-8 inline-flex items-center gap-2 bg-green-500 text-white px-4 py-2 rounded-full text-sm font-medium"
            >
              <CheckCircle className="h-4 w-4" />
              3 Free Premium Scans for New Users
            </motion.div>
          </motion.div>
        </div>
      </section>

      {/* Stats Section */}
      <section className="bg-white py-16 border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
            {stats.map((stat, index) => (
              <motion.div
                key={stat.label}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.1 }}
                className="text-center"
              >
                <div className="text-3xl font-bold text-blue-600 mb-2">
                  {stat.value}
                </div>
                <div className="text-gray-600">{stat.label}</div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-20 bg-gray-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="text-center mb-16"
          >
            <h2 className="text-4xl font-bold text-gray-900 mb-4">
              Why Choose SecureAnalyzer?
            </h2>
            <p className="text-xl text-gray-600 max-w-2xl mx-auto">
              Comprehensive security analysis powered by the latest advances in AI and formal verification
            </p>
          </motion.div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
            {features.map((feature, index) => (
              <motion.div
                key={feature.title}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.1 }}
              >
                <Card className="h-full hover:shadow-lg transition-shadow">
                  <CardHeader>
                    <div className="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center mb-4">
                      <feature.icon className="h-6 w-6 text-blue-600" />
                    </div>
                    <CardTitle className="text-xl">{feature.title}</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <p className="text-gray-600">{feature.description}</p>
                  </CardContent>
                </Card>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* How It Works */}
      <section className="py-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="text-center mb-16"
          >
            <h2 className="text-4xl font-bold text-gray-900 mb-4">
              How It Works
            </h2>
            <p className="text-xl text-gray-600">
              Get comprehensive security analysis in just 3 simple steps
            </p>
          </motion.div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            {[
              {
                step: '1',
                title: 'Upload Contract',
                description: 'Simply drag and drop your Solidity file or paste the code directly into our secure platform.'
              },
              {
                step: '2',
                title: 'AI Analysis',
                description: 'Our advanced AI engines perform multi-layered security analysis including static, symbolic, and fuzz testing.'
              },
              {
                step: '3',
                title: 'Get Report',
                description: 'Receive detailed vulnerability reports with code examples, severity ratings, and fix recommendations.'
              }
            ].map((step, index) => (
              <motion.div
                key={step.step}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.2 }}
                className="text-center"
              >
                <div className="w-16 h-16 bg-blue-600 text-white rounded-full flex items-center justify-center text-2xl font-bold mx-auto mb-6">
                  {step.step}
                </div>
                <h3 className="text-xl font-semibold mb-4">{step.title}</h3>
                <p className="text-gray-600">{step.description}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Testimonials */}
      <section className="py-20 bg-gray-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="text-center mb-16"
          >
            <h2 className="text-4xl font-bold text-gray-900 mb-4">
              Trusted by Developers Worldwide
            </h2>
            <p className="text-xl text-gray-600">
              See what our users say about SecureAnalyzer
            </p>
          </motion.div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            {testimonials.map((testimonial, index) => (
              <motion.div
                key={testimonial.name}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.1 }}
              >
                <Card className="h-full">
                  <CardContent className="p-6">
                    <div className="flex items-center mb-4">
                      {[...Array(testimonial.rating)].map((_, i) => (
                        <Star key={i} className="h-5 w-5 text-yellow-400 fill-current" />
                      ))}
                    </div>
                    <p className="text-gray-700 mb-4">"{testimonial.content}"</p>
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 bg-blue-100 rounded-full flex items-center justify-center">
                        <Users className="h-5 w-5 text-blue-600" />
                      </div>
                      <div>
                        <div className="font-semibold">{testimonial.name}</div>
                        <div className="text-sm text-gray-600">{testimonial.role}</div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="bg-blue-600 text-white py-20">
        <div className="max-w-4xl mx-auto text-center px-4 sm:px-6 lg:px-8">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
          >
            <h2 className="text-4xl font-bold mb-4">
              Ready to Secure Your Smart Contracts?
            </h2>
            <p className="text-xl text-blue-100 mb-8">
              Join thousands of developers who trust SecureAnalyzer for their smart contract security needs.
            </p>
            
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              {!isAuthenticated && (
                <Link to="/register">
                  <Button size="lg" className="bg-white text-blue-600 hover:bg-blue-50 px-8 py-4 text-lg">
                    Start Your Free Analysis
                    <ArrowRight className="ml-2 h-5 w-5" />
                  </Button>
                </Link>
              )}
              <Button 
              size="lg" 
              className="border border-white bg-transparent text-white hover:bg-white hover:text-blue-600 px-8 py-4 text-lg"
              onClick={() => window.open('/docs', '_blank')}
              >
              <Download className="mr-2 h-5 w-5" />
                View Documentation
              </Button>

            </div>

            <div className="mt-8 text-blue-200">
              <p>No credit card required • 3 free scans • Instant results</p>
            </div>
          </motion.div>
        </div>
      </section>
    </div>
  );
};

export default HomePage;
