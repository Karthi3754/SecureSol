import React from 'react';
import { motion } from 'framer-motion';
import { 
  CreditCard, 
  FileText, 
  AlertTriangle, 
  CheckCircle,
  TrendingUp,
  Clock
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/Card';
import { useAuth } from '../../hooks/useAuth';
import { useApi } from '../../hooks/useApi';

const DashboardOverview = () => {
  const { user, credits } = useAuth();
  const { data: dashboardStats, loading } = useApi('/user/dashboard-stats');

  const stats = dashboardStats || {
    totalScans: 0,
    vulnerabilitiesFound: 0,
    contractsSecured: 0,
    lastScanDate: null
  };

  const cardVariants = {
    hidden: { opacity: 0, y: 20 },
    visible: (i) => ({
      opacity: 1,
      y: 0,
      transition: {
        delay: i * 0.1,
        duration: 0.5,
        ease: "easeOut"
      }
    })
  };

  const statCards = [
    {
      title: 'Available Credits',
      value: credits,
      icon: CreditCard,
      color: 'text-green-600',
      bgColor: 'bg-green-50',
      borderColor: 'border-green-200'
    },
    {
      title: 'Total Scans',
      value: stats.totalScans,
      icon: FileText,
      color: 'text-blue-600',
      bgColor: 'bg-blue-50',
      borderColor: 'border-blue-200'
    },
    {
      title: 'Vulnerabilities Found',
      value: stats.vulnerabilitiesFound,
      icon: AlertTriangle,
      color: 'text-red-600',
      bgColor: 'bg-red-50',
      borderColor: 'border-red-200'
    },
    {
      title: 'Contracts Secured',
      value: stats.contractsSecured,
      icon: CheckCircle,
      color: 'text-emerald-600',
      bgColor: 'bg-emerald-50',
      borderColor: 'border-emerald-200'
    }
  ];

  if (loading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {[1, 2, 3, 4].map((i) => (
          <Card key={i} className="animate-pulse">
            <CardHeader className="pb-2">
              <div className="h-4 bg-gray-200 rounded w-3/4"></div>
            </CardHeader>
            <CardContent>
              <div className="h-8 bg-gray-200 rounded w-1/2 mb-2"></div>
              <div className="h-3 bg-gray-200 rounded w-1/3"></div>
            </CardContent>
          </Card>
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Welcome Section */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="bg-gradient-to-r from-blue-600 to-blue-700 text-white rounded-lg p-6"
      >
        <h1 className="text-2xl font-bold mb-2">
          Welcome back, {user?.username}!
        </h1>
        <p className="text-blue-100">
          Ready to secure your smart contracts? You have {credits} credits available.
        </p>
      </motion.div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {statCards.map((stat, index) => (
          <motion.div
            key={stat.title}
            custom={index}
            initial="hidden"
            animate="visible"
            variants={cardVariants}
          >
            <Card className={`${stat.borderColor} border-2 hover:shadow-lg transition-shadow`}>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium text-gray-600">
                  {stat.title}
                </CardTitle>
                <div className={`p-2 rounded-lg ${stat.bgColor}`}>
                  <stat.icon className={`h-4 w-4 ${stat.color}`} />
                </div>
              </CardHeader>
              <CardContent>
                <div className={`text-2xl font-bold ${stat.color} mb-1`}>
                  {stat.value}
                </div>
                {stat.title === 'Available Credits' && credits < 5 && (
                  <p className="text-xs text-amber-600">
                    Running low - consider upgrading
                  </p>
                )}
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </div>

      {/* Recent Activity */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Clock className="h-5 w-5" />
            Recent Activity
          </CardTitle>
        </CardHeader>
        <CardContent>
          {stats.lastScanDate ? (
            <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
              <div>
                <p className="font-medium">Last security scan completed</p>
                <p className="text-sm text-gray-600">
                  {new Date(stats.lastScanDate).toLocaleDateString()}
                </p>
              </div>
              <TrendingUp className="h-5 w-5 text-green-600" />
            </div>
          ) : (
            <div className="text-center py-8">
              <FileText className="h-12 w-12 text-gray-400 mx-auto mb-4" />
              <p className="text-gray-600 mb-2">No scans yet</p>
              <p className="text-sm text-gray-500">
                Upload your first smart contract to get started
              </p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default DashboardOverview;
