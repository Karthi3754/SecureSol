import React from 'react';
import { motion } from 'framer-motion';
import DashboardOverview from '../components/dashboard/DashboardOverview';
import QuickActions from '../components/dashboard/QuickActions';
import VulnerabilityHeatmap from '../components/dashboard/VulnerabilityHeatmap';

const DashboardPage = () => {
  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="space-y-8"
        >
          {/* Dashboard Overview */}
          <DashboardOverview />

          {/* Quick Actions */}
          <QuickActions />

          {/* Vulnerability Analytics */}
          <VulnerabilityHeatmap />
        </motion.div>
      </div>
    </div>
  );
};

export default DashboardPage;
