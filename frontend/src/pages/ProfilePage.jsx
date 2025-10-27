import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { User, Wallet, History } from 'lucide-react';
import ProfileDetails from '../components/profile/ProfileDetails';
import WalletInfo from '../components/profile/WalletInfo';
import ScanHistoryTable from '../components/profile/ScanHistoryTable';

const ProfilePage = () => {
  const [activeTab, setActiveTab] = useState('profile');

  const tabs = [
    { id: 'profile', label: 'Profile', icon: User, component: ProfileDetails },
    { id: 'wallet', label: 'Wallet', icon: Wallet, component: WalletInfo },
    { id: 'history', label: 'Scan History', icon: History, component: ScanHistoryTable }
  ];

  const ActiveComponent = tabs.find(tab => tab.id === activeTab)?.component;

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="space-y-6"
        >
          {/* Page Header */}
          <div>
            <h1 className="text-3xl font-bold text-gray-900">Account Settings</h1>
            <p className="mt-2 text-gray-600">
              Manage your profile, wallet connection, and view your scan history
            </p>
          </div>

          {/* Tab Navigation */}
          <div className="bg-white rounded-lg shadow-sm border">
            <div className="border-b border-gray-200">
              <nav className="-mb-px flex space-x-8 px-6">
                {tabs.map((tab) => (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={`py-4 px-1 border-b-2 font-medium text-sm flex items-center gap-2 ${
                      activeTab === tab.id
                        ? 'border-blue-500 text-blue-600'
                        : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                    }`}
                  >
                    <tab.icon className="h-4 w-4" />
                    {tab.label}
                  </button>
                ))}
              </nav>
            </div>

            {/* Tab Content */}
            <div className="p-6">
              <motion.div
                key={activeTab}
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.3 }}
              >
                {ActiveComponent && <ActiveComponent />}
              </motion.div>
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  );
};

export default ProfilePage;
