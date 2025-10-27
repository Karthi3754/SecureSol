import React, { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { 
  Shield, 
  User, 
  LogOut, 
  Menu, 
  X, 
  CreditCard,
  History,
  Settings
} from 'lucide-react';
import { Button } from '../ui/Button';
import { useAuth } from '../../hooks/useAuth';

const Navbar = () => {
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [isProfileOpen, setIsProfileOpen] = useState(false);
  const { user, logout, credits, isAuthenticated } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate('/');
    setIsProfileOpen(false);
  };

  const isActivePath = (path) => {
    return location.pathname === path;
  };

  const navItems = [
    { path: '/', label: 'Home', public: true },
    { path: '/dashboard', label: 'Dashboard', protected: true },
    { path: '/profile', label: 'Profile', protected: true }
  ];

  return (
    <nav className="bg-white shadow-lg border-b sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-16">
          {/* Logo */}
          <Link to="/" className="flex items-center space-x-2">
            <Shield className="h-8 w-8 text-blue-600" />
            <span className="text-xl font-bold text-gray-900">SecureAnalyzer</span>
          </Link>

          {/* Desktop Navigation */}
          <div className="hidden md:flex items-center space-x-6">
            {navItems.map((item) => {
              if (item.protected && !isAuthenticated) return null;
              if (item.protected === false && isAuthenticated) return null;
              
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  className={`px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                    isActivePath(item.path)
                      ? 'text-blue-600 bg-blue-50'
                      : 'text-gray-700 hover:text-blue-600 hover:bg-gray-50'
                  }`}
                >
                  {item.label}
                </Link>
              );
            })}
          </div>

          {/* Desktop Auth Section */}
          <div className="hidden md:flex items-center space-x-4">
            {isAuthenticated ? (
              <>
                {/* Credits Display */}
                <div className="flex items-center space-x-2 px-3 py-1 bg-green-50 border border-green-200 rounded-md">
                  <CreditCard className="h-4 w-4 text-green-600" />
                  <span className="text-sm font-medium text-green-700">
                    {credits} Credits
                  </span>
                </div>

                {/* Profile Dropdown */}
                <div className="relative">
                  <button
                    onClick={() => setIsProfileOpen(!isProfileOpen)}
                    className="flex items-center space-x-2 px-3 py-2 rounded-md text-sm font-medium text-gray-700 hover:bg-gray-50"
                  >
                    <User className="h-4 w-4" />
                    <span>{user?.username}</span>
                  </button>

                  {isProfileOpen && (
                    <motion.div
                      initial={{ opacity: 0, y: -10 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -10 }}
                      className="absolute right-0 mt-2 w-48 bg-white rounded-md shadow-lg border border-gray-200 py-1 z-50"
                    >
                      <Link
                        to="/profile"
                        onClick={() => setIsProfileOpen(false)}
                        className="flex items-center px-4 py-2 text-sm text-gray-700 hover:bg-gray-50"
                      >
                        <Settings className="h-4 w-4 mr-2" />
                        Profile Settings
                      </Link>
                      <Link
                        to="/dashboard"
                        onClick={() => setIsProfileOpen(false)}
                        className="flex items-center px-4 py-2 text-sm text-gray-700 hover:bg-gray-50"
                      >
                        <History className="h-4 w-4 mr-2" />
                        Scan History
                      </Link>
                      <hr className="my-1" />
                      <button
                        onClick={handleLogout}
                        className="flex items-center w-full px-4 py-2 text-sm text-red-600 hover:bg-red-50"
                      >
                        <LogOut className="h-4 w-4 mr-2" />
                        Sign Out
                      </button>
                    </motion.div>
                  )}
                </div>
              </>
            ) : (
              <div className="flex items-center space-x-3">
                <Link to="/login">
                  <Button variant="ghost">Sign In</Button>
                </Link>
                <Link to="/register">
                  <Button>Get Started</Button>
                </Link>
              </div>
            )}
          </div>

          {/* Mobile Menu Button */}
          <div className="md:hidden">
            <button
              onClick={() => setIsMenuOpen(!isMenuOpen)}
              className="p-2 rounded-md text-gray-700 hover:bg-gray-50"
            >
              {isMenuOpen ? <X className="h-6 w-6" /> : <Menu className="h-6 w-6" />}
            </button>
          </div>
        </div>

        {/* Mobile Menu */}
        {isMenuOpen && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="md:hidden border-t border-gray-200 py-4"
          >
            <div className="space-y-2">
              {navItems.map((item) => {
                if (item.protected && !isAuthenticated) return null;
                if (item.protected === false && isAuthenticated) return null;
                
                return (
                  <Link
                    key={item.path}
                    to={item.path}
                    onClick={() => setIsMenuOpen(false)}
                    className={`block px-3 py-2 rounded-md text-base font-medium ${
                      isActivePath(item.path)
                        ? 'text-blue-600 bg-blue-50'
                        : 'text-gray-700 hover:text-blue-600 hover:bg-gray-50'
                    }`}
                  >
                    {item.label}
                  </Link>
                );
              })}

              {isAuthenticated ? (
                <div className="border-t border-gray-200 pt-4 mt-4">
                  <div className="px-3 py-2">
                    <div className="text-sm text-gray-500">Signed in as</div>
                    <div className="text-base font-medium text-gray-900">{user?.username}</div>
                    <div className="text-sm text-green-600">{credits} Credits Available</div>
                  </div>
                  <button
                    onClick={handleLogout}
                    className="flex items-center w-full px-3 py-2 text-base font-medium text-red-600 hover:bg-red-50 rounded-md"
                  >
                    <LogOut className="h-5 w-5 mr-2" />
                    Sign Out
                  </button>
                </div>
              ) : (
                <div className="border-t border-gray-200 pt-4 mt-4 space-y-2">
                  <Link
                    to="/login"
                    onClick={() => setIsMenuOpen(false)}
                    className="block w-full"
                  >
                    <Button variant="ghost" className="w-full justify-start">
                      Sign In
                    </Button>
                  </Link>
                  <Link
                    to="/register"
                    onClick={() => setIsMenuOpen(false)}
                    className="block w-full"
                  >
                    <Button className="w-full">Get Started</Button>
                  </Link>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </div>
    </nav>
  );
};

export default Navbar;
