import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import { WalletProvider } from './context/WalletContext';
import ProtectedRoute from './components/layout/ProtectedRoute';
import Navbar from './components/layout/Navbar';
import Footer from './components/layout/Footer';

// Pages
import HomePage from './pages/HomePage';
import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import DashboardPage from './pages/DashboardPage';
import ProfilePage from './pages/ProfilePage';
import ScanResultsPage from './pages/ScanResultsPage';
import NewScanPage from './pages/NewScanPage';

function App() {
  return (
    <AuthProvider>
      <WalletProvider>
        <Router>
          <div className="flex flex-col min-h-screen">
            <Navbar />
            
            <main className="flex-1">
              <Routes>
                {/* Public Routes */}
                <Route path="/" element={<HomePage />} />
                <Route path="/login" element={<LoginPage />} />
                <Route path="/register" element={<RegisterPage />} />
                
                {/* Protected Routes */}
                <Route
                  path="/dashboard"
                  element={
                    <ProtectedRoute>
                      <DashboardPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/profile"
                  element={
                    <ProtectedRoute>
                      <ProfilePage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/scan/new" 
                  element={
                    <ProtectedRoute>
                      <NewScanPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/scan/:scanId/results"
                  element={
                    <ProtectedRoute>
                      <ScanResultsPage />
                    </ProtectedRoute>
                  }
                />
                
                {/* Redirect any unknown routes to home */}
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </main>
            
            <Footer />
          </div>
        </Router>
      </WalletProvider>
    </AuthProvider>
  );
}

export default App;
