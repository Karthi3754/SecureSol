import React, { createContext, useState, useEffect } from 'react';
import { authService } from '../services/authService';
import { userService } from '../services/userService';

export const AuthContext = createContext({});

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [credits, setCredits] = useState(0);

  useEffect(() => {
    const initializeAuth = async () => {
      try {
        const token = authService.getToken();
        const savedUser = authService.getCurrentUser();
        
        if (token && savedUser) {
          setUser(savedUser);
          // Fetch fresh user data
          const profile = await userService.getProfile();
          setUser(profile.user);
          setCredits(profile.credits);
        }
      } catch (error) {
        console.error('Auth initialization error:', error);
        authService.logout();
      } finally {
        setLoading(false);
      }
    };

    initializeAuth();
  }, []);

  const login = async (credentials) => {
    try {
      const response = await authService.login(credentials);
      setUser(response.user);
      setCredits(response.user.credits || 0);
      return response;
    } catch (error) {
      throw error;
    }
  };

  const register = async (userData) => {
    try {
      const response = await authService.register(userData);
      setUser(response.user);
      setCredits(response.user.credits || 3); // New users get 3 free credits
      return response;
    } catch (error) {
      throw error;
    }
  };

  const logout = async () => {
    try {
      await authService.logout();
      setUser(null);
      setCredits(0);
    } catch (error) {
      console.error('Logout error:', error);
    }
  };

  const updateUser = (updatedUser) => {
    setUser(updatedUser);
    localStorage.setItem('user', JSON.stringify(updatedUser));
  };

  const updateCredits = (newCredits) => {
    setCredits(newCredits);
  };

  const refreshUserData = async () => {
    try {
      const profile = await userService.getProfile();
      setUser(profile.user);
      setCredits(profile.credits);
    } catch (error) {
      console.error('Error refreshing user data:', error);
    }
  };

  const value = {
    user,
    credits,
    loading,
    login,
    register,
    logout,
    updateUser,
    updateCredits,
    refreshUserData,
    isAuthenticated: !!user
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};
