import React, { createContext, useState, useEffect } from 'react';
import { userService } from '../services/userService';

export const WalletContext = createContext({});

export const WalletProvider = ({ children }) => {
  const [walletAddress, setWalletAddress] = useState(null);
  const [isConnecting, setIsConnecting] = useState(false);
  const [walletProvider, setWalletProvider] = useState(null);

  useEffect(() => {
    checkWalletConnection();

    // ✅ Listen for account changes
    if (window.ethereum) {
      window.ethereum.on('accountsChanged', handleAccountsChanged);
      window.ethereum.on('chainChanged', () => window.location.reload());
    }

    return () => {
      if (window.ethereum) {
        window.ethereum.removeListener('accountsChanged', handleAccountsChanged);
        window.ethereum.removeListener('chainChanged', () => window.location.reload());
      }
    };
  }, []);

  const handleAccountsChanged = (accounts) => {
    if (accounts.length > 0) {
      setWalletAddress(accounts[0]);
      setWalletProvider('MetaMask');
    } else {
      setWalletAddress(null);
      setWalletProvider(null);
    }
  };

  const checkWalletConnection = async () => {
    try {
      if (window.ethereum) {
        const accounts = await window.ethereum.request({ method: 'eth_accounts' });
        if (accounts.length > 0) {
          setWalletAddress(accounts[0]);
          setWalletProvider('MetaMask');
        }
      }
    } catch (error) {
      console.error('Error checking wallet connection:', error);
    }
  };

  const connectMetaMask = async () => {
  if (!window.ethereum) {
    window.open('https://metamask.io/download/', '_blank');
    throw new Error('MetaMask is not installed. Please install it from https://metamask.io/');
  }

  try {
    setIsConnecting(true);

    const accounts = await window.ethereum.request({
      method: 'eth_requestAccounts',
    });

    if (accounts.length > 0) {
      const address = accounts[0];

      // Sign message to prove ownership
      const message = `Connect wallet to Smart Contract Analyzer: ${Date.now()}`;
      const signature = await window.ethereum.request({
        method: 'personal_sign',
        params: [message, address],
      });

      // Send to backend for verification
      await userService.connectWallet(address, signature);

      setWalletAddress(address);
      setWalletProvider('MetaMask');
      return address;
    }
  } catch (error) {
    console.error('Error connecting MetaMask:', error);

    // ✅ Extract backend message if available
    if (error.response && error.response.data) {
      const backendMsg = error.response.data.error || error.response.data.message;
      throw new Error(backendMsg || 'Failed to connect wallet');
    }

    throw error; // fallback for unexpected errors
  } finally {
    setIsConnecting(false);
  }
};

  const disconnectWallet = async () => {
    try {
      await userService.disconnectWallet();
    } catch (error) {
      console.error('Error disconnecting wallet:', error);
    } finally {
      setWalletAddress(null);
      setWalletProvider(null);
    }
  };

  const getBalance = async () => {
    if (!window.ethereum || !walletAddress) return null;

    try {
      const balance = await window.ethereum.request({
        method: 'eth_getBalance',
        params: [walletAddress, 'latest'],
      });

      // Convert from wei → ETH
      return parseFloat(parseInt(balance, 16) / Math.pow(10, 18)).toFixed(4);
    } catch (error) {
      console.error('Error getting wallet balance:', error);
      return null;
    }
  };

  const switchNetwork = async (chainId) => {
    if (!window.ethereum) {
      window.open('https://metamask.io/download/', '_blank');
      throw new Error('MetaMask is not installed');
    }

    try {
      await window.ethereum.request({
        method: 'wallet_switchEthereumChain',
        params: [{ chainId }],
      });
    } catch (error) {
      console.error('Error switching network:', error);
      throw error;
    }
  };

  const value = {
    walletAddress,
    walletProvider,
    isConnecting,
    connectMetaMask,
    disconnectWallet,
    getBalance,
    switchNetwork,
    isConnected: !!walletAddress,
  };

  return <WalletContext.Provider value={value}>{children}</WalletContext.Provider>;
};
