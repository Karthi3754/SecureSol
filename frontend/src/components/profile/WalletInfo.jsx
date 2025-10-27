import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  Wallet, 
  Link, 
  Unlink, 
  Copy, 
  ExternalLink,
  AlertCircle,
  CheckCircle,
  Download,
  Clock
} from 'lucide-react';
import { Button } from '../ui/Button';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/Card';
import { useWallet } from '../../hooks/useWallet';
import { useMutation } from '../../hooks/useApi';

const WalletInfo = () => {
  const {
    walletAddress,
    walletProvider,
    isConnected,
    isConnecting,
    connectMetaMask,
    disconnectWallet,
    getBalance
  } = useWallet();

  const [balance, setBalance] = useState(null);
  const [copied, setCopied] = useState(false);
  const { mutate, loading, error } = useMutation();

  const hasMetaMask = typeof window.ethereum !== 'undefined';

  useEffect(() => {
    if (isConnected) {
      fetchBalance();
    }
  }, [isConnected, walletAddress]);

  const fetchBalance = async () => {
    try {
      const walletBalance = await getBalance();
      setBalance(walletBalance);
    } catch (err) {
      console.error('Failed to fetch balance:', err);
    }
  };

  const handleConnect = async () => {
  try {
    await mutate(() => connectMetaMask());
  } catch (err) {
    // Instead of just logging, surface backend message
    console.error('Failed to connect wallet:', err.message || err);

    // 🔥 Optional: you can also show a toast/alert here if you don’t only want the red box
    // alert(err.message);
  }
};

  const handleDisconnect = async () => {
    try {
      await mutate(() => disconnectWallet());
      setBalance(null);
    } catch (err) {
      console.error('Failed to disconnect wallet:', err);
    }
  };

  const copyAddress = async () => {
    if (walletAddress) {
      await navigator.clipboard.writeText(walletAddress);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const truncateAddress = (address) => {
    if (!address) return '';
    return `${address.slice(0, 6)}...${address.slice(-4)}`;
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Wallet className="h-5 w-5" />
          Wallet Connection
        </CardTitle>
      </CardHeader>
      
      <CardContent className="space-y-6">
        {error && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            className="p-3 bg-red-50 border border-red-200 rounded-md flex items-center gap-2 text-red-600"
          >
            <AlertCircle className="h-4 w-4" />
            <span className="text-sm">{error}</span>
          </motion.div>
        )}

        {isConnected ? (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="space-y-4"
          >
            {/* Connected Status */}
            <div className="flex items-center gap-2 p-3 bg-green-50 border border-green-200 rounded-lg">
              <CheckCircle className="h-5 w-5 text-green-600" />
              <span className="text-green-700 font-medium">
                Wallet Connected via {walletProvider}
              </span>
            </div>

            {/* Wallet Address */}
            <div className="space-y-2">
              <label className="text-sm font-medium text-gray-700">
                Wallet Address
              </label>
              <div className="flex items-center gap-2 p-3 bg-gray-50 border rounded-lg">
                <code className="flex-1 text-sm font-mono text-gray-900">
                  {walletAddress}
                </code>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={copyAddress}
                  className="flex items-center gap-1"
                >
                  {copied ? (
                    <>
                      <CheckCircle className="h-4 w-4" />
                      Copied
                    </>
                  ) : (
                    <>
                      <Copy className="h-4 w-4" />
                      Copy
                    </>
                  )}
                </Button>
              </div>
            </div>

            {/* Wallet Balance */}
            <div className="space-y-2">
              <label className="text-sm font-medium text-gray-700">
                Balance
              </label>
              <div className="p-3 bg-gray-50 border rounded-lg">
                <div className="text-lg font-semibold">
                  {balance !== null ? `${balance} ETH` : 'Loading...'}
                </div>
                <div className="text-sm text-gray-600">
                  Ethereum Mainnet
                </div>
              </div>
            </div>

            {/* Quick Actions */}
            <div className="flex gap-3">
              <Button
                variant="outline"
                onClick={handleDisconnect}
                disabled={loading}
                className="flex items-center gap-2"
              >
                <Unlink className="h-4 w-4" />
                Disconnect
              </Button>
              
              <Button
                variant="outline"
                onClick={() => window.open(`https://etherscan.io/address/${walletAddress}`, '_blank')}
                className="flex items-center gap-2"
              >
                <ExternalLink className="h-4 w-4" />
                View on Etherscan
              </Button>
            </div>
          </motion.div>
        ) : (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="text-center space-y-4"
          >
            <div className="p-8">
              <Wallet className="h-16 w-16 text-gray-400 mx-auto mb-4" />
              <h3 className="text-lg font-semibold text-gray-900 mb-2">
                No Wallet Connected
              </h3>
              <p className="text-gray-600 mb-6">
                Connect your wallet to purchase premium credits and unlock advanced features
              </p>

              {!hasMetaMask ? (
                <Button
                  onClick={() => window.open('https://metamask.io/download/', '_blank')}
                  size="lg"
                  className="flex items-center gap-2 bg-blue-500 hover:bg-blue-600 text-white"
                >
                  <Download className="h-4 w-4" />
                  Install MetaMask
                </Button>
              ) : (
                <Button
                  onClick={handleConnect}
                  disabled={isConnecting || loading}
                  size="lg"
                  className="flex items-center gap-2"
                >
                  {isConnecting || loading ? (
                    <>
                      <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                      Connecting...
                    </>
                  ) : (
                    <>
                      <Link className="h-4 w-4" />
                      Connect MetaMask
                    </>
                  )}
                </Button>
              )}
            </div>

            <div className="text-center text-sm text-gray-600">
              <p>Supported wallets: MetaMask, WalletConnect</p>
            </div>
          </motion.div>
        )}
      </CardContent>
    </Card>
  );
};

export default WalletInfo;
