import api from '../lib/axios';

export const userService = {
  async getProfile() {
    const response = await api.get('/user/profile');
    return response.data;
  },

  async updateProfile(profileData) {
    const response = await api.put('/user/profile', profileData);
    return response.data;
  },

  async connectWallet(walletAddress, signature) {
    const response = await api.post('/user/connect-wallet', {
      walletAddress,
      signature
    });
    return response.data;
  },

  async disconnectWallet() {
    const response = await api.post('/user/disconnect-wallet');
    return response.data;
  },

  async getCredits() {
    const response = await api.get('/user/credits');
    return response.data;
  },

  async getDashboardStats() {
    const response = await api.get('/user/dashboard-stats');
    return response.data;
  },

  async changePassword(currentPassword, newPassword) {
    const response = await api.post('/user/change-password', {
      currentPassword,
      newPassword
    });
    return response.data;
  },

  async deleteAccount() {
    const response = await api.delete('/user/account');
    return response.data;
  }
};
