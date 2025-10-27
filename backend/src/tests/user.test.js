const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../../server');
const User = require('../models/User');

describe('User Endpoints', () => {
  let token;
  let user;

  beforeEach(async () => {
    await User.deleteMany({});
    
    user = new User({
      username: 'testuser',
      email: 'test@example.com',
      password: 'Password123',
      credits: 5
    });
    await user.save();
    token = user.getSignedJwtToken();
  });

  afterAll(async () => {
    await mongoose.connection.close();
  });

  describe('GET /api/user/profile', () => {
    it('should get user profile', async () => {
      const res = await request(app)
        .get('/api/user/profile')
        .set('Authorization', `Bearer ${token}`);

      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.user.email).toBe('test@example.com');
      expect(res.body.credits).toBe(5);
    });
  });

  describe('PUT /api/user/profile', () => {
    it('should update user profile', async () => {
      const updateData = {
        username: 'updateduser',
        email: 'updated@example.com'
      };

      const res = await request(app)
        .put('/api/user/profile')
        .set('Authorization', `Bearer ${token}`)
        .send(updateData);

      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.user.username).toBe(updateData.username);
      expect(res.body.user.email).toBe(updateData.email);
    });

    it('should not update with invalid email', async () => {
      const updateData = {
        username: 'updateduser',
        email: 'invalid-email'
      };

      const res = await request(app)
        .put('/api/user/profile')
        .set('Authorization', `Bearer ${token}`)
        .send(updateData);

      expect(res.statusCode).toBe(400);
      expect(res.body.success).toBe(false);
    });
  });

  describe('POST /api/user/connect-wallet', () => {
    it('should connect wallet', async () => {
      const walletData = {
        walletAddress: '0x742d35Cc6634C0532925a3b8D400cEaB4E502d05',
        signature: 'mock_signature'
      };

      const res = await request(app)
        .post('/api/user/connect-wallet')
        .set('Authorization', `Bearer ${token}`)
        .send(walletData);

      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.walletAddress).toBe(walletData.walletAddress);
    });

    it('should not connect invalid wallet address', async () => {
      const walletData = {
        walletAddress: 'invalid_address',
        signature: 'mock_signature'
      };

      const res = await request(app)
        .post('/api/user/connect-wallet')
        .set('Authorization', `Bearer ${token}`)
        .send(walletData);

      expect(res.statusCode).toBe(400);
      expect(res.body.success).toBe(false);
    });
  });

  describe('GET /api/user/credits', () => {
    it('should get user credits', async () => {
      const res = await request(app)
        .get('/api/user/credits')
        .set('Authorization', `Bearer ${token}`);

      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.credits).toBe(5);
    });
  });
});
