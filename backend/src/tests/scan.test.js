const request = require('supertest');
const mongoose = require('mongoose');
const path = require('path');
const fs = require('fs');
const app = require('../../server');
const User = require('../models/User');
const ScanReport = require('../models/ScanReport');

describe('Scan Endpoints', () => {
  let token;
  let user;
  let testFilePath;

  beforeEach(async () => {
    await User.deleteMany({});
    await ScanReport.deleteMany({});
    
    user = new User({
      username: 'testuser',
      email: 'test@example.com',
      password: 'Password123',
      credits: 5
    });
    await user.save();
    token = user.getSignedJwtToken();

    // Create test Solidity file
    testFilePath = path.join(__dirname, 'test-contract.sol');
    const contractContent = `
pragma solidity ^0.8.0;

contract TestContract {
    uint256 public value;
    
    function setValue(uint256 _value) public {
        value = _value;
    }
}`;
    fs.writeFileSync(testFilePath, contractContent);
  });

  afterEach(() => {
    // Clean up test file
    if (fs.existsSync(testFilePath)) {
      fs.unlinkSync(testFilePath);
    }
  });

  afterAll(async () => {
    await mongoose.connection.close();
  });

  describe('POST /api/scan/upload', () => {
    it('should upload contract and start scan', async () => {
      const res = await request(app)
        .post('/api/scan/upload')
        .set('Authorization', `Bearer ${token}`)
        .attach('contract', testFilePath)
        .field('scanType', 'premium');

      expect(res.statusCode).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.scanId).toBeDefined();
      expect(res.body.data.status).toBe('queued');
      expect(res.body.data.scanType).toBe('premium');
    });

    it('should not upload without file', async () => {
      const res = await request(app)
        .post('/api/scan/upload')
        .set('Authorization', `Bearer ${token}`)
        .field('scanType', 'premium');

      expect(res.statusCode).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should not upload with insufficient credits', async () => {
      // Set user credits to 0
      await User.findByIdAndUpdate(user._id, { credits: 0 });

      const res = await request(app)
        .post('/api/scan/upload')
        .set('Authorization', `Bearer ${token}`)
        .attach('contract', testFilePath)
        .field('scanType', 'premium');

      expect(res.statusCode).toBe(402);
      expect(res.body.success).toBe(false);
    });
  });

  describe('GET /api/scan/history', () => {
    beforeEach(async () => {
      // Create test scan reports
      await ScanReport.create({
        user: user._id,
        contractName: 'TestContract',
        contractContent: 'pragma solidity ^0.8.0; contract Test {}',
        status: 'completed',
        scanType: 'premium',
        vulnerabilities: []
      });
    });

    it('should get scan history', async () => {
      const res = await request(app)
        .get('/api/scan/history')
        .set('Authorization', `Bearer ${token}`);

      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveLength(1);
      expect(res.body.data[0].contractName).toBe('TestContract');
    });

    it('should filter scan history by status', async () => {
      const res = await request(app)
        .get('/api/scan/history?status=completed')
        .set('Authorization', `Bearer ${token}`);

      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveLength(1);
    });
  });

  describe('GET /api/scan/:id/status', () => {
    let scanReport;

    beforeEach(async () => {
      scanReport = await ScanReport.create({
        user: user._id,
        contractName: 'TestContract',
        contractContent: 'pragma solidity ^0.8.0; contract Test {}',
        status: 'processing',
        progress: 50,
        currentStep: 'static_analysis',
        scanType: 'premium'
      });
    });

    it('should get scan status', async () => {
      const res = await request(app)
        .get(`/api/scan/${scanReport._id}/status`)
        .set('Authorization', `Bearer ${token}`);

      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.status).toBe('processing');
      expect(res.body.data.progress).toBe(50);
      expect(res.body.data.currentStep).toBe('static_analysis');
    });

    it('should not get status for non-existent scan', async () => {
      const fakeId = new mongoose.Types.ObjectId();
      const res = await request(app)
        .get(`/api/scan/${fakeId}/status`)
        .set('Authorization', `Bearer ${token}`);

      expect(res.statusCode).toBe(404);
      expect(res.body.success).toBe(false);
    });
  });

  describe('GET /api/scan/vulnerability-stats', () => {
    beforeEach(async () => {
      // Create scan with vulnerabilities
      await ScanReport.create({
        user: user._id,
        contractName: 'VulnContract',
        contractContent: 'pragma solidity ^0.8.0; contract Test {}',
        status: 'completed',
        scanType: 'premium',
        vulnerabilities: [
          {
            id: 'test_001',
            title: 'Test Vulnerability',
            description: 'Test description',
            severity: 'High',
            category: 'Test Category'
          }
        ]
      });
    });

    it('should get vulnerability statistics', async () => {
      const res = await request(app)
        .get('/api/scan/vulnerability-stats')
        .set('Authorization', `Bearer ${token}`);

      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.totalVulnerabilities).toBe(1);
      expect(res.body.data.bySeverity).toBeDefined();
      expect(res.body.data.byType).toBeDefined();
    });
  });
});
