const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const User = require('../models/User');
const ScanReport = require('../models/ScanReport');
const Transaction = require('../models/Transaction');
const connectDB = require('../config/db');
const logger = require('./logger');

const seedData = async () => {
  try {
    await connectDB();

    // Clear existing data
    await User.deleteMany({});
    await ScanReport.deleteMany({});
    await Transaction.deleteMany({});

    console.log('🗑️  Cleared existing data');

    // Create demo users
    const demoUsers = [
      {
        username: 'demouser',
        email: 'demo@example.com',
        password: 'password123',
        credits: 5,
        role: 'user',
        walletAddress: '0x742d35Cc6634C0532925a3b8D400cEaB4E502d05',
        totalScans: 3
      },
      {
        username: 'testdev',
        email: 'test@developer.com',
        password: 'password123',
        credits: 10,
        role: 'user',
        walletAddress: '0x8ba1f109551bD432803012645Hac136c30000000',
        totalScans: 7
      },
      {
        username: 'admin',
        email: 'admin@example.com',
        password: 'admin123',
        credits: 100,
        role: 'admin',
        totalScans: 15
      }
    ];

    const createdUsers = [];
    
    for (const userData of demoUsers) {
      const user = await User.create(userData);
      createdUsers.push(user);
      console.log(`✅ Created user: ${user.email}`);
    }

    // Create sample scan reports
    const sampleContract = `
pragma solidity ^0.8.0;

contract SimpleStorage {
    uint256 private storedData;
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    function set(uint256 x) public onlyOwner {
        storedData = x;
    }
    
    function get() public view returns (uint256) {
        return storedData;
    }
    
    function withdraw() public {
        payable(msg.sender).transfer(address(this).balance);
    }
}`;

    const sampleVulnerabilities = [
      {
        id: 'demo_001',
        title: 'Missing Access Control',
        description: 'The withdraw function lacks proper access control, allowing any user to drain the contract.',
        severity: 'High',
        category: 'Access Control',
        location: { line: 23, function: 'withdraw' },
        vulnerableCode: 'function withdraw() public {\n    payable(msg.sender).transfer(address(this).balance);\n}',
        fixedCode: 'function withdraw() public onlyOwner {\n    payable(msg.sender).transfer(address(this).balance);\n}',
        recommendation: 'Add the onlyOwner modifier to restrict access to the contract owner only.',
        impact: 'Any user can drain the contract balance, leading to complete loss of funds.',
        confidence: 'High',
        references: [
          {
            title: 'SWC-105: Unprotected Ether Withdrawal',
            url: 'https://swcregistry.io/docs/SWC-105'
          }
        ]
      }
    ];

    const scanReports = [
      {
        user: createdUsers[0]._id,
        contractName: 'SimpleStorage',
        contractContent: sampleContract,
        status: 'completed',
        progress: 100,
        scanType: 'premium',
        vulnerabilities: sampleVulnerabilities,
        securityScore: 75,
        gasOptimization: 'Good',
        complexityScore: 'Low',
        functionsAnalyzed: 4,
        linesOfCode: 25,
        analysisTime: '1m 45s',
        solidityVersion: '^0.8.0',
        recommendations: [
          {
            title: 'Implement Access Control',
            description: 'Use OpenZeppelin AccessControl for more granular permission management.',
            priority: 'High'
          }
        ]
      },
      {
        user: createdUsers[1]._id,
        contractName: 'SafeContract',
        contractContent: sampleContract,
        status: 'completed',
        progress: 100,
        scanType: 'premium',
        vulnerabilities: [],
        securityScore: 95,
        gasOptimization: 'Excellent',
        complexityScore: 'Low',
        functionsAnalyzed: 3,
        linesOfCode: 20,
        analysisTime: '2m 12s',
        solidityVersion: '^0.8.0',
        recommendations: []
      },
      {
        user: createdUsers[0]._id,
        contractName: 'TokenContract',
        contractContent: sampleContract,
        status: 'processing',
        progress: 65,
        currentStep: 'symbolic_execution',
        scanType: 'premium',
        vulnerabilities: [],
        functionsAnalyzed: 8,
        linesOfCode: 150
      }
    ];

    for (const reportData of scanReports) {
      const report = await ScanReport.create(reportData);
      console.log(`✅ Created scan report: ${report.contractName} (${report.status})`);
    }

    // Create sample transactions
    const transactions = [
      {
        user: createdUsers[0]._id,
        transactionHash: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        walletAddress: createdUsers[0].walletAddress,
        amount: 0.01,
        currency: 'ETH',
        amountUSD: 25,
        credits: 10,
        planId: 'basic',
        planName: 'Basic Pack',
        status: 'confirmed',
        blockNumber: 18500000,
        gasUsed: '21000',
        gasPrice: '20000000000',
        confirmations: 12
      },
      {
        user: createdUsers[1]._id,
        transactionHash: '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
        walletAddress: createdUsers[1].walletAddress,
        amount: 0.02,
        currency: 'ETH',
        amountUSD: 50,
        credits: 25,
        planId: 'pro',
        planName: 'Professional Pack',
        status: 'confirmed',
        blockNumber: 18500100,
        gasUsed: '21000',
        gasPrice: '18000000000',
        confirmations: 8
      }
    ];

    for (const txData of transactions) {
      const transaction = await Transaction.create(txData);
      console.log(`✅ Created transaction: ${transaction.transactionHash.substring(0, 10)}...`);
    }

    console.log('\n🎉 Seed data created successfully!');
    console.log('\n📋 Demo Accounts:');
    console.log('   Email: demo@example.com | Password: password123 | Credits: 5');
    console.log('   Email: test@developer.com | Password: password123 | Credits: 10');
    console.log('   Email: admin@example.com | Password: admin123 | Credits: 100 (Admin)');
    console.log('\n🚀 You can now start the server and test the application!');

  } catch (error) {
    console.error('❌ Error seeding data:', error.message);
    process.exit(1);
  } finally {
    process.exit(0);
  }
};

// Run seed function if called directly
if (require.main === module) {
  seedData();
}

module.exports = seedData;
