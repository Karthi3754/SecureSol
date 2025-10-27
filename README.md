# 🛡️ Smart Contract Security Analyzer

A full-stack **AI-powered web application** designed to help developers and auditors **detect vulnerabilities in Solidity smart contracts before deployment**.  
It combines **AI analysis, symbolic execution, fuzz testing, and intent detection** to generate clear, actionable reports for smart contract security.

---

## 📝 Project Overview

The **Smart Contract Security Analyzer** enables users to securely upload Solidity contracts and receive detailed, multi-layered security insights.  
It provides vulnerability detection, user management, wallet integration, scan tracking, and crypto-based payments — all within a user-friendly dashboard.

### 🔍 Core Highlights
- Multi-layered contract analysis: **AI + Symbolic Execution + Fuzz Testing + Intent Detection**
- **Interactive dashboard** with scan history & status tracking
- **PDF/JSON report generation**
- **3 free premium scans** for new users
- **Crypto-based payment** for additional premium scans

---

## 🎯 Problem Statement

Smart contracts are **immutable** and often handle **real digital assets**.  
Even a small bug can lead to massive financial losses. Existing tools are either:

- Too technical for non-experts  
- Limited to static analysis  
- Lacking user-friendly reporting  

### 🧩 Our Solution
This platform solves these issues by offering:
- A **simple interface** for uploading and scanning contracts  
- A **multi-layered automated analysis pipeline**  
- **Clear, developer-friendly reports** with examples and fixes  

---

## 💡 Solution Workflow

1. **Upload Solidity contract**
2. **Run analysis pipeline**
   - Static analysis  
   - AI intent detection  
   - Symbolic execution  
   - Fuzz testing  
3. **View results** interactively in the dashboard  
4. **Download reports** in PDF or JSON  
5. **Track history** and manage account via Profile page  

---

## 🔧 Tech Stack

### 🖥️ Frontend
| Technology | Purpose |
|-------------|----------|
| **React (Vite)** | Fast and modular frontend framework |
| **TailwindCSS** | Utility-first styling |
| **ShadCN/UI + Lucide-react** | UI components and icons |
| **Framer Motion** | Animations and transitions |
| **Axios** | API communication |

### ⚙️ Backend
| Technology | Purpose |
|-------------|----------|
| **Node.js + Express** | REST API and user management |
| **Python (Flask / FastAPI)** | AI, symbolic execution, fuzz testing modules |
| **Hardhat / Foundry** | Smart contract compilation and testing |
| **ML/NLP Models** | AI intent detection and vulnerability classification |

### 🗄️ Database
| Technology | Purpose |
|-------------|----------|
| **MongoDB (Atlas)** | Users, reports, payments, and scan history |

### 🔐 Authentication & Security
- **JWT** for user login/register  
- **MetaMask / WalletConnect** for wallet connection  

### 📁 File Handling & Reports
- **Multer** for contract uploads  
- **pdf-lib / Puppeteer** for PDF report generation  
- **JSON Exporter** for structured report output  

---

## ⚙️ Workflow

### 1️⃣ Registration & Login
- Users sign up with username, email, and password.  
- Login to access the dashboard.  
- Connect wallet (MetaMask / WalletConnect) from the Profile page.

### 2️⃣ Free Trial & Premium Scans
- New users get **3 free premium scans**.  
- Each premium scan deducts 1 credit.  
- When credits = 0 → **PaymentModal** appears for crypto-based payment.

### 3️⃣ Contract Upload & Analysis
- Upload Solidity contract file.  
- Backend triggers analysis pipeline:
  - **Static analysis**
  - **AI-powered intent detection**
  - **Symbolic execution**
  - **Fuzz testing**

### 4️⃣ Report Generation
- Vulnerabilities displayed in **interactive cards**.  
- Download as **PDF or JSON**.  
- Automatically saved in scan history.

### 5️⃣ Scan Status Tracking
- Each scan moves through: `Queued → In-progress → Completed`.  
- Dashboard shows live progress updates.

### 6️⃣ Profile Management
- Edit username, email, and wallet.  
- View remaining premium credits.  
- Access past scans and reports with timestamps.

### 7️⃣ Dashboard UX
- Quick buttons: **Run Scan**, **Upgrade to Premium**, **View History**  
- Vulnerability heatmap for quick visual overview  
- Locked premium features highlighted for free users  

### 8️⃣ Developer-Friendly Features
- Reports include **before/after code snippets**  
- Example vulnerability fixes  
- Severity classification for each finding  

---

## ✅ Key Features Summary

| Feature | Description |
|----------|-------------|
| **JWT Authentication** | Secure login/register |
| **Wallet Connect** | MetaMask / WalletConnect integration |
| **Free Premium Scans** | 3 credits for new users |
| **Contract Upload & Multi-layer Analysis** | AI, symbolic, fuzzing, and intent detection |
| **Report Generation** | Download as PDF/JSON |
| **Scan Tracking** | Real-time status updates |
| **Profile Management** | Edit info, view wallet & credits |
| **Crypto Payments** | For premium scan credits |
| **Dashboard Insights** | Heatmap, history, and quick actions |
| **Developer-Friendly Reports** | Example fixes, before/after snippets |

---

🚀 Happy Coding 🎯.
