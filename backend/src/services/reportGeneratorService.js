const fs = require('fs');
const path = require('path');
const puppeteer = require('puppeteer');
const { PDFDocument, rgb, StandardFonts } = require('pdf-lib');
const logger = require('../utils/logger');
const config = require('../config');

class ReportGeneratorService {
  constructor() {
    this.reportsPath = path.join(config.UPLOAD_PATH, 'reports');
    this.ensureReportsDirectory();
  }

  ensureReportsDirectory() {
    if (!fs.existsSync(this.reportsPath)) {
      fs.mkdirSync(this.reportsPath, { recursive: true });
    }
  }

  async generateReport(scanReport, format = 'pdf') {
    try {
      if (format === 'json') {
        return this.generateJSONReport(scanReport);
      } else if (format === 'pdf') {
        return this.generatePDFReport(scanReport);
      } else {
        throw new Error(`Unsupported format: ${format}`);
      }
    } catch (error) {
      logger.error(`Report generation error: ${error.message}`);
      throw error;
    }
  }

  generateJSONReport(scanReport) {
    const reportData = {
      reportInfo: {
        id: scanReport._id,
        contractName: scanReport.contractName,
        scanType: scanReport.scanType,
        generatedAt: new Date().toISOString(),
        analysisDate: scanReport.createdAt,
        status: scanReport.status
      },
      summary: {
        totalVulnerabilities: scanReport.vulnerabilities.length,
        securityScore: scanReport.securityScore,
        gasOptimization: scanReport.gasOptimization,
        complexityScore: scanReport.complexityScore,
        functionsAnalyzed: scanReport.functionsAnalyzed,
        linesOfCode: scanReport.linesOfCode,
        analysisTime: scanReport.analysisTime
      },
      vulnerabilityStats: scanReport.vulnerabilityStats,
      vulnerabilities: scanReport.vulnerabilities.map(vuln => ({
        id: vuln.id,
        title: vuln.title,
        description: vuln.description,
        severity: vuln.severity,
        category: vuln.category,
        location: vuln.location,
        vulnerableCode: vuln.vulnerableCode,
        fixedCode: vuln.fixedCode,
        recommendation: vuln.recommendation,
        impact: vuln.impact,
        confidence: vuln.confidence,
        references: vuln.references
      })),
      analysisResults: scanReport.analysisResults,
      recommendations: scanReport.recommendations,
      metadata: {
        solidityVersion: scanReport.solidityVersion,
        reportVersion: '1.0.0',
        generatedBy: 'Smart Contract Security Analyzer'
      }
    };

    return Buffer.from(JSON.stringify(reportData, null, 2), 'utf8');
  }

  async generatePDFReport(scanReport) {
    try {
      // Create HTML content for the report
      const htmlContent = this.generateReportHTML(scanReport);
      
      // Use Puppeteer to generate PDF from HTML
      const browser = await puppeteer.launch({
        headless: 'new',
        args: ['--no-sandbox', '--disable-setuid-sandbox']
      });

      const page = await browser.newPage();
      await page.setContent(htmlContent, { waitUntil: 'networkidle0' });

      const pdfBuffer = await page.pdf({
        format: 'A4',
        printBackground: true,
        margin: {
          top: '20px',
          right: '20px',
          bottom: '20px',
          left: '20px'
        }
      });

      await browser.close();

      return pdfBuffer;
    } catch (error) {
      logger.error(`PDF generation error: ${error.message}`);
      // Fallback to simple PDF if Puppeteer fails
      return this.generateSimplePDF(scanReport);
    }
  }

  generateReportHTML(scanReport) {
    const vulnerabilityStats = scanReport.vulnerabilityStats;
    const totalVulnerabilities = scanReport.vulnerabilities.length;

    return `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Analysis Report - ${scanReport.contractName}</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            text-align: center;
            border-bottom: 3px solid #3b82f6;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        
        .header h1 {
            color: #1f2937;
            margin: 0;
            font-size: 28px;
        }
        
        .header .subtitle {
            color: #6b7280;
            font-size: 16px;
            margin-top: 10px;
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .summary-card {
            background: #f9fafb;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }
        
        .summary-card .number {
            font-size: 32px;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .summary-card .label {
            color: #6b7280;
            font-size: 14px;
        }
        
        .score-excellent { color: #10b981; }
        .score-good { color: #3b82f6; }
        .score-warning { color: #f59e0b; }
        .score-danger { color: #ef4444; }
        
        .section {
            margin-bottom: 40px;
        }
        
        .section h2 {
            color: #1f2937;
            border-bottom: 2px solid #e5e7eb;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        
        .vulnerability {
            background: white;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }
        
        .vulnerability-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .vulnerability-title {
            font-size: 18px;
            font-weight: 600;
            color: #1f2937;
        }
        
        .severity-badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .severity-critical {
            background: #fee2e2;
            color: #991b1b;
            border: 1px solid #fecaca;
        }
        
        .severity-high {
            background: #fed7aa;
            color: #9a3412;
            border: 1px solid #fdba74;
        }
        
        .severity-medium {
            background: #fef3c7;
            color: #92400e;
            border: 1px solid #fde68a;
        }
        
        .severity-low {
            background: #dbeafe;
            color: #1e40af;
            border: 1px solid #93c5fd;
        }
        
        .vulnerability-content {
            margin-bottom: 15px;
        }
        
        .code-block {
            background: #1f2937;
            color: #f3f4f6;
            padding: 15px;
            border-radius: 6px;
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 14px;
            overflow-x: auto;
            margin: 10px 0;
        }
        
        .code-block.vulnerable {
            border-left: 4px solid #ef4444;
        }
        
        .code-block.fixed {
            border-left: 4px solid #10b981;
        }
        
        .recommendation {
            background: #eff6ff;
            border: 1px solid #bfdbfe;
            border-radius: 6px;
            padding: 15px;
            margin-top: 15px;
        }
        
        .no-vulnerabilities {
            text-align: center;
            padding: 40px;
            background: #f0fdf4;
            border: 1px solid #bbf7d0;
            border-radius: 8px;
            color: #166534;
        }
        
        .footer {
            text-align: center;
            padding-top: 30px;
            border-top: 1px solid #e5e7eb;
            color: #6b7280;
            font-size: 14px;
        }
        
        @media print {
            body { print-color-adjust: exact; }
            .vulnerability { break-inside: avoid; }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Smart Contract Security Report</h1>
        <div class="subtitle">
            Contract: <strong>${scanReport.contractName}</strong><br>
            Generated: ${new Date().toLocaleDateString()}<br>
            Scan ID: ${scanReport._id}
        </div>
    </div>

    <div class="summary-grid">
        <div class="summary-card">
            <div class="number ${this.getScoreClass(scanReport.securityScore)}">${scanReport.securityScore || 'N/A'}</div>
            <div class="label">Security Score</div>
        </div>
        <div class="summary-card">
            <div class="number ${totalVulnerabilities === 0 ? 'score-excellent' : totalVulnerabilities < 3 ? 'score-warning' : 'score-danger'}">${totalVulnerabilities}</div>
            <div class="label">Total Issues</div>
        </div>
        <div class="summary-card">
            <div class="number">${scanReport.functionsAnalyzed || 0}</div>
            <div class="label">Functions Analyzed</div>
        </div>
        <div class="summary-card">
            <div class="number">${scanReport.linesOfCode || 0}</div>
            <div class="label">Lines of Code</div>
        </div>
    </div>

    ${totalVulnerabilities > 0 ? `
    <div class="section">
        <h2>Vulnerability Details</h2>
        ${scanReport.vulnerabilities.map(vuln => `
        <div class="vulnerability">
            <div class="vulnerability-header">
                <div class="vulnerability-title">${vuln.title}</div>
                <div class="severity-badge severity-${vuln.severity.toLowerCase()}">${vuln.severity}</div>
            </div>
            
            <div class="vulnerability-content">
                <p><strong>Description:</strong> ${vuln.description}</p>
                ${vuln.location ? `<p><strong>Location:</strong> Line ${vuln.location.line}${vuln.location.function ? ` in function ${vuln.location.function}` : ''}</p>` : ''}
                ${vuln.impact ? `<p><strong>Impact:</strong> ${vuln.impact}</p>` : ''}
            </div>

            ${vuln.vulnerableCode ? `
            <div>
                <strong>Vulnerable Code:</strong>
                <pre class="code-block vulnerable">${vuln.vulnerableCode}</pre>
            </div>
            ` : ''}

            ${vuln.fixedCode ? `
            <div>
                <strong>Recommended Fix:</strong>
                <pre class="code-block fixed">${vuln.fixedCode}</pre>
            </div>
            ` : ''}

            ${vuln.recommendation ? `
            <div class="recommendation">
                <strong>Recommendation:</strong> ${vuln.recommendation}
            </div>
            ` : ''}
        </div>
        `).join('')}
    </div>
    ` : `
    <div class="section">
        <div class="no-vulnerabilities">
            <h2>🎉 No Vulnerabilities Found!</h2>
            <p>Your smart contract passed all security checks. Great work!</p>
        </div>
    </div>
    `}

    ${scanReport.recommendations && scanReport.recommendations.length > 0 ? `
    <div class="section">
        <h2>General Recommendations</h2>
        ${scanReport.recommendations.map(rec => `
        <div class="recommendation">
            <strong>${rec.title}</strong><br>
            ${rec.description}
        </div>
        `).join('')}
    </div>
    ` : ''}

    <div class="footer">
        <p>Report generated by Smart Contract Security Analyzer</p>
        <p>Analysis completed in ${scanReport.analysisTime || 'N/A'}</p>
    </div>
</body>
</html>
    `;
  }

  getScoreClass(score) {
    if (score >= 90) return 'score-excellent';
    if (score >= 75) return 'score-good';
    if (score >= 60) return 'score-warning';
    return 'score-danger';
  }

  async generateSimplePDF(scanReport) {
    try {
      // Fallback simple PDF generation using pdf-lib
      const pdfDoc = await PDFDocument.create();
      const timesRomanFont = await pdfDoc.embedFont(StandardFonts.TimesRoman);
      const page = pdfDoc.addPage();
      const { width, height } = page.getSize();

      let yPosition = height - 50;

      // Title
      page.drawText('Smart Contract Security Report', {
        x: 50,
        y: yPosition,
        size: 24,
        font: timesRomanFont,
        color: rgb(0, 0, 0),
      });

      yPosition -= 40;

      // Contract info
      page.drawText(`Contract: ${scanReport.contractName}`, {
        x: 50,
        y: yPosition,
        size: 14,
        font: timesRomanFont,
      });

      yPosition -= 20;

      page.drawText(`Generated: ${new Date().toLocaleDateString()}`, {
        x: 50,
        y: yPosition,
        size: 14,
        font: timesRomanFont,
      });

      yPosition -= 40;

      // Summary
      page.drawText(`Total Vulnerabilities: ${scanReport.vulnerabilities.length}`, {
        x: 50,
        y: yPosition,
        size: 16,
        font: timesRomanFont,
      });

      yPosition -= 20;

            page.drawText(`Security Score: ${scanReport.securityScore || 'N/A'}`, {
        x: 50,
        y: yPosition,
        size: 16,
        font: timesRomanFont,
      });

      yPosition -= 40;

      // Vulnerabilities
      if (scanReport.vulnerabilities.length > 0) {
        page.drawText('Vulnerabilities Found:', {
          x: 50,
          y: yPosition,
          size: 18,
          font: timesRomanFont,
          color: rgb(0.8, 0, 0),
        });

        yPosition -= 30;

        scanReport.vulnerabilities.forEach((vuln, index) => {
          if (yPosition < 100) return; // Prevent overflow

          page.drawText(`${index + 1}. ${vuln.title} (${vuln.severity})`, {
            x: 70,
            y: yPosition,
            size: 12,
            font: timesRomanFont,
          });

          yPosition -= 15;

          if (vuln.description && yPosition > 100) {
            const description = vuln.description.length > 80 
              ? vuln.description.substring(0, 80) + '...'
              : vuln.description;
            
            page.drawText(`   ${description}`, {
              x: 70,
              y: yPosition,
              size: 10,
              font: timesRomanFont,
              color: rgb(0.3, 0.3, 0.3),
            });

            yPosition -= 20;
          }
        });
      } else {
        page.drawText('✓ No vulnerabilities found!', {
          x: 50,
          y: yPosition,
          size: 16,
          font: timesRomanFont,
          color: rgb(0, 0.6, 0),
        });
      }

      return Buffer.from(await pdfDoc.save());
    } catch (error) {
      logger.error(`Simple PDF generation error: ${error.message}`);
      throw error;
    }
  }

  async saveReportFile(scanId, buffer, format) {
    try {
      const filename = `report-${scanId}.${format}`;
      const filepath = path.join(this.reportsPath, filename);
      
      fs.writeFileSync(filepath, buffer);
      
      logger.info(`Report saved: ${filename}`);
      return filepath;
    } catch (error) {
      logger.error(`Error saving report file: ${error.message}`);
      throw error;
    }
  }

  async deleteReportFile(filepath) {
    try {
      if (fs.existsSync(filepath)) {
        fs.unlinkSync(filepath);
        logger.info(`Report file deleted: ${filepath}`);
      }
    } catch (error) {
      logger.error(`Error deleting report file: ${error.message}`);
    }
  }
}

module.exports = new ReportGeneratorService();
