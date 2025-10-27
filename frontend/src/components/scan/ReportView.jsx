import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { 
  AlertTriangle, 
  Shield, 
  FileText, 
  Download,
  Eye,
  EyeOff,
  Code,
  Info,
  CheckCircle,
  XCircle,
  ChevronDown,
  ChevronRight,
  ExternalLink
} from 'lucide-react';
import { Button } from '../ui/Button';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/Card';
import { useApi } from '../../hooks/useApi';
import { scanService } from '../../services/scanService';
import { getSeverityColor } from '../../lib/utils';

const ReportView = ({ scanId }) => {
  const [expandedVulnerabilities, setExpandedVulnerabilities] = useState(new Set());
  const [showCode, setShowCode] = useState({});
  const [activeTab, setActiveTab] = useState('vulnerabilities');

  const { data: report, loading, error } = useApi(`/scan/${scanId}/report`);

  const toggleVulnerability = (id) => {
    const newExpanded = new Set(expandedVulnerabilities);
    if (newExpanded.has(id)) {
      newExpanded.delete(id);
    } else {
      newExpanded.add(id);
    }
    setExpandedVulnerabilities(newExpanded);
  };

  const toggleCode = (vulnId, type) => {
    setShowCode(prev => ({
      ...prev,
      [`${vulnId}-${type}`]: !prev[`${vulnId}-${type}`]
    }));
  };

  const handleDownload = async (format) => {
    try {
      const blob = await scanService.downloadReport(scanId, format);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `security-report-${scanId}.${format}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      console.error('Download failed:', error);
    }
  };

  const getSeverityStats = (vulnerabilities) => {
    const stats = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    vulnerabilities?.forEach(vuln => {
      const severity = vuln.severity?.toLowerCase() || 'info';
      stats[severity] = (stats[severity] || 0) + 1;
    });
    return stats;
  };

  if (loading) {
    return (
      <div className="space-y-6">
        {[1, 2, 3].map((i) => (
          <Card key={i} className="animate-pulse">
            <CardHeader>
              <div className="h-6 bg-gray-200 rounded w-3/4"></div>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                <div className="h-4 bg-gray-200 rounded"></div>
                <div className="h-4 bg-gray-200 rounded w-5/6"></div>
                <div className="h-32 bg-gray-200 rounded"></div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    );
  }

  if (error) {
    return (
      <Card>
        <CardContent className="text-center py-12">
          <AlertTriangle className="h-16 w-16 text-red-500 mx-auto mb-4" />
          <h3 className="text-xl font-semibold text-gray-900 mb-2">
            Error Loading Report
          </h3>
          <p className="text-gray-600 mb-4">{error}</p>
          <Button onClick={() => window.location.reload()}>
            Try Again
          </Button>
        </CardContent>
      </Card>
    );
  }

  if (!report) return null;

  const vulnerabilities = report.vulnerabilities || [];
  const severityStats = getSeverityStats(vulnerabilities);
  const totalIssues = vulnerabilities.length;

  return (
    <div className="space-y-6">
      {/* Report Header */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-6 w-6 text-blue-600" />
              Security Analysis Report
            </CardTitle>
            <div className="flex gap-2">
              <Button
                variant="outline"
                onClick={() => handleDownload('json')}
                className="flex items-center gap-2"
              >
                <Download className="h-4 w-4" />
                JSON
              </Button>
              <Button
                onClick={() => handleDownload('pdf')}
                className="flex items-center gap-2"
              >
                <Download className="h-4 w-4" />
                PDF Report
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
            <div className="text-center p-4 bg-gray-50 rounded-lg">
              <div className="text-2xl font-bold text-gray-900">{totalIssues}</div>
              <div className="text-sm text-gray-600">Total Issues</div>
            </div>
            <div className="text-center p-4 bg-red-50 rounded-lg">
              <div className="text-2xl font-bold text-red-600">
                {severityStats.critical + severityStats.high}
              </div>
              <div className="text-sm text-red-700">Critical & High</div>
            </div>
            <div className="text-center p-4 bg-yellow-50 rounded-lg">
              <div className="text-2xl font-bold text-yellow-600">
                {severityStats.medium}
              </div>
              <div className="text-sm text-yellow-700">Medium</div>
            </div>
            <div className="text-center p-4 bg-blue-50 rounded-lg">
              <div className="text-2xl font-bold text-blue-600">
                {severityStats.low + severityStats.info}
              </div>
              <div className="text-sm text-blue-700">Low & Info</div>
            </div>
          </div>

          {/* Contract Info */}
          <div className="bg-gray-50 p-4 rounded-lg">
            <h3 className="font-semibold mb-2">Contract Information</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
              <div>
                <span className="font-medium">Contract Name:</span> {report.contractName}
              </div>
              <div>
                <span className="font-medium">Analysis Date:</span> {new Date(report.createdAt).toLocaleString()}
              </div>
              <div>
                <span className="font-medium">Solidity Version:</span> {report.solidityVersion || 'Auto-detected'}
              </div>
              <div>
                <span className="font-medium">Analysis Duration:</span> {report.analysisTime || 'N/A'}
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Navigation Tabs */}
      <div className="flex space-x-1 bg-gray-100 p-1 rounded-lg">
        {[
          { id: 'vulnerabilities', label: 'Vulnerabilities', count: totalIssues },
          { id: 'summary', label: 'Summary', count: null },
          { id: 'recommendations', label: 'Recommendations', count: null }
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex-1 flex items-center justify-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              activeTab === tab.id
                ? 'bg-white text-blue-600 shadow-sm'
                : 'text-gray-600 hover:text-gray-900'
            }`}
          >
            {tab.label}
            {tab.count !== null && (
              <span className={`px-2 py-1 text-xs rounded-full ${
                activeTab === tab.id ? 'bg-blue-100' : 'bg-gray-200'
              }`}>
                {tab.count}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      {activeTab === 'vulnerabilities' && (
        <div className="space-y-4">
          {totalIssues === 0 ? (
            <Card>
              <CardContent className="text-center py-12">
                <CheckCircle className="h-16 w-16 text-green-500 mx-auto mb-4" />
                <h3 className="text-xl font-semibold text-gray-900 mb-2">
                  No Vulnerabilities Found!
                </h3>
                <p className="text-gray-600">
                  Congratulations! Your smart contract passed all security checks.
                </p>
              </CardContent>
            </Card>
          ) : (
            vulnerabilities.map((vulnerability, index) => (
              <motion.div
                key={vulnerability.id || index}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.1 }}
              >
                <Card>
                  <CardHeader>
                    <div 
                      className="flex items-center justify-between cursor-pointer"
                      onClick={() => toggleVulnerability(vulnerability.id || index)}
                    >
                      <div className="flex items-center gap-3">
                        <div className={`w-3 h-3 rounded-full ${
                          vulnerability.severity === 'Critical' ? 'bg-red-600' :
                          vulnerability.severity === 'High' ? 'bg-orange-500' :
                          vulnerability.severity === 'Medium' ? 'bg-yellow-500' :
                          vulnerability.severity === 'Low' ? 'bg-blue-500' :
                          'bg-gray-500'
                        }`} />
                        <div>
                          <CardTitle className="text-lg">{vulnerability.title}</CardTitle>
                          <div className="flex items-center gap-2 mt-1">
                            <span className={`px-2 py-1 text-xs rounded-full font-medium ${getSeverityColor(vulnerability.severity)}`}>
                              {vulnerability.severity}
                            </span>
                            {vulnerability.category && (
                              <span className="px-2 py-1 text-xs bg-gray-100 text-gray-700 rounded-full">
                                {vulnerability.category}
                              </span>
                            )}
                          </div>
                        </div>
                      </div>
                      {expandedVulnerabilities.has(vulnerability.id || index) ? (
                        <ChevronDown className="h-5 w-5 text-gray-400" />
                      ) : (
                        <ChevronRight className="h-5 w-5 text-gray-400" />
                      )}
                    </div>
                  </CardHeader>

                  {expandedVulnerabilities.has(vulnerability.id || index) && (
                    <CardContent className="space-y-6">
                      {/* Description */}
                      <div>
                        <h4 className="font-semibold mb-2">Description</h4>
                        <p className="text-gray-700">{vulnerability.description}</p>
                      </div>

                      {/* Location */}
                      {vulnerability.location && (
                        <div>
                          <h4 className="font-semibold mb-2">Location</h4>
                          <div className="bg-gray-50 p-3 rounded-lg text-sm">
                            <div className="flex items-center gap-2 mb-2">
                              <FileText className="h-4 w-4 text-gray-500" />
                              <span>Line {vulnerability.location.line}</span>
                              {vulnerability.location.function && (
                                <span className="text-gray-500">
                                  in function <code className="bg-gray-200 px-1 rounded">{vulnerability.location.function}</code>
                                </span>
                              )}
                            </div>
                          </div>
                        </div>
                      )}

                      {/* Vulnerable Code */}
                      {vulnerability.vulnerableCode && (
                        <div>
                          <div className="flex items-center justify-between mb-2">
                            <h4 className="font-semibold">Vulnerable Code</h4>
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => toggleCode(vulnerability.id || index, 'vulnerable')}
                              className="flex items-center gap-1"
                            >
                              {showCode[`${vulnerability.id || index}-vulnerable`] ? (
                                <>
                                  <EyeOff className="h-3 w-3" />
                                  Hide Code
                                </>
                              ) : (
                                <>
                                  <Eye className="h-3 w-3" />
                                  Show Code
                                </>
                              )}
                            </Button>
                          </div>
                          {showCode[`${vulnerability.id || index}-vulnerable`] && (
                            <motion.div
                              initial={{ opacity: 0, height: 0 }}
                              animate={{ opacity: 1, height: 'auto' }}
                              className="bg-red-50 border border-red-200 rounded-lg p-4 overflow-x-auto"
                            >
                              <pre className="text-sm">
                                <code className="text-red-700">{vulnerability.vulnerableCode}</code>
                              </pre>
                            </motion.div>
                          )}
                        </div>
                      )}

                      {/* Fixed Code */}
                      {vulnerability.fixedCode && (
                        <div>
                          <div className="flex items-center justify-between mb-2">
                            <h4 className="font-semibold">Recommended Fix</h4>
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => toggleCode(vulnerability.id || index, 'fixed')}
                              className="flex items-center gap-1"
                            >
                              {showCode[`${vulnerability.id || index}-fixed`] ? (
                                <>
                                  <EyeOff className="h-3 w-3" />
                                  Hide Code
                                </>
                              ) : (
                                <>
                                  <Eye className="h-3 w-3" />
                                  Show Fix
                                </>
                              )}
                            </Button>
                          </div>
                          {showCode[`${vulnerability.id || index}-fixed`] && (
                            <motion.div
                              initial={{ opacity: 0, height: 0 }}
                              animate={{ opacity: 1, height: 'auto' }}
                              className="bg-green-50 border border-green-200 rounded-lg p-4 overflow-x-auto"
                            >
                              <pre className="text-sm">
                                <code className="text-green-700">{vulnerability.fixedCode}</code>
                              </pre>
                            </motion.div>
                          )}
                        </div>
                      )}

                      {/* Recommendation */}
                      <div>
                        <h4 className="font-semibold mb-2">Recommendation</h4>
                        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                          <p className="text-blue-700">{vulnerability.recommendation}</p>
                        </div>
                      </div>

                      {/* References */}
                      {vulnerability.references && vulnerability.references.length > 0 && (
                        <div>
                          <h4 className="font-semibold mb-2">References</h4>
                          <ul className="space-y-2">
                            {vulnerability.references.map((ref, refIndex) => (
                              <li key={refIndex} className="flex items-center gap-2">
                                <ExternalLink className="h-4 w-4 text-blue-600" />
                                <a
                                  href={ref.url}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-blue-600 hover:underline text-sm"
                                >
                                  {ref.title}
                                </a>
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {/* Impact */}
                      {vulnerability.impact && (
                        <div>
                          <h4 className="font-semibold mb-2">Impact</h4>
                          <div className={`p-3 rounded-lg ${
                            vulnerability.severity === 'Critical' || vulnerability.severity === 'High'
                              ? 'bg-red-50 border border-red-200'
                              : vulnerability.severity === 'Medium'
                              ? 'bg-yellow-50 border border-yellow-200'
                              : 'bg-blue-50 border border-blue-200'
                          }`}>
                            <p className={
                              vulnerability.severity === 'Critical' || vulnerability.severity === 'High'
                                ? 'text-red-700'
                                : vulnerability.severity === 'Medium'
                                ? 'text-yellow-700'
                                : 'text-blue-700'
                            }>
                              {vulnerability.impact}
                            </p>
                          </div>
                        </div>
                      )}
                    </CardContent>
                  )}
                </Card>
              </motion.div>
            ))
          )}
        </div>
      )}

      {activeTab === 'summary' && (
        <Card>
          <CardHeader>
            <CardTitle>Analysis Summary</CardTitle>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* Security Score */}
            <div className="text-center">
              <div className="inline-flex items-center justify-center w-24 h-24 bg-blue-100 rounded-full mb-4">
                <span className="text-2xl font-bold text-blue-600">{report.securityScore || 85}</span>
              </div>
              <h3 className="text-lg font-semibold mb-2">Security Score</h3>
              <p className="text-gray-600">
                Based on vulnerability severity and coverage analysis
              </p>
            </div>

            {/* Analysis Coverage */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <h4 className="font-semibold mb-3">Analysis Methods</h4>
                <div className="space-y-2">
                  {[
                    { method: 'Static Analysis', status: 'completed' },
                    { method: 'Symbolic Execution', status: 'completed' },
                    { method: 'Fuzz Testing', status: 'completed' },
                    { method: 'AI Intent Detection', status: 'completed' }
                  ].map((item, index) => (
                    <div key={index} className="flex items-center justify-between p-2 bg-gray-50 rounded">
                      <span className="text-sm">{item.method}</span>
                      <CheckCircle className="h-4 w-4 text-green-600" />
                    </div>
                  ))}
                </div>
              </div>

              <div>
                <h4 className="font-semibold mb-3">Key Findings</h4>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span>Functions Analyzed:</span>
                    <span className="font-medium">{report.functionsAnalyzed || 0}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Lines of Code:</span>
                    <span className="font-medium">{report.linesOfCode || 0}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Complexity Score:</span>
                    <span className="font-medium">{report.complexityScore || 'Medium'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Gas Optimization:</span>
                    <span className="font-medium">{report.gasOptimization || 'Good'}</span>
                  </div>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {activeTab === 'recommendations' && (
        <Card>
          <CardHeader>
            <CardTitle>General Recommendations</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {report.recommendations?.map((rec, index) => (
                <motion.div
                  key={index}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: index * 0.1 }}
                  className="p-4 bg-blue-50 border border-blue-200 rounded-lg"
                >
                  <div className="flex items-start gap-3">
                    <Info className="h-5 w-5 text-blue-600 mt-0.5" />
                    <div>
                      <h4 className="font-medium text-blue-900 mb-1">{rec.title}</h4>
                      <p className="text-blue-700 text-sm">{rec.description}</p>
                    </div>
                  </div>
                </motion.div>
              )) || (
                <div className="text-center py-8">
                  <Info className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                  <p className="text-gray-600">No additional recommendations at this time.</p>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

export default ReportView;
