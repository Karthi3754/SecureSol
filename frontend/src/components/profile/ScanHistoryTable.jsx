import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { 
  FileText, 
  Download, 
  Eye, 
  Calendar,
  Filter,
  Search,
  AlertTriangle,
  CheckCircle,
  Clock
} from 'lucide-react';
import { Button } from '../ui/Button';
import { Input } from '../ui/Input';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/Card';
import { useApi } from '../../hooks/useApi';
import { scanService } from '../../services/scanService';
import { formatDate, getSeverityColor } from '../../lib/utils';

const ScanHistoryTable = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [sortBy, setSortBy] = useState('date');
  
  const { data, loading, refetch } = useApi('/scan/history');
  const scans = Array.isArray(data) ? data : data?.scans || []; // ✅ ensure array

  const getStatusIcon = (status) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="h-4 w-4 text-green-600" />;
      case 'failed':
        return <AlertTriangle className="h-4 w-4 text-red-600" />;
      case 'processing':
        return <Clock className="h-4 w-4 text-yellow-600" />;
      default:
        return <Clock className="h-4 w-4 text-gray-600" />;
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'completed':
        return 'text-green-600 bg-green-50 border-green-200';
      case 'failed':
        return 'text-red-600 bg-red-50 border-red-200';
      case 'processing':
        return 'text-yellow-600 bg-yellow-50 border-yellow-200';
      default:
        return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  const handleDownload = async (scanId, format) => {
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

  const filteredScans = scans
    .filter(scan => {
      const matchesSearch = scan.contractName?.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          scan.id?.toLowerCase().includes(searchTerm.toLowerCase());
      const matchesStatus = statusFilter === 'all' || scan.status === statusFilter;
      return matchesSearch && matchesStatus;
    })
    .sort((a, b) => {
      switch (sortBy) {
        case 'date':
          return new Date(b.createdAt) - new Date(a.createdAt);
        case 'name':
          return (a.contractName || '').localeCompare(b.contractName || '');
        case 'status':
          return a.status.localeCompare(b.status);
        default:
          return 0;
      }
    });

  if (loading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileText className="h-5 w-5" />
            Scan History
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="animate-pulse">
            <div className="h-4 bg-gray-200 rounded w-1/4 mb-4"></div>
            {[1, 2, 3].map((i) => (
              <div key={i} className="flex items-center space-x-4 py-4 border-b">
                <div className="h-4 bg-gray-200 rounded w-1/4"></div>
                <div className="h-4 bg-gray-200 rounded w-1/6"></div>
                <div className="h-4 bg-gray-200 rounded w-1/6"></div>
                <div className="h-4 bg-gray-200 rounded w-1/4"></div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <FileText className="h-5 w-5" />
          Scan History
        </CardTitle>
      </CardHeader>
      
      <CardContent className="space-y-6">
        {/* Filters */}
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 h-4 w-4" />
            <Input
              placeholder="Search by contract name or scan ID..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-10"
            />
          </div>
          
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-2 border border-gray-300 rounded-md bg-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="all">All Status</option>
            <option value="completed">Completed</option>
            <option value="processing">Processing</option>
            <option value="failed">Failed</option>
          </select>

          <select
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value)}
            className="px-3 py-2 border border-gray-300 rounded-md bg-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="date">Sort by Date</option>
            <option value="name">Sort by Name</option>
            <option value="status">Sort by Status</option>
          </select>
        </div>

        {/* Table */}
        {filteredScans.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-200">
                  <th className="text-left py-3 px-4 font-medium text-gray-900">Contract</th>
                  <th className="text-left py-3 px-4 font-medium text-gray-900">Date</th>
                  <th className="text-left py-3 px-4 font-medium text-gray-900">Status</th>
                  <th className="text-left py-3 px-4 font-medium text-gray-900">Vulnerabilities</th>
                  <th className="text-left py-3 px-4 font-medium text-gray-900">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredScans.map((scan, index) => (
                  <motion.tr
                    key={scan.id}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: index * 0.1 }}
                    className="border-b border-gray-100 hover:bg-gray-50"
                  >
                    <td className="py-4 px-4">
                      <div>
                        <div className="font-medium text-gray-900">
                          {scan.contractName || 'Unnamed Contract'}
                        </div>
                        <div className="text-sm text-gray-500">
                          ID: {scan.id?.slice(0, 8)}...
                        </div>
                      </div>
                    </td>
                    
                    <td className="py-4 px-4">
                      <div className="flex items-center gap-2 text-sm text-gray-600">
                        <Calendar className="h-4 w-4" />
                        {formatDate(scan.createdAt)}
                      </div>
                    </td>
                    
                    <td className="py-4 px-4">
                      <div className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium border ${getStatusColor(scan.status)}`}>
                        {getStatusIcon(scan.status)}
                        {scan.status.charAt(0).toUpperCase() + scan.status.slice(1)}
                      </div>
                    </td>
                    
                    <td className="py-4 px-4">
                      {scan.status === 'completed' ? (
                        <div className="space-y-1">
                          {scan.vulnerabilities?.length > 0 ? (
                            <div className="flex gap-1">
                              {['critical', 'high', 'medium', 'low'].map(severity => {
                                const count = scan.vulnerabilities.filter(
                                  v => v.severity?.toLowerCase() === severity
                                ).length;
                                if (count === 0) return null;
                                return (
                                  <span
                                    key={severity}
                                    className={`px-2 py-1 text-xs rounded-full ${getSeverityColor(severity)}`}
                                  >
                                    {count} {severity}
                                  </span>
                                );
                              })}
                            </div>
                          ) : (
                            <span className="text-sm text-green-600">No issues found</span>
                          )}
                        </div>
                      ) : (
                        <span className="text-sm text-gray-400">-</span>
                      )}
                    </td>
                    
                    <td className="py-4 px-4">
                      <div className="flex items-center gap-2">
                        {scan.status === 'completed' && (
                          <>
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => window.open(`/scan/${scan.id}`, '_blank')}
                              className="flex items-center gap-1"
                            >
                              <Eye className="h-3 w-3" />
                              View
                            </Button>
                            
                            <div className="relative group">
                              <Button
                                variant="outline"
                                size="sm"
                                className="flex items-center gap-1"
                              >
                                <Download className="h-3 w-3" />
                                Download
                              </Button>
                              
                              {/* Download Dropdown */}
                              <div className="absolute right-0 top-full mt-1 w-32 bg-white border border-gray-200 rounded-md shadow-lg opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all z-10">
                                <button
                                  onClick={() => handleDownload(scan.id, 'pdf')}
                                  className="w-full px-3 py-2 text-left text-sm hover:bg-gray-50 first:rounded-t-md"
                                >
                                  PDF Report
                                </button>
                                <button
                                  onClick={() => handleDownload(scan.id, 'json')}
                                  className="w-full px-3 py-2 text-left text-sm hover:bg-gray-50 last:rounded-b-md"
                                >
                                  JSON Data
                                </button>
                              </div>
                            </div>
                          </>
                        )}
                        
                        {scan.status === 'processing' && (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => window.open(`/scan/${scan.id}`, '_blank')}
                            className="flex items-center gap-1"
                          >
                            <Clock className="h-3 w-3" />
                            View Progress
                          </Button>
                        )}
                      </div>
                    </td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="text-center py-12"
          >
            <FileText className="h-16 w-16 text-gray-400 mx-auto mb-4" />
            <h3 className="text-lg font-semibold text-gray-900 mb-2">
              {searchTerm || statusFilter !== 'all' ? 'No matching scans found' : 'No scans yet'}
            </h3>
            <p className="text-gray-600 mb-6">
              {searchTerm || statusFilter !== 'all' 
                ? 'Try adjusting your search or filter criteria'
                : 'Upload your first smart contract to get started with security analysis'
              }
            </p>
            {(!searchTerm && statusFilter === 'all') && (
              <Button onClick={() => window.location.href = '/scan/new'}>
                Start Your First Scan
              </Button>
            )}
          </motion.div>
        )}
      </CardContent>
    </Card>
  );
};

export default ScanHistoryTable;
