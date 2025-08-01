import React, { useState, useEffect } from "react";
import "./App.css";
import axios from "axios";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

function App() {
  const [selectedFile, setSelectedFile] = useState(null);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [dragActive, setDragActive] = useState(false);
  const [analyses, setAnalyses] = useState([]);
  
  // Gmail integration state
  const [gmailConfig, setGmailConfig] = useState({
    client_id: '',
    client_secret: '',
    refresh_token: ''
  });
  const [gmailStatus, setGmailStatus] = useState({
    configured: false,
    monitoring_active: false
  });
  const [monitoringConfig, setMonitoringConfig] = useState({
    alert_email: '',
    check_interval: 60
  });
  const [showGmailSetup, setShowGmailSetup] = useState(false);
  const [showImapSetup, setShowImapSetup] = useState(false);
  const [showDashboard, setShowDashboard] = useState(false);
  const [dashboardStats, setDashboardStats] = useState({
    totalProcessed: 0,
    threatsFound: 0,
    lastScan: null,
    uptime: '0m',
    alertsSent: 0
  });
  const [imapConfig, setImapConfig] = useState({
    email: '',
    app_password: ''
  });
  const [connectionMethod, setConnectionMethod] = useState('imap'); // 'gmail' or 'imap'
  const [manualScanLoading, setManualScanLoading] = useState(false);
  const [scanResults, setScanResults] = useState(null);
  
  // Email analysis details
  const [showAnalysisDetails, setShowAnalysisDetails] = useState(false);
  const [selectedAnalysis, setSelectedAnalysis] = useState(null);
  const [analysisDetailsLoading, setAnalysisDetailsLoading] = useState(false);
  
  // Enterprise features
  const [showEnterprisePanel, setShowEnterprisePanel] = useState(false);
  const [showBlockedEmails, setShowBlockedEmails] = useState(false);
  const [enterpriseAccounts, setEnterpriseAccounts] = useState([]);
  const [blockedEmails, setBlockedEmails] = useState([]);
  const [enterpriseStats, setEnterpriseStats] = useState({});
  const [newAccount, setNewAccount] = useState({
    email: '',
    app_password: '',
    employee_name: '',
    department: '',
    alert_email: ''
  });

  useEffect(() => {
    fetchAnalyses();
    checkGmailStatus();
    fetchDashboardStats();
    fetchEnterpriseData();
    
    // Update dashboard stats every 30 seconds
    const interval = setInterval(() => {
      fetchDashboardStats();
      checkGmailStatus();
      fetchEnterpriseData();
    }, 30000);
    
    return () => clearInterval(interval);
  }, []);

  const fetchEnterpriseData = async () => {
    try {
      const [accountsRes, statsRes] = await Promise.all([
        axios.get(`${API}/enterprise/accounts`),
        axios.get(`${API}/enterprise/stats`)
      ]);
      
      setEnterpriseAccounts(accountsRes.data.accounts || []);
      setEnterpriseStats(statsRes.data.enterprise_stats || {});
    } catch (error) {
      console.error('Error fetching enterprise data:', error);
    }
  };

  const fetchBlockedEmails = async () => {
    try {
      const response = await axios.get(`${API}/enterprise/blocked-emails?limit=50`);
      setBlockedEmails(response.data.blocked_emails || []);
    } catch (error) {
      console.error('Error fetching blocked emails:', error);
    }
  };

  const fetchDashboardStats = async () => {
    try {
      const response = await axios.get(`${API}/monitoring/stats`);
      setDashboardStats(response.data);
    } catch (error) {
      console.error('Error fetching dashboard stats:', error);
    }
  };

  const fetchAnalyses = async () => {
    try {
      const response = await axios.get(`${API}/analyses`);
      setAnalyses(response.data.slice(0, 5));
    } catch (error) {
      console.error('Error fetching analyses:', error);
    }
  };

  const checkGmailStatus = async () => {
    try {
      let response;
      if (connectionMethod === 'imap') {
        response = await axios.get(`${API}/imap/status`);
      } else {
        response = await axios.get(`${API}/gmail/status`);
      }
      setGmailStatus(response.data);
    } catch (error) {
      console.error('Error checking Gmail status:', error);
    }
  };

  const setupImap = async () => {
    try {
      setLoading(true);
      const response = await axios.post(`${API}/imap/setup`, imapConfig);
      
      if (response.data.success) {
        alert('✅ IMAP setup successful! You can now start monitoring.');
        await checkGmailStatus();
        setShowImapSetup(false);
      } else {
        const errorDetails = response.data.connection_test?.details || '';
        alert(`❌ IMAP setup failed: ${response.data.message}\n\n${errorDetails}`);
      }
    } catch (error) {
      const errorMsg = error.response?.data?.detail || error.message;
      alert(`❌ IMAP setup failed: ${errorMsg}`);
    } finally {
      setLoading(false);
    }
  };

  const testImapConnection = async () => {
    try {
      setLoading(true);
      
      // Just test the connection without saving
      const testService = {
        email_address: imapConfig.email,
        app_password: imapConfig.app_password
      };
      
      const response = await axios.post(`${API}/imap/test-connection`, testService);
      
      if (response.data.status === 'success') {
        alert(`✅ Connection Test Successful!\n\n${response.data.message}\n\nFound ${response.data.total_messages} messages in inbox.`);
      } else {
        alert(`❌ Connection Test Failed!\n\n${response.data.message}\n\n${response.data.details || ''}`);
      }
    } catch (error) {
      const errorMsg = error.response?.data?.detail || error.message;
      alert(`❌ Connection test failed: ${errorMsg}`);
    } finally {
      setLoading(false);
    }
  };

  const handleFileSelect = (event) => {
    const file = event.target.files[0];
    setSelectedFile(file);
  };

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setSelectedFile(e.dataTransfer.files[0]);
    }
  };

  const analyzeEmail = async () => {
    if (!selectedFile) return;

    setLoading(true);
    const formData = new FormData();
    formData.append('file', selectedFile);

    try {
      const response = await axios.post(`${API}/analyze-email`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      
      setAnalysisResult(response.data.analysis);
      fetchAnalyses(); // Refresh the list
    } catch (error) {
      console.error('Error analyzing email:', error);
      setAnalysisResult({
        error: 'Failed to analyze email. Please try again.',
        threat_level: 'UNKNOWN'
      });
    } finally {
      setLoading(false);
    }
  };

  const getThreatColor = (level) => {
    switch (level) {
      case 'CRITICAL': return 'text-red-600 bg-red-100';
      case 'HIGH': return 'text-orange-600 bg-orange-100';
      case 'MEDIUM': return 'text-yellow-600 bg-yellow-100';
      case 'LOW': return 'text-green-600 bg-green-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getThreatIcon = (level) => {
    switch (level) {
      case 'CRITICAL': return '🚨';
      case 'HIGH': return '⚠️';
      case 'MEDIUM': return '⚡';
      case 'LOW': return '✅';
      default: return '❓';
    }
  };

  const resetAnalysis = () => {
    setSelectedFile(null);
    setAnalysisResult(null);
  };

  // Gmail Integration Functions
  const setupGmail = async () => {
    try {
      setLoading(true);
      const response = await axios.post(`${API}/gmail/setup`, gmailConfig);
      
      if (response.data.auth_url) {
        alert(`Please visit this URL to authorize: ${response.data.auth_url}`);
      } else {
        alert('Gmail setup successful!');
        await checkGmailStatus();
        setShowGmailSetup(false);
      }
    } catch (error) {
      alert(`Gmail setup failed: ${error.response?.data?.detail || error.message}`);
    } finally {
      setLoading(false);
    }
  };

  const startMonitoring = async () => {
    try {
      setLoading(true);
      const response = await axios.post(`${API}/imap/start-monitoring`, monitoringConfig);
      alert(response.data.message);
      await checkGmailStatus();
    } catch (error) {
      alert(`Failed to start monitoring: ${error.response?.data?.detail || error.message}`);
    } finally {
      setLoading(false);
    }
  };

  const stopMonitoring = async () => {
    try {
      setLoading(true);
      const response = await axios.post(`${API}/imap/stop-monitoring`);
      alert(response.data.message);
      await checkGmailStatus();
    } catch (error) {
      alert(`Failed to stop monitoring: ${error.response?.data?.detail || error.message}`);
    } finally {
      setLoading(false);
    }
  };

  const fetchAnalysisDetails = async (analysisId) => {
    try {
      setAnalysisDetailsLoading(true);
      const response = await axios.get(`${API}/analyses/${analysisId}`);
      
      if (response.data.success) {
        setSelectedAnalysis(response.data.analysis);
        setShowAnalysisDetails(true);
      } else {
        alert('Failed to load analysis details');
      }
    } catch (error) {
      console.error('Error fetching analysis details:', error);
      alert(`Failed to load analysis details: ${error.response?.data?.detail || error.message}`);
    } finally {
      setAnalysisDetailsLoading(false);
    }
  };

  const manualScan = async () => {
    try {
      setManualScanLoading(true);
      const response = await axios.post(`${API}/imap/manual-scan`, { max_emails: 50 });
      setScanResults(response.data.results);
      await fetchAnalyses(); // Refresh analyses
    } catch (error) {
      alert(`Manual scan failed: ${error.response?.data?.detail || error.message}`);
    } finally {
      setManualScanLoading(false);
    }
  };

  const testDetection = async () => {
    try {
      setLoading(true);
      const response = await axios.get(`${API}/debug/analyze-sample`);
      
      if (response.data.success) {
        const analysis = response.data.analysis;
        const summary = response.data.detection_summary;
        
        alert(`🧪 Detection Test Results:
        
📧 Sample: ${response.data.sample_email}
🎯 Threat Level: ${summary.threat_level}
🔗 URL Threats: ${summary.url_threats}
👤 Sender Issues: ${summary.sender_issues}  
🧠 Social Engineering: ${summary.social_engineering}
🛡️ Advanced Threats: ${summary.advanced_url_threats}
📊 Overall Risk: ${summary.overall_risk}

${summary.threat_level === 'CRITICAL' || summary.threat_level === 'HIGH' ? 
  '✅ Detection Working! This would trigger alerts.' : 
  '⚠️ Detection may need tuning.'}`);
      }
    } catch (error) {
      alert(`Test failed: ${error.response?.data?.detail || error.message}`);
    } finally {
      setLoading(false);
    }
  };

  // Enterprise functions
  const addEnterpriseAccount = async () => {
    try {
      setLoading(true);
      const response = await axios.post(`${API}/enterprise/accounts/add`, newAccount);
      
      if (response.data.success) {
        alert(`✅ Account added: ${newAccount.employee_name || newAccount.email}`);
        setNewAccount({
          email: '',
          app_password: '',
          employee_name: '',
          department: '',
          alert_email: ''
        });
        await fetchEnterpriseData();
      }
    } catch (error) {
      alert(`❌ Failed to add account: ${error.response?.data?.detail || error.message}`);
    } finally {
      setLoading(false);
    }
  };

  const startAccountMonitoring = async (email) => {
    try {
      const response = await axios.post(`${API}/enterprise/accounts/${email}/start-monitoring`);
      alert(`✅ ${response.data.message}`);
      await fetchEnterpriseData();
    } catch (error) {
      alert(`❌ Failed to start monitoring: ${error.response?.data?.detail || error.message}`);
    }
  };

  const stopAccountMonitoring = async (email) => {
    try {
      const response = await axios.post(`${API}/enterprise/accounts/${email}/stop-monitoring`);
      alert(`✅ ${response.data.message}`);
      await fetchEnterpriseData();
    } catch (error) {
      alert(`❌ Failed to stop monitoring: ${error.response?.data?.detail || error.message}`);
    }
  };

  const startAllMonitoring = async () => {
    try {
      setLoading(true);
      const response = await axios.post(`${API}/enterprise/monitoring/start-all`);
      alert(`✅ ${response.data.message}`);
      await fetchEnterpriseData();
    } catch (error) {
      alert(`❌ Failed to start monitoring: ${error.response?.data?.detail || error.message}`);
    } finally {
      setLoading(false);
    }
  };

  const stopAllMonitoring = async () => {
    try {
      setLoading(true);
      const response = await axios.post(`${API}/enterprise/monitoring/stop-all`);
      alert(`✅ ${response.data.message}`);
      await fetchEnterpriseData();
    } catch (error) {
      alert(`❌ Failed to stop monitoring: ${error.response?.data?.detail || error.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="py-6">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <div className="w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center">
                  <span className="text-white font-bold text-xl">🛡️</span>
                </div>
              </div>
              <div className="ml-4">
                <h1 className="text-2xl font-bold text-gray-900">
                  Email Phishing Detector
                </h1>
                <p className="text-sm text-gray-600">
                  Advanced AI-powered email security analysis
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        
        {/* Gmail Integration Status Bar */}
        <div className="mb-6 bg-white rounded-xl shadow-sm border border-gray-200 p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center">
              <div className={`w-3 h-3 rounded-full mr-3 ${gmailStatus.configured ? 'bg-green-500' : 'bg-red-500'}`}></div>
              <div>
                <h3 className="font-medium text-gray-900">
                  Gmail Integration {gmailStatus.configured ? 'Connected' : 'Not Connected'}
                </h3>
                <p className="text-sm text-gray-600">
                  {gmailStatus.monitoring_active ? '🟢 Real-time monitoring active' : '⏸️ Monitoring inactive'}
                  {gmailStatus.configured && (
                    <span className="ml-2 text-xs bg-blue-100 text-blue-600 px-2 py-1 rounded">
                      {connectionMethod === 'imap' ? 'IMAP' : 'OAuth'}
                    </span>
                  )}
                </p>
              </div>
            </div>
            <div className="flex space-x-2">
              {!gmailStatus.configured && (
                <select 
                  value={connectionMethod} 
                  onChange={(e) => setConnectionMethod(e.target.value)}
                  className="px-2 py-1 text-sm border rounded-lg"
                >
                  <option value="imap">IMAP (Recommended)</option>
                  <option value="gmail">Gmail OAuth</option>
                </select>
              )}
              <button
                onClick={() => {
                  if (connectionMethod === 'imap') {
                    setShowImapSetup(!showImapSetup);
                    setShowGmailSetup(false);
                  } else {
                    setShowGmailSetup(!showGmailSetup);
                    setShowImapSetup(false);
                  }
                }}
                className="px-3 py-1 text-sm bg-blue-100 text-blue-700 rounded-lg hover:bg-blue-200"
              >
                Setup
              </button>
              {gmailStatus.configured && (
                <>
                  <button
                    onClick={gmailStatus.monitoring_active ? stopMonitoring : startMonitoring}
                    disabled={loading}
                    className={`px-3 py-1 text-sm rounded-lg ${
                      gmailStatus.monitoring_active 
                        ? 'bg-red-100 text-red-700 hover:bg-red-200' 
                        : 'bg-green-100 text-green-700 hover:bg-green-200'
                    }`}
                  >
                    {gmailStatus.monitoring_active ? 'Stop' : 'Start'} Monitoring
                  </button>
                  <button
                    onClick={manualScan}
                    disabled={manualScanLoading}
                    className="px-3 py-1 text-sm bg-purple-100 text-purple-700 rounded-lg hover:bg-purple-200"
                  >
                    {manualScanLoading ? 'Scanning...' : 'Manual Scan'}
                  </button>
                  <button
                    onClick={testDetection}
                    disabled={loading}
                    className="px-3 py-1 text-sm bg-orange-100 text-orange-700 rounded-lg hover:bg-orange-200"
                  >
                    Test Detection
                  </button>
                  <button
                    onClick={() => setShowDashboard(!showDashboard)}
                    className="px-3 py-1 text-sm bg-indigo-100 text-indigo-700 rounded-lg hover:bg-indigo-200"
                  >
                    Dashboard
                  </button>
                  <button
                    onClick={() => setShowEnterprisePanel(!showEnterprisePanel)}
                    className="px-3 py-1 text-sm bg-emerald-100 text-emerald-700 rounded-lg hover:bg-emerald-200"
                  >
                    Enterprise
                  </button>
                  <button
                    onClick={() => {
                      setShowBlockedEmails(!showBlockedEmails);
                      if (!showBlockedEmails) fetchBlockedEmails();
                    }}
                    className="px-3 py-1 text-sm bg-red-100 text-red-700 rounded-lg hover:bg-red-200"
                  >
                    Blocked Emails
                  </button>
                </>
              )}
            </div>
          </div>
        </div>

        {/* IMAP Setup Panel */}
        {showImapSetup && (
          <div className="mb-6 bg-white rounded-xl shadow-sm border border-gray-200 p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">
              Gmail IMAP Setup (Recommended)
            </h3>
            
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-4">
              <div className="flex items-start">
                <div className="text-blue-500 mr-2">ℹ️</div>
                <div className="text-sm text-blue-800">
                  <p className="font-medium mb-2">How to get Gmail App Password:</p>
                  <ol className="list-decimal list-inside space-y-1">
                    <li>Go to Google Account settings</li>
                    <li>Enable 2-Factor Authentication</li>
                    <li>Go to "App passwords" section</li>
                    <li>Generate password for "Mail" app</li>
                    <li>Use that 16-character password below</li>
                  </ol>
                  <a 
                    href="https://myaccount.google.com/apppasswords" 
                    target="_blank" 
                    rel="noopener noreferrer"
                    className="text-blue-600 underline mt-2 inline-block"
                  >
                    → Generate App Password
                  </a>
                </div>
              </div>
            </div>
            
            <div className="grid grid-cols-1 gap-4 mb-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Gmail Address</label>
                <input
                  type="email"
                  value={imapConfig.email}
                  onChange={(e) => setImapConfig({...imapConfig, email: e.target.value})}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  placeholder="your-email@gmail.com"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">App Password</label>
                <input
                  type="password"
                  value={imapConfig.app_password}
                  onChange={(e) => setImapConfig({...imapConfig, app_password: e.target.value.replace(/\s+/g, '')})}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  placeholder="16-character app password (no spaces)"
                  maxLength="16"
                />
                <p className="text-xs text-gray-500 mt-1">
                  Format: abcdefghijklmnop (16 characters, no spaces)
                </p>
              </div>
            </div>

            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-700 mb-1">Alert Email</label>
              <input
                type="email"
                value={monitoringConfig.alert_email}
                onChange={(e) => setMonitoringConfig({...monitoringConfig, alert_email: e.target.value})}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                placeholder="alerts@yourdomain.com"
              />
            </div>
            
            <div className="flex gap-2">
              <button
                onClick={setupImap}
                disabled={
                  loading || 
                  !imapConfig.email || 
                  !imapConfig.app_password || 
                  imapConfig.app_password.length !== 16 ||
                  !imapConfig.email.includes('@gmail.com')
                }
                className="flex-1 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? 'Testing IMAP Connection...' : 'Setup IMAP Connection'}
              </button>
              
              <button
                onClick={testImapConnection}
                disabled={
                  loading || 
                  !imapConfig.email || 
                  !imapConfig.app_password ||
                  imapConfig.app_password.length !== 16
                }
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? 'Testing...' : 'Quick Test'}
              </button>
            </div>
            
            {(!imapConfig.email.includes('@gmail.com') && imapConfig.email) && (
              <p className="text-red-500 text-sm mt-2">⚠️ Please use a Gmail address</p>
            )}
            
            {(imapConfig.app_password && imapConfig.app_password.length !== 16) && (
              <p className="text-red-500 text-sm mt-2">⚠️ App password must be exactly 16 characters</p>
            )}
          </div>
        )}

        {/* Gmail OAuth Setup Panel */}
        {showGmailSetup && (
          <div className="mb-6 bg-white rounded-xl shadow-sm border border-gray-200 p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Gmail API Setup</h3>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Client ID</label>
                <input
                  type="text"
                  value={gmailConfig.client_id}
                  onChange={(e) => setGmailConfig({...gmailConfig, client_id: e.target.value})}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  placeholder="Google Cloud Console Client ID"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Client Secret</label>
                <input
                  type="password"
                  value={gmailConfig.client_secret}
                  onChange={(e) => setGmailConfig({...gmailConfig, client_secret: e.target.value})}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  placeholder="Google Cloud Console Client Secret"
                />
              </div>
            </div>
            
            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-700 mb-1">Refresh Token (Optional)</label>
              <input
                type="text"
                value={gmailConfig.refresh_token}
                onChange={(e) => setGmailConfig({...gmailConfig, refresh_token: e.target.value})}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                placeholder="Leave empty to generate new token"
              />
            </div>

            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-700 mb-1">Alert Email</label>
              <input
                type="email"
                value={monitoringConfig.alert_email}
                onChange={(e) => setMonitoringConfig({...monitoringConfig, alert_email: e.target.value})}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                placeholder="your-email@gmail.com"
              />
            </div>
            
            <button
              onClick={setupGmail}
              disabled={loading || !gmailConfig.client_id || !gmailConfig.client_secret}
              className="w-full py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? 'Setting up...' : 'Setup Gmail Integration'}
            </button>
          </div>
        )}

        {/* Enterprise Management Panel */}
        {showEnterprisePanel && (
          <div className="mb-6 bg-white rounded-xl shadow-sm border border-gray-200 p-6">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-lg font-semibold text-gray-900">🏢 Enterprise Account Management</h3>
              <button
                onClick={() => setShowEnterprisePanel(false)}
                className="text-gray-400 hover:text-gray-600"
              >
                ✕
              </button>
            </div>
            
            {/* Enterprise Statistics */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
              <div className="bg-blue-50 rounded-lg p-4">
                <div className="text-blue-600 text-2xl mb-2">👥</div>
                <p className="text-sm text-blue-600 font-medium">Total Accounts</p>
                <p className="text-2xl font-bold text-blue-900">
                  {enterpriseStats.accounts?.total || enterpriseAccounts.length}
                </p>
              </div>
              
              <div className="bg-green-50 rounded-lg p-4">
                <div className="text-green-600 text-2xl mb-2">📡</div>
                <p className="text-sm text-green-600 font-medium">Active Monitoring</p>
                <p className="text-2xl font-bold text-green-900">
                  {enterpriseStats.accounts?.monitoring_active || enterpriseAccounts.filter(a => a.monitoring_active).length}
                </p>
              </div>
              
              <div className="bg-orange-50 rounded-lg p-4">
                <div className="text-orange-600 text-2xl mb-2">📧</div>
                <p className="text-sm text-orange-600 font-medium">Emails Processed</p>
                <p className="text-2xl font-bold text-orange-900">
                  {enterpriseStats.emails?.total_processed || 0}
                </p>
              </div>
              
              <div className="bg-red-50 rounded-lg p-4">
                <div className="text-red-600 text-2xl mb-2">🚨</div>
                <p className="text-sm text-red-600 font-medium">Threats Blocked</p>
                <p className="text-2xl font-bold text-red-900">
                  {enterpriseStats.emails?.total_threats || 0}
                </p>
              </div>
            </div>

            {/* Add New Account Form */}
            <div className="border border-gray-200 rounded-lg p-4 mb-6">
              <h4 className="font-semibold text-gray-900 mb-4">➕ Add New Employee Account</h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <input
                  type="email"
                  placeholder="employee@company.com"
                  value={newAccount.email}
                  onChange={(e) => setNewAccount({...newAccount, email: e.target.value})}
                  className="px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                />
                <input
                  type="password"
                  placeholder="16-character app password"
                  value={newAccount.app_password}
                  onChange={(e) => setNewAccount({...newAccount, app_password: e.target.value.replace(/\s+/g, '')})}
                  className="px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                  maxLength="16"
                />
                <input
                  type="text"
                  placeholder="Employee Name"
                  value={newAccount.employee_name}
                  onChange={(e) => setNewAccount({...newAccount, employee_name: e.target.value})}
                  className="px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                />
                <input
                  type="text"
                  placeholder="Department"
                  value={newAccount.department}
                  onChange={(e) => setNewAccount({...newAccount, department: e.target.value})}
                  className="px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                />
                <input
                  type="email"
                  placeholder="Security Alert Email (optional)"
                  value={newAccount.alert_email}
                  onChange={(e) => setNewAccount({...newAccount, alert_email: e.target.value})}
                  className="px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                />
                <button
                  onClick={addEnterpriseAccount}
                  disabled={loading || !newAccount.email || !newAccount.app_password || newAccount.app_password.length !== 16}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                >
                  {loading ? 'Adding...' : 'Add Account'}
                </button>
              </div>
            </div>

            {/* Mass Actions */}
            <div className="flex gap-2 mb-6">
              <button
                onClick={startAllMonitoring}
                disabled={loading}
                className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:opacity-50"
              >
                🚀 Start All Monitoring
              </button>
              <button
                onClick={stopAllMonitoring}
                disabled={loading}
                className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 disabled:opacity-50"
              >
                ⏸️ Stop All Monitoring
              </button>
            </div>

            {/* Account List */}
            <div className="border border-gray-200 rounded-lg">
              <div className="px-4 py-3 bg-gray-50 border-b border-gray-200">
                <h4 className="font-semibold text-gray-900">📋 Employee Accounts ({enterpriseAccounts.length})</h4>
              </div>
              <div className="divide-y divide-gray-200 max-h-96 overflow-y-auto">
                {enterpriseAccounts.length === 0 ? (
                  <div className="px-4 py-8 text-center text-gray-500">
                    No accounts configured yet. Add your first employee account above.
                  </div>
                ) : (
                  enterpriseAccounts.map((account, index) => (
                    <div key={index} className="px-4 py-3 hover:bg-gray-50">
                      <div className="flex items-center justify-between">
                        <div className="flex-1">
                          <div className="flex items-center">
                            <div className={`w-3 h-3 rounded-full mr-3 ${account.monitoring_active ? 'bg-green-500' : 'bg-gray-400'}`}></div>
                            <div>
                              <p className="font-medium text-gray-900">{account.employee_name || account.email}</p>
                              <p className="text-sm text-gray-600">{account.email}</p>
                              {account.department && (
                                <p className="text-xs text-gray-500">📍 {account.department}</p>
                              )}
                            </div>
                          </div>
                        </div>
                        
                        <div className="flex items-center space-x-2">
                          <div className="text-right text-sm">
                            <p className="text-gray-900 font-medium">
                              {account.total_processed || 0} processed
                            </p>
                            <p className="text-red-600">
                              {account.threats_blocked || 0} blocked
                            </p>
                          </div>
                          
                          <button
                            onClick={() => account.monitoring_active ? 
                              stopAccountMonitoring(account.email) : 
                              startAccountMonitoring(account.email)
                            }
                            className={`px-3 py-1 text-xs rounded-full ${
                              account.monitoring_active 
                                ? 'bg-red-100 text-red-700 hover:bg-red-200'
                                : 'bg-green-100 text-green-700 hover:bg-green-200'
                            }`}
                          >
                            {account.monitoring_active ? 'Stop' : 'Start'}
                          </button>
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        )}

        {/* Blocked Emails Panel */}
        {showBlockedEmails && (
          <div className="mb-6 bg-white rounded-xl shadow-sm border border-gray-200 p-6">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-lg font-semibold text-gray-900">🚫 Blocked Emails ({blockedEmails.length})</h3>
              <button
                onClick={() => setShowBlockedEmails(false)}
                className="text-gray-400 hover:text-gray-600"
              >
                ✕
              </button>
            </div>
            
            <div className="border border-gray-200 rounded-lg">
              <div className="px-4 py-3 bg-gray-50 border-b border-gray-200">
                <div className="grid grid-cols-5 gap-4 text-sm font-medium text-gray-700">
                  <div>Employee</div>
                  <div>From</div>
                  <div>Subject</div>
                  <div>Threat Level</div>
                  <div>Blocked Time</div>
                </div>
              </div>
              <div className="divide-y divide-gray-200 max-h-96 overflow-y-auto">
                {blockedEmails.length === 0 ? (
                  <div className="px-4 py-8 text-center text-gray-500">
                    No blocked emails yet. This is good news! 🎉
                  </div>
                ) : (
                  blockedEmails.map((email, index) => (
                    <div key={index} className="px-4 py-3 hover:bg-gray-50">
                      <div className="grid grid-cols-5 gap-4 text-sm">
                        <div>
                          <p className="font-medium text-gray-900">
                            {email.employee_name || 'Unknown'}
                          </p>
                          <p className="text-gray-600 text-xs">
                            {email.analysis_result?.monitored_account || 'N/A'}
                          </p>
                        </div>
                        <div className="truncate">
                          <p className="text-gray-900">
                            {email.analysis_result?.from || 'Unknown Sender'}
                          </p>
                        </div>
                        <div className="truncate">
                          <p className="text-gray-900">
                            {email.analysis_result?.subject || 'No Subject'}
                          </p>
                        </div>
                        <div>
                          <span className={`px-2 py-1 rounded-full text-xs font-medium ${getThreatColor(email.threat_level)}`}>
                            {email.threat_level}
                          </span>
                        </div>
                        <div className="text-gray-600">
                          {new Date(email.timestamp).toLocaleString()}
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        )}

        {/* Monitoring Dashboard */}
        {showDashboard && (
          <div className="mb-6 bg-white rounded-xl shadow-sm border border-gray-200 p-6">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-lg font-semibold text-gray-900">📊 Monitoring Dashboard</h3>
              <button
                onClick={() => setShowDashboard(false)}
                className="text-gray-400 hover:text-gray-600"
              >
                ✕
              </button>
            </div>
            
            {/* Status Overview */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
              <div className="bg-blue-50 rounded-lg p-4">
                <div className="flex items-center">
                  <div className="text-blue-600 text-2xl mr-3">🔍</div>
                  <div>
                    <p className="text-sm text-blue-600 font-medium">Connection Status</p>
                    <p className="text-lg font-bold text-blue-900">
                      {gmailStatus.configured ? 'Connected' : 'Disconnected'}
                    </p>
                  </div>
                </div>
              </div>
              
              <div className="bg-green-50 rounded-lg p-4">
                <div className="flex items-center">
                  <div className="text-green-600 text-2xl mr-3">⚡</div>
                  <div>
                    <p className="text-sm text-green-600 font-medium">Monitoring Status</p>
                    <p className="text-lg font-bold text-green-900">
                      {gmailStatus.monitoring_active ? 'Active' : 'Inactive'}
                    </p>
                  </div>
                </div>
              </div>
              
              <div className="bg-purple-50 rounded-lg p-4">
                <div className="flex items-center">
                  <div className="text-purple-600 text-2xl mr-3">📧</div>
                  <div>
                    <p className="text-sm text-purple-600 font-medium">Emails Processed</p>
                    <p className="text-lg font-bold text-purple-900">
                      {dashboardStats.totalProcessed || analyses.length}
                    </p>
                  </div>
                </div>
              </div>
              
              <div className="bg-red-50 rounded-lg p-4">
                <div className="flex items-center">
                  <div className="text-red-600 text-2xl mr-3">🚨</div>
                  <div>
                    <p className="text-sm text-red-600 font-medium">Threats Blocked</p>
                    <p className="text-lg font-bold text-red-900">
                      {dashboardStats.threatsFound || analyses.filter(a => a.threat_level === 'HIGH' || a.threat_level === 'CRITICAL').length}
                    </p>
                  </div>
                </div>
              </div>
            </div>
            
            {/* Real-time Information */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
              <div className="border border-gray-200 rounded-lg p-4">
                <h4 className="font-semibold text-gray-900 mb-3">🔄 System Status</h4>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-gray-600">Connection Method:</span>
                    <span className="font-medium">{connectionMethod === 'imap' ? 'IMAP' : 'OAuth'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600">Check Interval:</span>
                    <span className="font-medium">{monitoringConfig.check_interval}s</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600">Alert Email:</span>
                    <span className="font-medium truncate">{monitoringConfig.alert_email || 'Not set'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600">Last Scan:</span>
                    <span className="font-medium">{dashboardStats.lastScan || 'Never'}</span>
                  </div>
                </div>
              </div>
              
              <div className="border border-gray-200 rounded-lg p-4">
                <h4 className="font-semibold text-gray-900 mb-3">🎯 Detection Stats</h4>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-gray-600">CRITICAL Threats:</span>
                    <span className="font-medium text-red-600">
                      {analyses.filter(a => a.threat_level === 'CRITICAL').length}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600">HIGH Threats:</span>
                    <span className="font-medium text-orange-600">
                      {analyses.filter(a => a.threat_level === 'HIGH').length}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600">MEDIUM Threats:</span>
                    <span className="font-medium text-yellow-600">
                      {analyses.filter(a => a.threat_level === 'MEDIUM').length}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600">Detection Rate:</span>
                    <span className="font-medium text-green-600">
                      {analyses.length > 0 ? 
                        Math.round((analyses.filter(a => a.threat_level !== 'LOW').length / analyses.length) * 100) : 0}%
                    </span>
                  </div>
                </div>
              </div>
            </div>
            
            {/* Quick Actions */}
            <div className="border-t border-gray-200 pt-4">
              <h4 className="font-semibold text-gray-900 mb-3">⚡ Quick Actions</h4>
              <div className="flex flex-wrap gap-2">
                <button
                  onClick={() => {
                    checkGmailStatus();
                    fetchDashboardStats();
                  }}
                  className="px-3 py-2 bg-blue-100 text-blue-700 rounded-lg hover:bg-blue-200 text-sm"
                >
                  🔄 Refresh Status
                </button>
                
                <button
                  onClick={testDetection}
                  disabled={loading}
                  className="px-3 py-2 bg-orange-100 text-orange-700 rounded-lg hover:bg-orange-200 text-sm"
                >
                  🧪 Test Detection
                </button>
                
                <button
                  onClick={manualScan}
                  disabled={manualScanLoading}
                  className="px-3 py-2 bg-purple-100 text-purple-700 rounded-lg hover:bg-purple-200 text-sm"
                >
                  📨 Manual Scan
                </button>
                
                {gmailStatus.configured && (
                  <button
                    onClick={gmailStatus.monitoring_active ? stopMonitoring : startMonitoring}
                    disabled={loading}
                    className={`px-3 py-2 text-sm rounded-lg ${
                      gmailStatus.monitoring_active 
                        ? 'bg-red-100 text-red-700 hover:bg-red-200' 
                        : 'bg-green-100 text-green-700 hover:bg-green-200'
                    }`}
                  >
                    {gmailStatus.monitoring_active ? '⏸️ Stop Monitoring' : '▶️ Start Monitoring'}
                  </button>
                )}
              </div>
            </div>
            
            {/* System Health */}
            <div className="mt-6 p-4 bg-gray-50 rounded-lg">
              <h4 className="font-semibold text-gray-900 mb-2">💚 System Health</h4>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                <div className="text-center">
                  <div className="text-green-500 text-lg">✅</div>
                  <div className="font-medium">AI Engine</div>
                  <div className="text-gray-500">Online</div>
                </div>
                <div className="text-center">
                  <div className={`text-lg ${gmailStatus.configured ? 'text-green-500' : 'text-red-500'}`}>
                    {gmailStatus.configured ? '✅' : '❌'}
                  </div>
                  <div className="font-medium">Email Connection</div>
                  <div className="text-gray-500">{gmailStatus.configured ? 'Connected' : 'Disconnected'}</div>
                </div>
                <div className="text-center">
                  <div className="text-green-500 text-lg">✅</div>
                  <div className="font-medium">Database</div>
                  <div className="text-gray-500">Online</div>
                </div>
                <div className="text-center">
                  <div className={`text-lg ${gmailStatus.monitoring_active ? 'text-green-500' : 'text-yellow-500'}`}>
                    {gmailStatus.monitoring_active ? '✅' : '⚠️'}
                  </div>
                  <div className="font-medium">Monitoring</div>
                  <div className="text-gray-500">{gmailStatus.monitoring_active ? 'Active' : 'Standby'}</div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Manual Scan Results */}
        {scanResults && (
          <div className="mb-6 bg-white rounded-xl shadow-sm border border-gray-200 p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Manual Scan Results</h3>
            <div className="grid grid-cols-3 gap-4 mb-4">
              <div className="text-center">
                <div className="text-2xl font-bold text-blue-600">{scanResults.total_scanned}</div>
                <div className="text-sm text-gray-600">Emails Scanned</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-red-600">{scanResults.threats_found}</div>
                <div className="text-sm text-gray-600">Threats Found</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-orange-600">{scanResults.actions_taken}</div>
                <div className="text-sm text-gray-600">Actions Taken</div>
              </div>
            </div>
            
            {scanResults.findings && scanResults.findings.length > 0 && (
              <div className="space-y-2">
                <h4 className="font-medium text-gray-900">Threat Details:</h4>
                {scanResults.findings.slice(0, 5).map((finding, index) => (
                  <div key={index} className="border border-gray-200 rounded-lg p-3">
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-medium text-gray-900 truncate">{finding.subject}</span>
                      <span className={`px-2 py-1 rounded text-xs ${getThreatColor(finding.threat_level)}`}>
                        {finding.threat_level}
                      </span>
                    </div>
                    <div className="text-sm text-gray-600">From: {finding.from}</div>
                    {finding.actions_taken && (
                      <div className="text-sm text-green-600 mt-1">✅ Automated actions taken</div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          
          {/* Upload Section */}
          <div className="lg:col-span-2">
            <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
              <h2 className="text-xl font-semibold text-gray-900 mb-4">
                Upload Email for Analysis
              </h2>
              
              {!selectedFile ? (
                <div
                  className={`border-2 border-dashed rounded-xl p-8 text-center transition-colors ${
                    dragActive 
                      ? 'border-blue-400 bg-blue-50' 
                      : 'border-gray-300 hover:border-gray-400'
                  }`}
                  onDragEnter={handleDrag}
                  onDragLeave={handleDrag}
                  onDragOver={handleDrag}
                  onDrop={handleDrop}
                >
                  <div className="text-6xl mb-4">📧</div>
                  <h3 className="text-lg font-medium text-gray-900 mb-2">
                    Drop your email file here
                  </h3>
                  <p className="text-gray-600 mb-4">
                    Supports .eml, .msg, .txt files and plain text emails
                  </p>
                  <input
                    type="file"
                    onChange={handleFileSelect}
                    accept=".eml,.msg,.txt"
                    className="hidden"
                    id="file-upload"
                  />
                  <label
                    htmlFor="file-upload"
                    className="inline-flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 cursor-pointer transition-colors"
                  >
                    Choose File
                  </label>
                </div>
              ) : (
                <div className="border border-gray-200 rounded-xl p-6">
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center">
                      <div className="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center mr-3">
                        <span className="text-blue-600">📄</span>
                      </div>
                      <div>
                        <p className="font-medium text-gray-900">{selectedFile.name}</p>
                        <p className="text-sm text-gray-600">
                          {(selectedFile.size / 1024).toFixed(1)} KB
                        </p>
                      </div>
                    </div>
                    <button
                      onClick={resetAnalysis}
                      className="text-gray-400 hover:text-gray-600"
                    >
                      ✕
                    </button>
                  </div>
                  
                  <button
                    onClick={analyzeEmail}
                    disabled={loading}
                    className="w-full py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                  >
                    {loading ? (
                      <div className="flex items-center justify-center">
                        <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>
                        Analyzing Email...
                      </div>
                    ) : (
                      'Analyze Email'
                    )}
                  </button>
                </div>
              )}
            </div>

            {/* Results Section */}
            {analysisResult && (
              <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mt-6">
                <h2 className="text-xl font-semibold text-gray-900 mb-4">
                  Analysis Results
                </h2>
                
                {/* Threat Level */}
                <div className={`inline-flex items-center px-4 py-2 rounded-full text-sm font-medium mb-4 ${getThreatColor(analysisResult.threat_level)}`}>
                  <span className="mr-2">{getThreatIcon(analysisResult.threat_level)}</span>
                  Threat Level: {analysisResult.threat_level}
                </div>

                {/* Email Info */}
                {analysisResult.subject && (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
                    <div>
                      <h4 className="font-medium text-gray-900 mb-1">Subject</h4>
                      <p className="text-gray-600 text-sm">{analysisResult.subject}</p>
                    </div>
                    <div>
                      <h4 className="font-medium text-gray-900 mb-1">From</h4>
                      <p className="text-gray-600 text-sm">{analysisResult.from}</p>
                    </div>
                  </div>
                )}

                {/* Findings */}
                <div className="space-y-4">
                  {analysisResult.url_analysis && analysisResult.url_analysis.length > 0 && (
                    <div className="border border-red-200 rounded-lg p-4 bg-red-50">
                      <h4 className="font-medium text-red-900 mb-2">🔗 URL Analysis</h4>
                      {analysisResult.url_analysis.map((finding, index) => (
                        <div key={index} className="text-sm text-red-800 mb-1">
                          • {finding.type}: {finding.original_url || finding.url}
                        </div>
                      ))}
                    </div>
                  )}

                  {analysisResult.sender_analysis && analysisResult.sender_analysis.length > 0 && (
                    <div className="border border-orange-200 rounded-lg p-4 bg-orange-50">
                      <h4 className="font-medium text-orange-900 mb-2">👤 Sender Analysis</h4>
                      {analysisResult.sender_analysis.map((finding, index) => (
                        <div key={index} className="text-sm text-orange-800 mb-1">
                          • {finding.type}: {finding.suspected_brand || finding.from}
                        </div>
                      ))}
                    </div>
                  )}

                  {analysisResult.social_engineering && analysisResult.social_engineering.length > 0 && (
                    <div className="border border-yellow-200 rounded-lg p-4 bg-yellow-50">
                      <h4 className="font-medium text-yellow-900 mb-2">🧠 Social Engineering</h4>
                      {analysisResult.social_engineering.map((finding, index) => (
                        <div key={index} className="text-sm text-yellow-800 mb-1">
                          • {finding.type}: {finding.pattern || finding.greeting}
                        </div>
                      ))}
                    </div>
                  )}

                  {analysisResult.attachment_analysis && analysisResult.attachment_analysis.length > 0 && (
                    <div className="border border-purple-200 rounded-lg p-4 bg-purple-50">
                      <h4 className="font-medium text-purple-900 mb-2">📎 Attachment Analysis</h4>
                      {analysisResult.attachment_analysis.map((finding, index) => (
                        <div key={index} className="text-sm text-purple-800 mb-1">
                          • {finding.type}: {finding.filename}
                        </div>
                      ))}
                    </div>
                  )}

                  {/* LLM Analysis */}
                  {analysisResult.llm_analysis && (
                    <div className="border border-blue-200 rounded-lg p-4 bg-blue-50">
                      <h4 className="font-medium text-blue-900 mb-2">🤖 AI Analysis</h4>
                      <div className="text-sm text-blue-800 whitespace-pre-wrap">
                        {analysisResult.llm_analysis}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Recent Analyses Sidebar */}
          <div className="lg:col-span-1">
            <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
              <h2 className="text-xl font-semibold text-gray-900 mb-4">
                Recent Analyses
              </h2>
              
              {analyses.length === 0 ? (
                <p className="text-gray-600 text-sm">No analyses yet</p>
              ) : (
                <div className="space-y-3">
                  {analyses.map((analysis) => (
                    <div 
                      key={analysis.id} 
                      className="border border-gray-200 rounded-lg p-3 hover:bg-gray-50 cursor-pointer transition-colors"
                      onClick={() => fetchAnalysisDetails(analysis.id)}
                    >
                      <div className="flex items-center justify-between mb-2">
                        <p className="font-medium text-gray-900 text-sm truncate">
                          {analysis.filename}
                        </p>
                        <span className={`px-2 py-1 rounded text-xs ${getThreatColor(analysis.threat_level)}`}>
                          {analysis.threat_level}
                        </span>
                      </div>
                      <p className="text-xs text-gray-600">
                        {new Date(analysis.timestamp).toLocaleDateString()}
                      </p>
                      <p className="text-xs text-blue-600 mt-1">
                        Click to view details
                      </p>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Info Panel */}
            <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mt-6">
              <h3 className="font-semibold text-gray-900 mb-3">Detection Features</h3>
              <div className="space-y-2 text-sm text-gray-600">
                <div className="flex items-center">
                  <span className="mr-2">🔗</span>
                  URL redirection analysis
                </div>
                <div className="flex items-center">
                  <span className="mr-2">👤</span>
                  Sender authenticity check
                </div>
                <div className="flex items-center">
                  <span className="mr-2">🧠</span>
                  Social engineering detection
                </div>
                <div className="flex items-center">
                  <span className="mr-2">📎</span>
                  Malicious attachment scan
                </div>
                <div className="flex items-center">
                  <span className="mr-2">🤖</span>
                  AI-powered analysis
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Analysis Details Modal */}
      {showAnalysisDetails && selectedAnalysis && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-xl shadow-xl max-w-4xl max-h-[90vh] overflow-y-auto m-4">
            <div className="p-6 border-b border-gray-200">
              <div className="flex justify-between items-center">
                <h2 className="text-2xl font-bold text-gray-900">Email Analysis Details</h2>
                <button 
                  onClick={() => {setShowAnalysisDetails(false); setSelectedAnalysis(null);}}
                  className="text-gray-500 hover:text-gray-700 text-2xl"
                >
                  ×
                </button>
              </div>
            </div>
            
            <div className="p-6">
              {analysisDetailsLoading ? (
                <div className="text-center py-8">
                  <div className="spinner mx-auto mb-4"></div>
                  <p>Loading analysis details...</p>
                </div>
              ) : (
                <div className="space-y-6">
                  {/* Email Info */}
                  <div className="bg-gray-50 rounded-lg p-4">
                    <h3 className="font-semibold text-gray-900 mb-3">Email Information</h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                      <div>
                        <span className="font-medium text-gray-700">Subject:</span>
                        <p className="text-gray-900 mt-1">{selectedAnalysis.email_info?.subject || 'N/A'}</p>
                      </div>
                      <div>
                        <span className="font-medium text-gray-700">From:</span>
                        <p className="text-gray-900 mt-1">{selectedAnalysis.email_info?.from || 'N/A'}</p>
                      </div>
                      <div>
                        <span className="font-medium text-gray-700">Date:</span>
                        <p className="text-gray-900 mt-1">{selectedAnalysis.email_info?.date || 'N/A'}</p>
                      </div>
                      <div>
                        <span className="font-medium text-gray-700">Threat Level:</span>
                        <span className={`px-2 py-1 rounded text-xs ${getThreatColor(selectedAnalysis.threat_level)}`}>
                          {selectedAnalysis.threat_level}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Detection Reasons */}
                  {selectedAnalysis.detection_reasons && selectedAnalysis.detection_reasons.length > 0 && (
                    <div className="bg-red-50 rounded-lg p-4">
                      <h3 className="font-semibold text-red-900 mb-3">🚨 Why This Email Was Blocked</h3>
                      <ul className="space-y-2">
                        {selectedAnalysis.detection_reasons.map((reason, index) => (
                          <li key={index} className="flex items-start">
                            <span className="text-red-600 mr-2">•</span>
                            <span className="text-red-800">{reason}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* Threat Indicators */}
                  {selectedAnalysis.threat_indicators && selectedAnalysis.threat_indicators.length > 0 && (
                    <div className="bg-orange-50 rounded-lg p-4">
                      <h3 className="font-semibold text-orange-900 mb-3">⚠️ Threat Indicators</h3>
                      <div className="space-y-2">
                        {selectedAnalysis.threat_indicators.map((indicator, index) => (
                          <div key={index} className="flex items-center justify-between bg-white rounded p-2">
                            <span className="text-orange-800">{indicator.pattern}</span>
                            <span className="text-xs text-orange-600">Score: {indicator.score}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* URL Analysis */}
                  {selectedAnalysis.url_analysis && selectedAnalysis.url_analysis.length > 0 && (
                    <div className="bg-yellow-50 rounded-lg p-4">
                      <h3 className="font-semibold text-yellow-900 mb-3">🔗 URL Analysis</h3>
                      <div className="space-y-2">
                        {selectedAnalysis.url_analysis.map((url, index) => (
                          <div key={index} className="bg-white rounded p-2">
                            <p className="font-medium text-yellow-800">URL: {url.original_url}</p>
                            {url.issues && url.issues.length > 0 && (
                              <ul className="mt-1 text-sm text-yellow-700">
                                {url.issues.map((issue, i) => (
                                  <li key={i}>• {issue}</li>
                                ))}
                              </ul>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Brand Impersonation */}
                  {selectedAnalysis.brand_impersonation && selectedAnalysis.brand_impersonation.length > 0 && (
                    <div className="bg-purple-50 rounded-lg p-4">
                      <h3 className="font-semibold text-purple-900 mb-3">🎭 Brand Impersonation</h3>
                      <div className="space-y-2">
                        {selectedAnalysis.brand_impersonation.map((brand, index) => (
                          <div key={index} className="bg-white rounded p-2">
                            <p className="font-medium text-purple-800">Brand: {brand.brand}</p>
                            <p className="text-sm text-purple-700">Mentions: {brand.mentions}</p>
                            <p className="text-sm text-purple-700">Sender Domain: {brand.sender_domain}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* AI Analysis */}
                  {selectedAnalysis.llm_analysis && (
                    <div className="bg-blue-50 rounded-lg p-4">
                      <h3 className="font-semibold text-blue-900 mb-3">🤖 AI Analysis</h3>
                      <div className="bg-white rounded p-3 text-sm text-gray-700 max-h-60 overflow-y-auto">
                        <pre className="whitespace-pre-wrap">{selectedAnalysis.llm_analysis}</pre>
                      </div>
                    </div>
                  )}

                  {/* Confidence Score */}
                  <div className="bg-gray-100 rounded-lg p-4">
                    <h3 className="font-semibold text-gray-900 mb-3">📊 Analysis Summary</h3>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-700">Confidence Score:</span>
                      <div className="flex items-center">
                        <div className="w-32 bg-gray-300 rounded-full h-2 mr-3">
                          <div 
                            className={`h-2 rounded-full ${
                              selectedAnalysis.confidence_score >= 80 ? 'bg-red-500' :
                              selectedAnalysis.confidence_score >= 60 ? 'bg-orange-500' :
                              selectedAnalysis.confidence_score >= 30 ? 'bg-yellow-500' : 'bg-green-500'
                            }`}
                            style={{width: `${selectedAnalysis.confidence_score}%`}}
                          ></div>
                        </div>
                        <span className="font-bold">{selectedAnalysis.confidence_score}%</span>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;