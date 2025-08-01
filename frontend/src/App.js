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
  const [imapConfig, setImapConfig] = useState({
    email: '',
    app_password: ''
  });
  const [connectionMethod, setConnectionMethod] = useState('imap'); // 'gmail' or 'imap'
  const [manualScanLoading, setManualScanLoading] = useState(false);
  const [scanResults, setScanResults] = useState(null);

  useEffect(() => {
    fetchAnalyses();
    checkGmailStatus();
  }, []);

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
      const response = await axios.post(`${API}/gmail/start-monitoring`, monitoringConfig);
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
      const response = await axios.post(`${API}/gmail/stop-monitoring`);
      alert(response.data.message);
      await checkGmailStatus();
    } catch (error) {
      alert(`Failed to stop monitoring: ${error.response?.data?.detail || error.message}`);
    } finally {
      setLoading(false);
    }
  };

  const manualScan = async () => {
    try {
      setManualScanLoading(true);
      const response = await axios.post(`${API}/gmail/manual-scan`, { max_emails: 50 });
      setScanResults(response.data.results);
      await fetchAnalyses(); // Refresh analyses
    } catch (error) {
      alert(`Manual scan failed: ${error.response?.data?.detail || error.message}`);
    } finally {
      setManualScanLoading(false);
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
            
            <button
              onClick={setupImap}
              disabled={
                loading || 
                !imapConfig.email || 
                !imapConfig.app_password || 
                imapConfig.app_password.length !== 16 ||
                !imapConfig.email.includes('@gmail.com')
              }
              className="w-full py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? 'Testing IMAP Connection...' : 'Setup IMAP Connection'}
            </button>
            
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
                    <div key={analysis.id} className="border border-gray-200 rounded-lg p-3">
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
    </div>
  );
}

export default App;