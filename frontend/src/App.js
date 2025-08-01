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

  useEffect(() => {
    fetchAnalyses();
  }, []);

  const fetchAnalyses = async () => {
    try {
      const response = await axios.get(`${API}/analyses`);
      setAnalyses(response.data.slice(0, 5)); // Show last 5 analyses
    } catch (error) {
      console.error('Error fetching analyses:', error);
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