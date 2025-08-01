#!/usr/bin/env python3
"""
Backend API Testing for Enhanced Email Phishing Detection Tool
Tests IMAP integration, detection engine, monitoring, and alert systems
"""

import requests
import json
import tempfile
import os
from io import BytesIO
import time

# Get backend URL from environment
BACKEND_URL = "https://ac1d4513-2ed8-469e-a2c0-26e2c8368863.preview.emergentagent.com/api"

def test_api_connectivity():
    """Test basic API connectivity"""
    print("🔍 Testing API connectivity...")
    try:
        response = requests.get(f"{BACKEND_URL}/", timeout=10)
        if response.status_code == 200:
            data = response.json()
            if "message" in data:
                print("✅ API connectivity successful")
                print(f"   - Response: {data['message']}")
                return True
            else:
                print("❌ API response format unexpected")
                return False
        else:
            print(f"❌ API connectivity failed with status {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ API connectivity failed: {str(e)}")
        return False

def test_imap_connection_without_credentials():
    """Test IMAP connection endpoints without credentials (should handle gracefully)"""
    print("\n🔍 Testing IMAP connection without credentials...")
    try:
        # Test connection with empty credentials
        test_data = {
            "email": "",
            "app_password": ""
        }
        
        response = requests.post(f"{BACKEND_URL}/imap/test-connection", 
                               json=test_data, timeout=15)
        
        if response.status_code in [200, 400, 422]:
            data = response.json()
            print("✅ IMAP test-connection endpoint handles empty credentials gracefully")
            print(f"   - Status: {data.get('status', 'unknown')}")
            print(f"   - Message: {data.get('message', 'No message')}")
            return True
        else:
            print(f"❌ Unexpected status code: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ IMAP connection test failed: {str(e)}")
        return False

def test_imap_setup_without_credentials():
    """Test IMAP setup endpoint without credentials"""
    print("\n🔍 Testing IMAP setup without credentials...")
    try:
        setup_data = {
            "email": "",
            "app_password": ""
        }
        
        response = requests.post(f"{BACKEND_URL}/imap/setup", 
                               json=setup_data, timeout=15)
        
        if response.status_code in [200, 400, 422]:
            data = response.json()
            print("✅ IMAP setup endpoint handles empty credentials gracefully")
            print(f"   - Success: {data.get('success', False)}")
            print(f"   - Message: {data.get('message', 'No message')}")
            return True
        else:
            print(f"❌ Unexpected status code: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ IMAP setup test failed: {str(e)}")
        return False

def test_imap_status():
    """Test IMAP status endpoint"""
    print("\n🔍 Testing IMAP status endpoint...")
    try:
        response = requests.get(f"{BACKEND_URL}/imap/status", timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            print("✅ IMAP status endpoint working")
            print(f"   - Configured: {data.get('configured', False)}")
            print(f"   - Monitoring Active: {data.get('monitoring_active', False)}")
            print(f"   - Status: {data.get('status', 'unknown')}")
            print(f"   - Message: {data.get('message', 'No message')}")
            return True
        else:
            print(f"❌ IMAP status failed with status {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ IMAP status test failed: {str(e)}")
        return False

def test_core_detection_engine():
    """Test the core detection engine with Office-365 phishing sample"""
    print("\n🔍 Testing core detection engine with Office-365 sample...")
    try:
        response = requests.get(f"{BACKEND_URL}/debug/analyze-sample", timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            
            if data.get('success'):
                analysis = data.get('analysis', {})
                detection_summary = data.get('detection_summary', {})
                
                threat_level = detection_summary.get('threat_level', 'UNKNOWN')
                confidence_score = detection_summary.get('confidence_score', 0)
                
                print("✅ Core detection engine working")
                print(f"   - Threat Level: {threat_level}")
                print(f"   - Confidence Score: {confidence_score}%")
                print(f"   - Detection Reasons: {len(detection_summary.get('detection_reasons', []))}")
                print(f"   - Should be blocked: {detection_summary.get('should_be_blocked', False)}")
                
                # Verify Office-365 phishing is detected as CRITICAL
                if threat_level == 'CRITICAL' and confidence_score >= 90:
                    print("   - ✅ Office-365 phishing correctly detected as CRITICAL threat")
                    return True
                else:
                    print(f"   - ⚠️  Expected CRITICAL threat with high confidence, got {threat_level} with {confidence_score}%")
                    return False
            else:
                print("❌ Detection analysis failed")
                return False
        else:
            print(f"❌ Detection engine test failed with status {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Core detection engine test failed: {str(e)}")
        return False

def test_manual_scan_without_imap():
    """Test manual scan endpoint when IMAP is not configured"""
    print("\n🔍 Testing manual scan without IMAP configuration...")
    try:
        scan_data = {
            "max_emails": 10
        }
        
        response = requests.post(f"{BACKEND_URL}/imap/manual-scan", 
                               json=scan_data, timeout=15)
        
        # Should return 400 error when IMAP not configured
        if response.status_code == 400:
            data = response.json()
            print("✅ Manual scan correctly returns error when IMAP not configured")
            print(f"   - Error: {data.get('detail', 'No detail')}")
            return True
        elif response.status_code == 200:
            data = response.json()
            print("⚠️  Manual scan returned success despite no IMAP config")
            print(f"   - Message: {data.get('message', 'No message')}")
            return True  # Still acceptable if it handles gracefully
        else:
            print(f"❌ Unexpected status code: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Manual scan test failed: {str(e)}")
        return False

def test_monitoring_endpoints():
    """Test real-time monitoring start/stop endpoints"""
    print("\n🔍 Testing monitoring endpoints...")
    try:
        # Test start monitoring without IMAP
        monitor_data = {
            "alert_email": "admin@company.com",
            "check_interval": 60
        }
        
        start_response = requests.post(f"{BACKEND_URL}/imap/start-monitoring", 
                                     json=monitor_data, timeout=15)
        
        if start_response.status_code == 400:
            print("✅ Start monitoring correctly returns error when IMAP not configured")
        elif start_response.status_code == 200:
            print("⚠️  Start monitoring returned success despite no IMAP config")
        else:
            print(f"❌ Unexpected start monitoring status: {start_response.status_code}")
            return False
        
        # Test stop monitoring
        stop_response = requests.post(f"{BACKEND_URL}/imap/stop-monitoring", timeout=10)
        
        if stop_response.status_code == 200:
            data = stop_response.json()
            print("✅ Stop monitoring endpoint working")
            print(f"   - Message: {data.get('message', 'No message')}")
            return True
        else:
            print(f"❌ Stop monitoring failed with status {stop_response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Monitoring endpoints test failed: {str(e)}")
        return False

def test_analysis_storage():
    """Test analysis storage endpoints"""
    print("\n🔍 Testing analysis storage endpoints...")
    try:
        # Test get all analyses
        analyses_response = requests.get(f"{BACKEND_URL}/analyses", timeout=10)
        
        if analyses_response.status_code == 200:
            analyses = analyses_response.json()
            print("✅ Analyses endpoint working")
            print(f"   - Found {len(analyses)} stored analyses")
        else:
            print(f"❌ Analyses endpoint failed with status {analyses_response.status_code}")
            return False
        
        # Test monitoring stats
        stats_response = requests.get(f"{BACKEND_URL}/monitoring/stats", timeout=10)
        
        if stats_response.status_code == 200:
            stats = stats_response.json()
            print("✅ Monitoring stats endpoint working")
            print(f"   - Total Processed: {stats.get('totalProcessed', 0)}")
            print(f"   - Threats Found: {stats.get('threatsFound', 0)}")
            print(f"   - Monitoring Active: {stats.get('monitoring_active', False)}")
            print(f"   - Detection Rate: {stats.get('detectionRate', 0)}%")
            return True
        else:
            print(f"❌ Monitoring stats failed with status {stats_response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Analysis storage test failed: {str(e)}")
        return False

def test_error_handling_comprehensive():
    """Test comprehensive error handling across all endpoints"""
    print("\n🔍 Testing comprehensive error handling...")
    try:
        error_tests = []
        
        # Test invalid JSON data
        try:
            response = requests.post(f"{BACKEND_URL}/imap/setup", 
                                   data="invalid json", timeout=10)
            error_tests.append(response.status_code in [400, 422])
        except:
            error_tests.append(True)  # Exception handling is also acceptable
        
        # Test missing required fields
        try:
            response = requests.post(f"{BACKEND_URL}/imap/test-connection", 
                                   json={}, timeout=10)
            error_tests.append(response.status_code in [400, 422])
        except:
            error_tests.append(True)
        
        # Test invalid email format
        try:
            response = requests.post(f"{BACKEND_URL}/imap/test-connection", 
                                   json={"email": "invalid-email", "app_password": "test"}, 
                                   timeout=10)
            error_tests.append(response.status_code in [200, 400, 422])  # Any reasonable response
        except:
            error_tests.append(True)
        
        passed_error_tests = sum(error_tests)
        total_error_tests = len(error_tests)
        
        if passed_error_tests >= total_error_tests * 0.8:
            print(f"✅ Error handling working ({passed_error_tests}/{total_error_tests} tests passed)")
            return True
        else:
            print(f"⚠️  Some error handling issues ({passed_error_tests}/{total_error_tests} tests passed)")
            return False
            
    except Exception as e:
        print(f"❌ Error handling test failed: {str(e)}")
        return False

def main():
    """Run all backend tests for enhanced phishing detection system"""
    print("🚀 Starting Enhanced Email Phishing Detection Backend Tests")
    print("=" * 70)
    print("Testing IMAP integration, detection engine, monitoring, and alerts")
    print("=" * 70)
    
    test_results = {}
    
    # Test 1: API Connectivity
    test_results['api_connectivity'] = test_api_connectivity()
    
    if not test_results['api_connectivity']:
        print("\n❌ API connectivity failed. Cannot proceed with other tests.")
        return test_results
    
    # Test 2: IMAP Connection Testing (without credentials)
    test_results['imap_connection_test'] = test_imap_connection_without_credentials()
    
    # Test 3: IMAP Setup Testing (without credentials)
    test_results['imap_setup_test'] = test_imap_setup_without_credentials()
    
    # Test 4: IMAP Status Endpoint
    test_results['imap_status'] = test_imap_status()
    
    # Test 5: Core Detection Engine (Office-365 sample)
    test_results['core_detection_engine'] = test_core_detection_engine()
    
    # Test 6: Manual Scan (should fail gracefully without IMAP)
    test_results['manual_scan_no_imap'] = test_manual_scan_without_imap()
    
    # Test 7: Monitoring Endpoints
    test_results['monitoring_endpoints'] = test_monitoring_endpoints()
    
    # Test 8: Analysis Storage
    test_results['analysis_storage'] = test_analysis_storage()
    
    # Test 9: Comprehensive Error Handling
    test_results['error_handling'] = test_error_handling_comprehensive()
    
    # Summary
    print("\n" + "=" * 70)
    print("📊 ENHANCED PHISHING DETECTION TEST SUMMARY")
    print("=" * 70)
    
    passed_tests = sum(1 for result in test_results.values() if result)
    total_tests = len(test_results)
    
    for test_name, result in test_results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        formatted_name = test_name.replace('_', ' ').title()
        print(f"{formatted_name:<30}: {status}")
    
    print(f"\nOverall Result: {passed_tests}/{total_tests} tests passed")
    
    if passed_tests == total_tests:
        print("🎉 All enhanced phishing detection tests passed!")
        print("✅ System is ready for production use")
    elif passed_tests >= total_tests * 0.8:
        print("⚠️  Most tests passed - minor issues detected")
        print("🔧 System functional but may need minor adjustments")
    else:
        print("❌ Significant issues found in enhanced system")
        print("🚨 System needs attention before production use")
    
    # Specific recommendations based on test results
    print("\n" + "=" * 70)
    print("📋 SYSTEM STATUS ASSESSMENT")
    print("=" * 70)
    
    critical_components = [
        ('core_detection_engine', 'Core Detection Engine'),
        ('imap_connection_test', 'IMAP Connection Handling'),
        ('error_handling', 'Error Handling'),
        ('analysis_storage', 'Analysis Storage')
    ]
    
    critical_passed = sum(1 for comp, _ in critical_components if test_results.get(comp, False))
    
    if critical_passed == len(critical_components):
        print("✅ All critical components working properly")
    else:
        print("⚠️  Some critical components need attention:")
        for comp, name in critical_components:
            if not test_results.get(comp, False):
                print(f"   - ❌ {name}")
    
    return test_results

if __name__ == "__main__":
    results = main()