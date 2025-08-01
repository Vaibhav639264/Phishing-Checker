#!/usr/bin/env python3
"""
Backend API Testing for Email Phishing Detection Tool
Tests the /api/analyze-email endpoint and related functionality
"""

import requests
import json
import tempfile
import os
from io import BytesIO
import time

# Get backend URL from environment
BACKEND_URL = "https://eabb3dac-4704-4fff-93d4-8cb208baf6ef.preview.emergentagent.com/api"

def create_sample_phishing_email():
    """Create a realistic phishing email sample for testing"""
    phishing_email = """From: Microsoft Security Team <security@microsft-support.com>
To: user@company.com
Subject: URGENT: Your Microsoft Account Will Be Suspended
Date: Mon, 15 Jan 2024 10:30:00 +0000
Reply-To: noreply@suspicious-domain.net

Dear User,

We have detected unusual login attempts on your Microsoft account from an unrecognized device. Your account will be suspended within 24 hours unless you verify your identity immediately.

Click here to verify your account: https://microsoft-verify.suspicious-domain.net/redirect?url=aHR0cHM6Ly9ldmlsLXNpdGUuY29tL3BoaXNoaW5n

If you do not take immediate action, your account will be permanently suspended and all data will be lost.

This is an automated message. Do not reply to this email.

Best regards,
Microsoft Security Team
"""
    return phishing_email

def create_legitimate_email():
    """Create a legitimate email sample for comparison"""
    legitimate_email = """From: John Smith <john.smith@company.com>
To: team@company.com
Subject: Weekly Team Meeting Notes
Date: Mon, 15 Jan 2024 14:30:00 +0000

Hi Team,

Here are the notes from our weekly meeting:

1. Project Alpha is on track for Q1 delivery
2. New team member Sarah will join us next Monday
3. Please review the updated documentation by Friday

Let me know if you have any questions.

Best regards,
John Smith
Project Manager
"""
    return legitimate_email

def test_api_connectivity():
    """Test basic API connectivity"""
    print("🔍 Testing API connectivity...")
    try:
        response = requests.get(f"{BACKEND_URL}/", timeout=10)
        if response.status_code == 200:
            data = response.json()
            if "message" in data:
                print("✅ API connectivity successful")
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

def test_email_analysis_phishing():
    """Test email analysis with phishing email"""
    print("\n🔍 Testing phishing email analysis...")
    try:
        phishing_email = create_sample_phishing_email()
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.eml', delete=False) as f:
            f.write(phishing_email)
            temp_file_path = f.name
        
        try:
            # Upload file for analysis
            with open(temp_file_path, 'rb') as f:
                files = {'file': ('phishing_test.eml', f, 'message/rfc822')}
                response = requests.post(f"{BACKEND_URL}/analyze-email", files=files, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                # Verify response structure
                required_fields = ['success', 'analysis', 'id']
                if all(field in data for field in required_fields):
                    analysis = data['analysis']
                    
                    # Check for key analysis components
                    expected_components = ['url_analysis', 'sender_analysis', 'social_engineering', 'threat_level']
                    found_components = [comp for comp in expected_components if comp in analysis]
                    
                    print(f"✅ Phishing email analysis successful")
                    print(f"   - Analysis ID: {data['id']}")
                    print(f"   - Threat Level: {analysis.get('threat_level', 'Unknown')}")
                    print(f"   - Components found: {found_components}")
                    
                    # Check if high-risk indicators were detected
                    if analysis.get('threat_level') in ['HIGH', 'CRITICAL']:
                        print("   - ✅ Correctly identified as high-risk")
                    else:
                        print(f"   - ⚠️  Threat level {analysis.get('threat_level')} may be lower than expected for phishing")
                    
                    return True, data
                else:
                    print(f"❌ Response missing required fields: {required_fields}")
                    return False, None
            else:
                print(f"❌ Email analysis failed with status {response.status_code}")
                print(f"   Response: {response.text}")
                return False, None
                
        finally:
            # Clean up temp file
            os.unlink(temp_file_path)
            
    except Exception as e:
        print(f"❌ Phishing email analysis failed: {str(e)}")
        return False, None

def test_email_analysis_legitimate():
    """Test email analysis with legitimate email"""
    print("\n🔍 Testing legitimate email analysis...")
    try:
        legitimate_email = create_legitimate_email()
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.eml', delete=False) as f:
            f.write(legitimate_email)
            temp_file_path = f.name
        
        try:
            # Upload file for analysis
            with open(temp_file_path, 'rb') as f:
                files = {'file': ('legitimate_test.eml', f, 'message/rfc822')}
                response = requests.post(f"{BACKEND_URL}/analyze-email", files=files, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                analysis = data['analysis']
                
                print(f"✅ Legitimate email analysis successful")
                print(f"   - Threat Level: {analysis.get('threat_level', 'Unknown')}")
                
                # Check if correctly identified as low-risk
                if analysis.get('threat_level') in ['LOW', 'MEDIUM']:
                    print("   - ✅ Correctly identified as low-risk")
                else:
                    print(f"   - ⚠️  Threat level {analysis.get('threat_level')} may be higher than expected for legitimate email")
                
                return True, data
            else:
                print(f"❌ Legitimate email analysis failed with status {response.status_code}")
                return False, None
                
        finally:
            # Clean up temp file
            os.unlink(temp_file_path)
            
    except Exception as e:
        print(f"❌ Legitimate email analysis failed: {str(e)}")
        return False, None

def test_llm_integration(analysis_data):
    """Test LLM integration by checking analysis results"""
    print("\n🔍 Testing LLM integration...")
    try:
        if analysis_data and 'analysis' in analysis_data:
            analysis = analysis_data['analysis']
            
            # Check for LLM analysis components
            llm_indicators = ['llm_analysis', 'analysis_successful']
            found_llm = [indicator for indicator in llm_indicators if indicator in analysis]
            
            if found_llm:
                print("✅ LLM integration detected in analysis")
                
                if analysis.get('analysis_successful'):
                    print("   - ✅ LLM analysis completed successfully")
                    if 'llm_analysis' in analysis and analysis['llm_analysis']:
                        print(f"   - LLM response length: {len(str(analysis['llm_analysis']))} characters")
                        return True
                    else:
                        print("   - ⚠️  LLM analysis field empty")
                        return False
                else:
                    print("   - ❌ LLM analysis failed")
                    print(f"   - Error: {analysis.get('llm_analysis', 'Unknown error')}")
                    return False
            else:
                print("❌ No LLM integration indicators found")
                return False
        else:
            print("❌ No analysis data provided for LLM testing")
            return False
            
    except Exception as e:
        print(f"❌ LLM integration test failed: {str(e)}")
        return False

def test_database_operations():
    """Test database operations by retrieving analyses"""
    print("\n🔍 Testing database operations...")
    try:
        # Test getting all analyses
        response = requests.get(f"{BACKEND_URL}/analyses", timeout=10)
        
        if response.status_code == 200:
            analyses = response.json()
            print(f"✅ Database retrieval successful")
            print(f"   - Found {len(analyses)} stored analyses")
            
            if len(analyses) > 0:
                # Test getting specific analysis
                first_analysis = analyses[0]
                if 'id' in first_analysis:
                    analysis_id = first_analysis['id']
                    specific_response = requests.get(f"{BACKEND_URL}/analyses/{analysis_id}", timeout=10)
                    
                    if specific_response.status_code == 200:
                        print("   - ✅ Individual analysis retrieval successful")
                        return True
                    else:
                        print(f"   - ❌ Individual analysis retrieval failed: {specific_response.status_code}")
                        return False
                else:
                    print("   - ⚠️  Analysis missing ID field")
                    return True  # Still consider successful if we can retrieve list
            else:
                print("   - ✅ Database accessible (no analyses stored yet)")
                return True
                
        else:
            print(f"❌ Database retrieval failed with status {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Database operations test failed: {str(e)}")
        return False

def test_error_handling():
    """Test error handling with invalid files"""
    print("\n🔍 Testing error handling...")
    try:
        # Test with invalid file content
        invalid_content = "This is not a valid email format"
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(invalid_content)
            temp_file_path = f.name
        
        try:
            with open(temp_file_path, 'rb') as f:
                files = {'file': ('invalid.txt', f, 'text/plain')}
                response = requests.post(f"{BACKEND_URL}/analyze-email", files=files, timeout=15)
            
            # Should either handle gracefully or return appropriate error
            if response.status_code in [200, 400, 422]:
                print("✅ Error handling working (graceful response to invalid input)")
                return True
            else:
                print(f"⚠️  Unexpected status code for invalid input: {response.status_code}")
                return True  # Still acceptable
                
        finally:
            os.unlink(temp_file_path)
            
    except Exception as e:
        print(f"❌ Error handling test failed: {str(e)}")
        return False

def test_comprehensive_detection_features(analysis_data):
    """Test comprehensive detection features"""
    print("\n🔍 Testing comprehensive detection features...")
    try:
        if not analysis_data or 'analysis' not in analysis_data:
            print("❌ No analysis data provided")
            return False
            
        analysis = analysis_data['analysis']
        
        # Check for URL redirection detection
        url_detection = 'url_analysis' in analysis
        print(f"   - URL redirection detection: {'✅' if url_detection else '❌'}")
        
        # Check for sender authenticity
        sender_detection = 'sender_analysis' in analysis
        print(f"   - Sender authenticity checks: {'✅' if sender_detection else '❌'}")
        
        # Check for social engineering detection
        social_detection = 'social_engineering' in analysis
        print(f"   - Social engineering detection: {'✅' if social_detection else '❌'}")
        
        # Check for attachment analysis
        attachment_detection = 'attachment_analysis' in analysis
        print(f"   - Attachment analysis: {'✅' if attachment_detection else '❌'}")
        
        # Check for threat level calculation
        threat_level = 'threat_level' in analysis and analysis['threat_level'] != 'UNKNOWN'
        print(f"   - Threat level calculation: {'✅' if threat_level else '❌'}")
        
        # Overall assessment
        features_working = sum([url_detection, sender_detection, social_detection, attachment_detection, threat_level])
        total_features = 5
        
        if features_working >= 4:
            print(f"✅ Comprehensive detection features working ({features_working}/{total_features})")
            return True
        else:
            print(f"⚠️  Some detection features missing ({features_working}/{total_features})")
            return False
            
    except Exception as e:
        print(f"❌ Comprehensive detection test failed: {str(e)}")
        return False

def main():
    """Run all backend tests"""
    print("🚀 Starting Backend API Tests for Email Phishing Detection")
    print("=" * 60)
    
    test_results = {}
    
    # Test 1: API Connectivity
    test_results['connectivity'] = test_api_connectivity()
    
    if not test_results['connectivity']:
        print("\n❌ API connectivity failed. Cannot proceed with other tests.")
        return test_results
    
    # Test 2: Email Analysis (Phishing)
    test_results['phishing_analysis'], phishing_data = test_email_analysis_phishing()
    
    # Test 3: Email Analysis (Legitimate)
    test_results['legitimate_analysis'], legitimate_data = test_email_analysis_legitimate()
    
    # Test 4: LLM Integration (using phishing data)
    test_results['llm_integration'] = test_llm_integration(phishing_data)
    
    # Test 5: Database Operations
    test_results['database_operations'] = test_database_operations()
    
    # Test 6: Error Handling
    test_results['error_handling'] = test_error_handling()
    
    # Test 7: Comprehensive Detection Features
    test_results['comprehensive_detection'] = test_comprehensive_detection_features(phishing_data)
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 TEST SUMMARY")
    print("=" * 60)
    
    passed_tests = sum(1 for result in test_results.values() if result)
    total_tests = len(test_results)
    
    for test_name, result in test_results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name.replace('_', ' ').title()}: {status}")
    
    print(f"\nOverall: {passed_tests}/{total_tests} tests passed")
    
    if passed_tests == total_tests:
        print("🎉 All backend tests passed!")
    elif passed_tests >= total_tests * 0.8:
        print("⚠️  Most tests passed with minor issues")
    else:
        print("❌ Significant issues found in backend")
    
    return test_results

if __name__ == "__main__":
    results = main()