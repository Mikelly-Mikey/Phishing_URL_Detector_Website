#!/usr/bin/env python3
"""
Comprehensive Backend API Testing for Phishing URL Checker
Tests all 5 layers of detection and core functionality
"""

import requests
import sys
import json
import time
from datetime import datetime
from typing import Dict, List, Any

class PhishingCheckerTester:
    def __init__(self, base_url="https://safechecker.preview.emergentagent.com"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
        self.tests_run = 0
        self.tests_passed = 0
        self.test_results = []
        self.scan_ids = []

    def log_test(self, name: str, success: bool, details: str = "", response_data: Any = None):
        """Log test result"""
        self.tests_run += 1
        if success:
            self.tests_passed += 1
        
        result = {
            "test_name": name,
            "success": success,
            "details": details,
            "timestamp": datetime.now().isoformat(),
            "response_data": response_data
        }
        self.test_results.append(result)
        
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} - {name}")
        if details:
            print(f"    {details}")
        if not success and response_data:
            print(f"    Response: {response_data}")

    def test_api_health(self) -> bool:
        """Test basic API connectivity"""
        try:
            response = requests.get(f"{self.api_url}/", timeout=10)
            success = response.status_code == 200
            
            if success:
                data = response.json()
                self.log_test("API Health Check", True, f"API responding: {data.get('message', 'OK')}")
            else:
                self.log_test("API Health Check", False, f"Status code: {response.status_code}")
            
            return success
        except Exception as e:
            self.log_test("API Health Check", False, f"Connection error: {str(e)}")
            return False

    def test_url_validation(self) -> bool:
        """Test URL input validation"""
        test_cases = [
            {"url": "", "should_fail": True, "description": "Empty URL"},
            {"url": "not-a-url", "should_fail": True, "description": "Invalid URL format"},
            {"url": "https://google.com", "should_fail": False, "description": "Valid HTTPS URL"},
        ]
        
        all_passed = True
        for case in test_cases:
            try:
                response = requests.post(
                    f"{self.api_url}/check-url",
                    json={"url": case["url"]},
                    timeout=30
                )
                
                if case["should_fail"]:
                    success = response.status_code != 200
                    details = f"Expected failure for {case['description']}"
                else:
                    success = response.status_code == 200
                    details = f"Expected success for {case['description']}"
                
                self.log_test(f"URL Validation - {case['description']}", success, details)
                if not success:
                    all_passed = False
                    
            except Exception as e:
                self.log_test(f"URL Validation - {case['description']}", False, f"Error: {str(e)}")
                all_passed = False
        
        return all_passed

    def test_url_analysis_comprehensive(self) -> bool:
        """Test comprehensive URL analysis with different URL types"""
        test_urls = [
            {
                "url": "https://google.com",
                "expected_category": "benign",
                "description": "Legitimate URL"
            },
            {
                "url": "http://paypal-verify-account.tk",
                "expected_category": "suspicious",
                "description": "Suspicious phishing-like URL"
            },
            {
                "url": "http://192.168.1.1/login?token=abc123&password=test",
                "expected_category": "malicious",
                "description": "Malicious-looking URL with IP and credentials"
            }
        ]
        
        all_passed = True
        for test_case in test_urls:
            try:
                print(f"\n🔍 Testing {test_case['description']}: {test_case['url']}")
                
                response = requests.post(
                    f"{self.api_url}/check-url",
                    json={"url": test_case["url"]},
                    timeout=60  # Longer timeout for AI processing
                )
                
                if response.status_code != 200:
                    self.log_test(f"URL Analysis - {test_case['description']}", False, 
                                f"HTTP {response.status_code}: {response.text}")
                    all_passed = False
                    continue
                
                result = response.json()
                self.scan_ids.append(result.get('id'))
                
                # Test basic response structure
                required_fields = ['id', 'url', 'risk_category', 'confidence_score', 
                                 'suspicious_patterns', 'threat_intelligence_result',
                                 'ai_scores', 'dynamic_analysis', 'privacy_status']
                
                missing_fields = [field for field in required_fields if field not in result]
                if missing_fields:
                    self.log_test(f"Response Structure - {test_case['description']}", False,
                                f"Missing fields: {missing_fields}")
                    all_passed = False
                    continue
                
                # Test Layer 1: Pattern Analysis
                patterns = result.get('suspicious_patterns', [])
                self.log_test(f"Layer 1 Pattern Analysis - {test_case['description']}", True,
                            f"Found {len(patterns)} patterns")
                
                # Test Layer 2: Threat Intelligence
                threat_intel = result.get('threat_intelligence_result', '')
                self.log_test(f"Layer 2 Threat Intelligence - {test_case['description']}", 
                            len(threat_intel) > 0, f"Result: {threat_intel[:100]}...")
                
                # Test Layer 3: AI Scores
                ai_scores = result.get('ai_scores', {})
                required_ai_fields = ['url_model_score', 'content_model_score', 'ensemble_score', 'confidence']
                ai_fields_present = all(field in ai_scores for field in required_ai_fields)
                self.log_test(f"Layer 3 AI Analysis - {test_case['description']}", 
                            ai_fields_present, f"AI scores: {ai_scores}")
                
                # Test Layer 4: Dynamic Analysis
                dynamic = result.get('dynamic_analysis', {})
                dynamic_fields = ['html_signals', 'javascript_behaviors', 'redirects_found', 'credential_harvesting_detected']
                dynamic_complete = all(field in dynamic for field in dynamic_fields)
                self.log_test(f"Layer 4 Dynamic Analysis - {test_case['description']}", 
                            dynamic_complete, f"Dynamic analysis complete")
                
                # Test Privacy Compliance
                privacy_status = result.get('privacy_status', '')
                masked_url = result.get('masked_url', '')
                privacy_ok = len(privacy_status) > 0 and 'masked' in privacy_status.lower()
                self.log_test(f"Privacy Compliance - {test_case['description']}", 
                            privacy_ok, f"Privacy status: {privacy_status}")
                
                # Test Risk Categorization
                risk_category = result.get('risk_category', '')
                category_match = risk_category in ['benign', 'suspicious', 'malicious']
                self.log_test(f"Risk Categorization - {test_case['description']}", 
                            category_match, f"Category: {risk_category}, Score: {result.get('confidence_score', 0)}")
                
                if not category_match:
                    all_passed = False
                
            except Exception as e:
                self.log_test(f"URL Analysis - {test_case['description']}", False, f"Error: {str(e)}")
                all_passed = False
        
        return all_passed

    def test_scan_history(self) -> bool:
        """Test scan history retrieval"""
        try:
            response = requests.get(f"{self.api_url}/scan-history", timeout=10)
            
            if response.status_code != 200:
                self.log_test("Scan History", False, f"HTTP {response.status_code}")
                return False
            
            history = response.json()
            
            if not isinstance(history, list):
                self.log_test("Scan History", False, "Response is not a list")
                return False
            
            self.log_test("Scan History", True, f"Retrieved {len(history)} scan records")
            return True
            
        except Exception as e:
            self.log_test("Scan History", False, f"Error: {str(e)}")
            return False

    def test_individual_scan_retrieval(self) -> bool:
        """Test retrieving individual scan by ID"""
        if not self.scan_ids:
            self.log_test("Individual Scan Retrieval", False, "No scan IDs available")
            return False
        
        try:
            scan_id = self.scan_ids[0]
            response = requests.get(f"{self.api_url}/scan/{scan_id}", timeout=10)
            
            if response.status_code != 200:
                self.log_test("Individual Scan Retrieval", False, f"HTTP {response.status_code}")
                return False
            
            scan_data = response.json()
            
            if scan_data.get('id') != scan_id:
                self.log_test("Individual Scan Retrieval", False, "Scan ID mismatch")
                return False
            
            self.log_test("Individual Scan Retrieval", True, f"Retrieved scan {scan_id}")
            return True
            
        except Exception as e:
            self.log_test("Individual Scan Retrieval", False, f"Error: {str(e)}")
            return False

    def test_pdf_generation(self) -> bool:
        """Test PDF report generation"""
        if not self.scan_ids:
            self.log_test("PDF Generation", False, "No scan IDs available")
            return False
        
        try:
            scan_id = self.scan_ids[0]
            response = requests.get(f"{self.api_url}/scan/{scan_id}/pdf", timeout=30)
            
            if response.status_code != 200:
                self.log_test("PDF Generation", False, f"HTTP {response.status_code}")
                return False
            
            # Check if response is PDF
            content_type = response.headers.get('content-type', '')
            is_pdf = 'application/pdf' in content_type
            
            if not is_pdf:
                self.log_test("PDF Generation", False, f"Wrong content type: {content_type}")
                return False
            
            # Check PDF size
            pdf_size = len(response.content)
            if pdf_size < 1000:  # PDF should be at least 1KB
                self.log_test("PDF Generation", False, f"PDF too small: {pdf_size} bytes")
                return False
            
            self.log_test("PDF Generation", True, f"Generated PDF: {pdf_size} bytes")
            return True
            
        except Exception as e:
            self.log_test("PDF Generation", False, f"Error: {str(e)}")
            return False

    def test_ai_integration(self) -> bool:
        """Test AI integration specifically"""
        try:
            # Test with a URL that should trigger AI analysis
            test_url = "https://suspicious-phishing-site.example.com"
            
            response = requests.post(
                f"{self.api_url}/check-url",
                json={"url": test_url},
                timeout=60
            )
            
            if response.status_code != 200:
                self.log_test("AI Integration", False, f"HTTP {response.status_code}")
                return False
            
            result = response.json()
            ai_scores = result.get('ai_scores', {})
            
            # Check if AI scores are present and reasonable
            required_scores = ['url_model_score', 'content_model_score', 'ensemble_score', 'confidence']
            scores_present = all(score in ai_scores for score in required_scores)
            
            if not scores_present:
                self.log_test("AI Integration", False, "Missing AI scores")
                return False
            
            # Check if scores are in valid range (0-100)
            valid_ranges = all(0 <= ai_scores[score] <= 100 for score in required_scores)
            
            if not valid_ranges:
                self.log_test("AI Integration", False, f"Invalid score ranges: {ai_scores}")
                return False
            
            self.log_test("AI Integration", True, f"AI analysis working: {ai_scores}")
            return True
            
        except Exception as e:
            self.log_test("AI Integration", False, f"Error: {str(e)}")
            return False

    def run_all_tests(self) -> Dict[str, Any]:
        """Run all tests and return results"""
        print("🚀 Starting Phishing URL Checker Backend Tests")
        print("=" * 60)
        
        start_time = time.time()
        
        # Test sequence
        tests = [
            ("API Health", self.test_api_health),
            ("URL Validation", self.test_url_validation),
            ("Comprehensive URL Analysis", self.test_url_analysis_comprehensive),
            ("AI Integration", self.test_ai_integration),
            ("Scan History", self.test_scan_history),
            ("Individual Scan Retrieval", self.test_individual_scan_retrieval),
            ("PDF Generation", self.test_pdf_generation),
        ]
        
        for test_name, test_func in tests:
            print(f"\n📋 Running {test_name}...")
            try:
                test_func()
            except Exception as e:
                self.log_test(test_name, False, f"Test execution error: {str(e)}")
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Summary
        print("\n" + "=" * 60)
        print("📊 TEST SUMMARY")
        print("=" * 60)
        print(f"Total Tests: {self.tests_run}")
        print(f"Passed: {self.tests_passed}")
        print(f"Failed: {self.tests_run - self.tests_passed}")
        print(f"Success Rate: {(self.tests_passed/self.tests_run*100):.1f}%")
        print(f"Duration: {duration:.2f} seconds")
        
        # Detailed results
        failed_tests = [test for test in self.test_results if not test['success']]
        if failed_tests:
            print(f"\n❌ FAILED TESTS ({len(failed_tests)}):")
            for test in failed_tests:
                print(f"  • {test['test_name']}: {test['details']}")
        
        return {
            "total_tests": self.tests_run,
            "passed_tests": self.tests_passed,
            "failed_tests": self.tests_run - self.tests_passed,
            "success_rate": (self.tests_passed/self.tests_run*100) if self.tests_run > 0 else 0,
            "duration": duration,
            "test_results": self.test_results,
            "scan_ids": self.scan_ids
        }

def main():
    """Main test execution"""
    tester = PhishingCheckerTester()
    results = tester.run_all_tests()
    
    # Return appropriate exit code
    return 0 if results["failed_tests"] == 0 else 1

if __name__ == "__main__":
    sys.exit(main())