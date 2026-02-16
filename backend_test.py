import requests
import sys
import json
from datetime import datetime, timezone, timedelta
import uuid

class CodeGuardAPITester:
    def __init__(self, base_url="https://repodoctor.preview.emergentagent.com"):
        self.base_url = base_url
        self.session_token = None
        self.user_id = None
        self.tests_run = 0
        self.tests_passed = 0
        self.test_results = []

    def log_test(self, name, success, details=""):
        """Log test result"""
        self.tests_run += 1
        if success:
            self.tests_passed += 1
            print(f"✅ {name}")
        else:
            print(f"❌ {name} - {details}")
        
        self.test_results.append({
            "test": name,
            "success": success,
            "details": details
        })

    def run_test(self, name, method, endpoint, expected_status, data=None, headers=None):
        """Run a single API test"""
        url = f"{self.base_url}/{endpoint}"
        test_headers = {'Content-Type': 'application/json'}
        
        if headers:
            test_headers.update(headers)
            
        if self.session_token:
            test_headers['Authorization'] = f'Bearer {self.session_token}'

        try:
            if method == 'GET':
                response = requests.get(url, headers=test_headers, timeout=30)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=test_headers, timeout=30)
            elif method == 'DELETE':
                response = requests.delete(url, headers=test_headers, timeout=30)

            success = response.status_code == expected_status
            details = f"Status: {response.status_code}"
            
            if not success:
                details += f" (expected {expected_status})"
                try:
                    error_data = response.json()
                    details += f" - {error_data.get('detail', 'Unknown error')}"
                except:
                    details += f" - {response.text[:100]}"

            self.log_test(name, success, details)
            
            if success:
                try:
                    return response.json()
                except:
                    return {}
            return None

        except Exception as e:
            self.log_test(name, False, f"Error: {str(e)}")
            return None

    def create_test_user_session(self):
        """Create test user and session in MongoDB"""
        print("\n🔧 Setting up test user and session...")
        
        # Generate test data
        timestamp = int(datetime.now().timestamp())
        self.user_id = f"test-user-{timestamp}"
        email = f"test.user.{timestamp}@example.com"
        self.session_token = f"test_session_{timestamp}"
        
        try:
            import subprocess
            
            # Create user and session in MongoDB
            mongo_script = f'''
use('test_database');
db.users.insertOne({{
  user_id: "{self.user_id}",
  email: "{email}",
  name: "Test User",
  picture: "https://via.placeholder.com/150",
  created_at: new Date()
}});
db.user_sessions.insertOne({{
  user_id: "{self.user_id}",
  session_token: "{self.session_token}",
  expires_at: new Date(Date.now() + 7*24*60*60*1000),
  created_at: new Date()
}});
print("Test user created successfully");
'''
            
            result = subprocess.run(
                ['mongosh', '--eval', mongo_script],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                print(f"✅ Test user created: {self.user_id}")
                print(f"✅ Session token: {self.session_token}")
                return True
            else:
                print(f"❌ Failed to create test user: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"❌ Error creating test user: {str(e)}")
            return False

    def cleanup_test_data(self):
        """Clean up test data from MongoDB"""
        if not self.user_id:
            return
            
        try:
            import subprocess
            
            mongo_script = f'''
use('test_database');
db.users.deleteOne({{user_id: "{self.user_id}"}});
db.user_sessions.deleteOne({{user_id: "{self.user_id}"}});
db.analyses.deleteMany({{user_id: "{self.user_id}"}});
print("Test data cleaned up");
'''
            
            subprocess.run(['mongosh', '--eval', mongo_script], timeout=10)
            print("🧹 Test data cleaned up")
            
        except Exception as e:
            print(f"⚠️ Cleanup warning: {str(e)}")

    def test_basic_endpoints(self):
        """Test basic non-authenticated endpoints"""
        print("\n📡 Testing Basic Endpoints...")
        
        # Test root endpoint
        self.run_test("Root API endpoint", "GET", "api/", 200)
        
        # Test health endpoint
        self.run_test("Health check", "GET", "api/health", 200)

    def test_auth_endpoints(self):
        """Test authentication endpoints"""
        print("\n🔐 Testing Authentication...")
        
        # Test /me endpoint with valid session
        user_data = self.run_test("Get current user", "GET", "api/auth/me", 200)
        
        if user_data:
            print(f"   User: {user_data.get('name')} ({user_data.get('email')})")
        
        # Test logout
        self.run_test("Logout", "POST", "api/auth/logout", 200)

    def test_analysis_endpoints(self):
        """Test analysis endpoints"""
        print("\n🔍 Testing Analysis Endpoints...")
        
        # Test list analyses (should be empty initially)
        analyses = self.run_test("List analyses", "GET", "api/analysis/list", 200)
        
        # Test dashboard stats
        stats = self.run_test("Dashboard stats", "GET", "api/analysis/stats/dashboard", 200)
        
        if stats:
            print(f"   Total analyses: {stats.get('total_analyses', 0)}")
        
        # Test GitHub analysis with a simple public repo
        print("\n   Testing GitHub analysis...")
        github_data = {
            "github_url": "https://github.com/octocat/Hello-World",
            "name": "Test Analysis"
        }
        
        analysis_result = self.run_test(
            "GitHub analysis", 
            "POST", 
            "api/analysis/github", 
            200, 
            github_data
        )
        
        analysis_id = None
        if analysis_result:
            analysis_id = analysis_result.get('analysis_id')
            print(f"   Analysis ID: {analysis_id}")
            
            # Test get specific analysis
            if analysis_id:
                analysis_detail = self.run_test(
                    "Get analysis detail", 
                    "GET", 
                    f"api/analysis/{analysis_id}", 
                    200
                )
                
                if analysis_detail:
                    print(f"   Status: {analysis_detail.get('status')}")
                    print(f"   Score: {analysis_detail.get('overall_score', 'N/A')}")

    def test_invalid_endpoints(self):
        """Test error handling"""
        print("\n❌ Testing Error Handling...")
        
        # Test non-existent analysis
        self.run_test("Non-existent analysis", "GET", "api/analysis/invalid-id", 404)
        
        # Test invalid GitHub URL
        invalid_github = {"github_url": "not-a-url"}
        self.run_test("Invalid GitHub URL", "POST", "api/analysis/github", 400, invalid_github)

    def run_all_tests(self):
        """Run complete test suite"""
        print("🚀 Starting CodeGuard AI Backend Tests")
        print(f"🎯 Target: {self.base_url}")
        
        # Setup test user
        if not self.create_test_user_session():
            print("❌ Cannot proceed without test user setup")
            return False
        
        try:
            # Run test suites
            self.test_basic_endpoints()
            self.test_auth_endpoints()
            self.test_analysis_endpoints()
            self.test_invalid_endpoints()
            
            # Print summary
            print(f"\n📊 Test Results: {self.tests_passed}/{self.tests_run} passed")
            
            if self.tests_passed == self.tests_run:
                print("🎉 All tests passed!")
                return True
            else:
                print("⚠️ Some tests failed")
                return False
                
        finally:
            self.cleanup_test_data()

def main():
    tester = CodeGuardAPITester()
    success = tester.run_all_tests()
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())