#!/usr/bin/env python3
"""
Comprehensive Test Runner for Secure Chat System with Virtual Environment Support
"""

import unittest
import sys
import os
import subprocess

# Add virtual environment to path
venv_path = os.path.join(os.path.dirname(__file__), 'securechat-env')
if os.path.exists(venv_path):
    # Add virtual environment's site-packages to Python path
    site_packages = os.path.join(venv_path, 'lib', 'python3.*', 'site-packages')
    import glob
    site_packages_dirs = glob.glob(site_packages)
    if site_packages_dirs:
        sys.path.insert(0, site_packages_dirs[0])

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

# Check if we're in virtual environment, if not, warn
if not hasattr(sys, 'real_prefix') and not (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
    print("⚠️  Warning: Not running in virtual environment. Run 'source securechat-env/bin/activate' first.")

def run_all_tests():
    """Discover and run all tests"""
    
    print("🧪 Running Secure Chat System Tests")
    print("=" * 60)
    
    # Discover and run unit tests
    loader = unittest.TestLoader()
    start_dir = 'tests'
    suite = loader.discover(start_dir, pattern='test_*.py')
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Run additional security tests
    print("\n" + "=" * 60)
    print("🔒 Running Security Tests")
    print("=" * 60)
    
    security_tests = [
        ("Invalid Certificate Test", "python tests/test_invalid_certificates.py"),
        ("Tampering Detection Test", "python tests/test_tampering.py"),
        ("Replay Attack Test", "python tests/test_replay.py"),
        ("Non-Repudiation Test", "python tests/test_non_repudiation.py"),
    ]
    
    security_results = []
    for test_name, command in security_tests:
        try:
            print(f"\n🔍 {test_name}")
            subprocess.run(command, shell=True, check=True)
            security_results.append((test_name, True))
        except subprocess.CalledProcessError:
            security_results.append((test_name, False))
    
    # Print summary
    print("\n" + "=" * 60)
    print("📊 COMPREHENSIVE TEST SUMMARY")
    print("=" * 60)
    
    # Unit test results
    unit_tests_passed = result.testsRun - len(result.failures) - len(result.errors)
    print(f"🔬 Unit Tests: {unit_tests_passed}/{result.testsRun} passed")
    
    # Security test results
    security_passed = sum(1 for _, success in security_results if success)
    security_total = len(security_results)
    print(f"🔒 Security Tests: {security_passed}/{security_total} passed")
    
    # Overall
    total_passed = unit_tests_passed + security_passed
    total_tests = result.testsRun + security_total
    print(f"🎯 Overall: {total_passed}/{total_tests} passed ({total_passed/total_tests*100:.1f}%)")
    
    if result.failures:
        print("\n🔴 UNIT TEST FAILURES:")
        for test, traceback in result.failures:
            print(f"  {test}: {traceback.splitlines()[-1]}")
    
    if result.errors:
        print("\n🟠 UNIT TEST ERRORS:")
        for test, traceback in result.errors:
            print(f"  {test}: {traceback.splitlines()[-1]}")
    
    for test_name, success in security_results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status}: {test_name}")
    
    success = (len(result.failures) == 0 and 
               len(result.errors) == 0 and 
               security_passed == security_total)
    
    if success:
        print("\n🎉 ALL TESTS PASSED! System meets all security requirements for CIANR.")
        print("   - Confidentiality: ✅ AES-128 Encryption")
        print("   - Integrity: ✅ SHA-256 + RSA Signatures") 
        print("   - Authenticity: ✅ Certificate Validation")
        print("   - Non-Repudiation: ✅ Session Transcripts")
    else:
        print("\n💥 Some tests failed. Please fix the issues before submission.")
    
    return success

if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
