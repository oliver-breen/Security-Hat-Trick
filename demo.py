#!/usr/bin/env python3
"""
Demo script to showcase the Security Hat Trick framework
Runs the vulnerable app and performs a security audit
"""
import time
import subprocess
import sys
import signal
from auditor.scanner import SecurityAuditor

def main():
    """Run the demo"""
    print("="*80)
    print("Security Hat Trick - Demo")
    print("="*80)
    print()
    print("This demo will:")
    print("1. Start the vulnerable web application")
    print("2. Run the security auditor to detect vulnerabilities")
    print("3. Display the security report")
    print()
    print("⚠️  WARNING: This demo runs an intentionally vulnerable application!")
    print("   Only run this in an isolated, controlled environment.")
    print()
    
    # Start the vulnerable app
    print("Starting vulnerable application on http://localhost:5000...")
    app_process = subprocess.Popen(
        [sys.executable, '-m', 'vulnerable_app.app'],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    
    # Wait for app to start
    print("Waiting for application to start...")
    time.sleep(3)
    
    try:
        # Run the security audit
        print("\nRunning security audit...")
        print("-" * 80)
        
        auditor = SecurityAuditor('http://localhost:5000')
        report = auditor.scan()
        auditor.print_report()
        
        print("\n" + "="*80)
        print("Demo completed successfully!")
        print("="*80)
        
    finally:
        # Clean up: stop the vulnerable app
        print("\nStopping vulnerable application...")
        app_process.terminate()
        try:
            app_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            app_process.kill()
        print("Demo cleanup complete.")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n\nError running demo: {e}")
        sys.exit(1)
