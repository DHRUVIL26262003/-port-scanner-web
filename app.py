#!/usr/bin/env python3
"""
Simple GitHub Uploader
Upload files to your existing repository
"""

import requests
import base64
import os
import time

# Your GitHub token
GITHUB_TOKEN = "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"
REPO_NAME = "port-scanner-web"
USERNAME = "dskum"

def upload_file(file_path, content, message):
    """Upload a single file to GitHub"""
    url = f"https://api.github.com/repos/{USERNAME}/{REPO_NAME}/contents/{file_path}"
    
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    # Encode content to base64
    content_b64 = base64.b64encode(content.encode('utf-8')).decode('utf-8')
    
    data = {
        "message": message,
        "content": content_b64
    }
    
    try:
        response = requests.put(url, headers=headers, json=data)
        if response.status_code == 201:
            print(f"✅ Uploaded: {file_path}")
            return True
        else:
            print(f"❌ Failed: {file_path} - {response.status_code}")
            print(f"Response: {response.text}")
            return False
    except Exception as e:
        print(f"❌ Error: {file_path} - {e}")
        return False

def main():
    print("🚀 UPLOADING TO GITHUB")
    print("=" * 30)
    print()
    
    # Files to upload
    files = [
        ("app.py", "Main Flask application"),
        ("requirements.txt", "Python dependencies"),
        ("render.yaml", "Render deployment config"),
        ("README.md", "Project documentation"),
        ("templates/index.html", "Main web interface"),
        ("templates/results.html", "Results display page")
    ]
    
    success_count = 0
    
    for file_path, description in files:
        if os.path.exists(file_path):
            print(f"Uploading {file_path}...")
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                if upload_file(file_path, content, f"Add {description}"):
                    success_count += 1
                
                time.sleep(1)  # Avoid rate limiting
                
            except Exception as e:
                print(f"❌ Error reading {file_path}: {e}")
        else:
            print(f"⚠️ File not found: {file_path}")
    
    print(f"\n📊 Uploaded {success_count}/{len(files)} files")
    
    if success_count > 0:
        print(f"\n🎉 SUCCESS!")
        print(f"Repository: https://github.com/{USERNAME}/{REPO_NAME}")
        print("\nNext: Deploy to Render.com for public access!")

if __name__ == "__main__":
    main()
