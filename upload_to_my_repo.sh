#!/bin/bash
# 🛡️ Upload to your personal GitHub repo: stylish-creator-007/KAVACH-V1.git

# Step 1: Go to your project directory
cd ~/KAVACH-V1- || { echo "❌ Directory not found!"; exit 1; }

# Step 2: Remove old remote (if any)
git remote remove origin 2>/dev/null

# Step 3: Add your new remote
git remote add origin https://github.com/stylish-creator-007/KAVACH-V1.git

# Step 4: Ask for a commit message
read -p "📝 Enter commit message: " commit_msg

# Step 5: Stage, commit, and push
git add .
git commit -m "$commit_msg"
git branch -M main 2>/dev/null
git push -u origin main

echo "✅ Successfully pushed to https://github.com/stylish-creator-007/KAVACH-V1.git"
