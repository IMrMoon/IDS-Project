#!/bin/bash
# upload_git.sh – initialise a Git repository and prepare for first push.

# Ensure a .gitignore file exists.  If it doesn't, you can create one manually.
if [ ! -f .gitignore ]; then
  echo "Warning: .gitignore not found. You should create one to exclude unnecessary files." >&2
fi

# Initialise the repository if not already initialised
if [ ! -d .git ]; then
  git init
fi

# Stage all files (respects .gitignore)
git add .

# Commit
git commit -m "Initial commit of Simple IDS project" || echo "Nothing to commit; maybe repository already has commits."

echo "Repository initialised. To push to a remote repository, run:"
echo "  git remote add origin <your-remote-url>"
echo "  git push -u origin master"