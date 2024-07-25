#!/bin/bash

# Directory containing the git projects
BASE_DIR="$HOME/Documents"

# Define directories for categories
INTERNALS_DIR="$BASE_DIR/Internals"
WEB_DIR="$BASE_DIR/Web"
WIFI_DIR="$BASE_DIR/WiFi"
RECON_DIR="$BASE_DIR/Recon"
PASSGEN_DIR="$BASE_DIR/PassGen"
GENERAL_DIR="$BASE_DIR/General"

# Function to update all git repositories in a given directory
update_git_repositories() {
  local target_dir=$1
  echo "Updating repositories in $target_dir..."
  
  # Change to the target directory
  cd "$target_dir" || { echo "Failed to access $target_dir"; return; }

  # Loop through each subdirectory and perform git pull if it is a git repository
  for dir in */; do
    if [ -d "$dir/.git" ]; then
      echo "Updating repository in $dir..."
      cd "$dir" || { echo "Failed to access $dir"; continue; }
      git pull || echo "Failed to update repository in $dir"
      cd ..
    else
      echo "$dir is not a git repository."
    fi
  done
}

# Update git repositories in each directory
update_git_repositories "$INTERNALS_DIR"
update_git_repositories "$WEB_DIR"
update_git_repositories "$WIFI_DIR"
update_git_repositories "$RECON_DIR"
update_git_repositories "$PASSGEN_DIR"
update_git_repositories "$GENERAL_DIR"

echo "All repositories have been successfully updated."
