#!/bin/bash

# Path to the agent.env file
ENV_FILE="agent.env"
ENCRYPTED_FILE="secret.enc"

# Function to load the ENC_KEY from agent.env
load_enckey() {
  if [[ -f "$ENV_FILE" ]]; then
    # Extract ENC_KEY from the environment file
    ENC_KEY=$(grep -oP '^ENC_KEY=\K.*' "$ENV_FILE")
    if [[ -z "$ENC_KEY" ]]; then
      echo "Error: ENC_KEY not found in $ENV_FILE"
      exit 1
    fi
  else
    echo "Error: Environment file $ENV_FILE does not exist."
    exit 1
  fi
}

# Function to decrypt the file
decrypt_file() {
  if [[ -f "$ENCRYPTED_FILE" ]]; then
    # Use OpenSSL to decrypt the file
    PLAINTEXT=$(openssl aes-256-cbc -d -salt -pbkdf2 -in "$ENCRYPTED_FILE" -k "$ENC_KEY" 2>/dev/null)
    
    if [[ $? -ne 0 ]]; then
      echo "Error: Decryption failed. Ensure the key and file are correct."
      exit 1
    else
      echo "Decrypted Data:"
      echo "$PLAINTEXT"
    fi
  else
    echo "Error: Encrypted file $ENCRYPTED_FILE does not exist."
    exit 1
  fi
}

# Main execution
load_enckey
decrypt_file
