#!/bin/bash
# run.sh — Start the Secure Document Vault

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Load environment variables from .env
if [ -f ".env" ]; then
  export $(cat .env | grep -v '^#' | xargs)
  echo "✅ Loaded environment from .env"
else
  echo "⚠️  .env file not found. Using defaults."
fi

echo ""
echo "🔒 Secure Document Vault"
echo "========================"
echo ""

# Check Python
if ! command -v python3 &>/dev/null; then
  echo "❌ Python 3 is required. Please install it first."
  exit 1
fi

# Install dependencies
echo "📦 Checking dependencies..."
pip install -q Flask cryptography PyJWT Werkzeug python-dotenv --break-system-packages 2>/dev/null || \
pip install -q Flask cryptography PyJWT Werkzeug python-dotenv 2>/dev/null || true

# Generate certs if missing
if [ ! -f "certs/cert.pem" ] || [ ! -f "certs/key.pem" ]; then
  echo "🔐 Generating SSL certificate..."
  mkdir -p certs
  openssl req -x509 -newkey rsa:4096 \
    -keyout certs/key.pem \
    -out certs/cert.pem \
    -days 365 -nodes \
    -subj "/C=EG/ST=Gharbia/O=SecureVault/CN=localhost" 2>/dev/null
  echo "✅ Certificate generated"
fi

echo ""
echo "🚀 Starting server..."
echo "   URL: https://localhost:5443"
echo "   Admin: admin / Admin@123456"
echo ""
echo "   Press Ctrl+C to stop"
echo ""

cd backend
python3 server.py
