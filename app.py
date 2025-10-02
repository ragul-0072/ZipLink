from flask import Flask, jsonify, request, redirect, abort, render_template
from flask_cors import CORS
import random
import string
from datetime import datetime
import pytz
import firebase_admin
from firebase_admin import credentials, firestore
from firebase_admin import exceptions as fb_exceptions
import re
from werkzeug.security import generate_password_hash, check_password_hash
import os  # Added for environment variables
import json # Added to parse Firebase credentials

app = Flask(__name__)

# --- CONFIGURATION CHANGES FOR RENDER ---

# 1. Use the RENDER_EXTERNAL_URL provided by Render, with a fallback for local dev
BASE_URL = os.environ.get('RENDER_EXTERNAL_URL', 'http://localhost:5000')

# 2. Get the frontend URL from an environment variable to configure CORS
frontend_url = os.environ.get('FRONTEND_URL', 'http://localhost:5173')
CORS(app, origins=[frontend_url])

# 3. Load Firebase credentials securely from an environment variable
firebase_creds_json = os.environ.get('FIREBASE_CREDS_JSON')
if not firebase_creds_json:
    # This will cause the app to fail on startup if the variable isn't set
    raise ValueError("The FIREBASE_CREDS_JSON environment variable is not set.")

cred_dict = json.loads(firebase_creds_json)
cred = credentials.Certificate(cred_dict)
firebase_admin.initialize_app(cred)

# --- END OF CONFIGURATION CHANGES ---

db = firestore.client()

# Define the Indian Standard Timezone
IST = pytz.timezone('Asia/Kolkata')

RESERVED_ALIASES = {
    'app', 'shorten', 'login', 'signup', 'auth', 'admin', 'dashboard', 'static', 'api', 'help', 'verify_password'
}

def generate_random_code():
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for i in range(6))

def is_short_code_available(code):
    doc_ref = db.collection('links').document(code)
    return not doc_ref.get().exists

@app.route('/')
def index():
    return jsonify({"message": "ZipLink Backend is running!"})

@app.route('/shorten', methods=['POST'])
def shorten_url():
    try:
        data = request.get_json(silent=True)
        if data is None:
            return jsonify({"error": "Request body must be valid JSON"}), 400

        long_url = data.get('longUrl')
        custom_alias = data.get('customAlias')
        link_password = data.get('linkPassword')
        user_id = data.get('userId')
        expiration_date_str = data.get('expirationDate')

        if not long_url:
            return jsonify({"error": "longUrl is required"}), 400

        short_code = None
        if custom_alias:
            short_code = custom_alias.lower()
            if not re.match(r'^[a-z0-9_-]+$', short_code):
                return jsonify({"error": "Custom alias can only contain lowercase letters, numbers, hyphens, and underscores."}), 400
            if short_code in RESERVED_ALIASES:
                return jsonify({"error": f"The alias '/{short_code}' is reserved."}), 400
            if len(short_code) < 3:
                return jsonify({"error": "Custom alias must be at least 3 characters long."}), 400
            if not is_short_code_available(short_code):
                return jsonify({"error": f"The custom alias '/{short_code}' is already taken."}), 409
        else:
            while True:
                short_code = generate_random_code()
                if short_code not in RESERVED_ALIASES and is_short_code_available(short_code):
                    break

        password_hash = generate_password_hash(link_password) if link_password else None
        
        expiration_date_dt = None
        if expiration_date_str:
            try:
                expiration_date_dt = datetime.fromisoformat(expiration_date_str)
                # No need to localize here, as fromisoformat from a Z-ended string is already timezone-aware (UTC)
            except ValueError:
                return jsonify({"error": "Invalid expiration date format."}), 400

        link_data = {
            'long_url': long_url,
            'short_code': short_code,
            'user_id': user_id,
            'clicks': 0,
            'created_at': datetime.now(pytz.utc), # Store in UTC for consistency
            'password_hash': password_hash,
            'is_protected': bool(link_password)
        }
        if expiration_date_dt:
            link_data['expires_at'] = expiration_date_dt

        doc_ref = db.collection('links').document(short_code)
        doc_ref.set(link_data)
        
        return jsonify({
            "shortUrl": f"{BASE_URL}/{short_code}",
            "isProtected": bool(link_password)
        })

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500

@app.route('/verify_password', methods=['POST'])
def verify_password():
    data = request.get_json(silent=True)
    short_code = data.get('shortCode')
    submitted_password = data.get('password')

    if not short_code or not submitted_password:
        return jsonify({"error": "Missing short code or password."}), 400

    doc_ref = db.collection('links').document(short_code)
    doc = doc_ref.get()

    if doc.exists:
        link_data = doc.to_dict()
        stored_hash = link_data.get('password_hash')
        if stored_hash and check_password_hash(stored_hash, submitted_password):
            long_url = link_data['long_url']
            doc_ref.update({'clicks': firestore.Increment(1)})
            return jsonify({"success": True, "longUrl": long_url})
        else:
            return jsonify({"success": False, "error": "Invalid password."}), 401
    else:
        return jsonify({"error": "Link not found."}), 404

@app.route('/<short_code>')
def redirect_to_long_url(short_code):
    if short_code.lower() in RESERVED_ALIASES:
        return abort(404)

    doc_ref = db.collection('links').document(short_code)
    doc = doc_ref.get()
    
    if doc.exists:
        data = doc.to_dict()

        if 'expires_at' in data and data['expires_at']:
            expiration_time = data['expires_at']
            if datetime.now(pytz.utc) > expiration_time:
                return render_expired_page(), 410

        if data.get('is_protected'):
            return render_password_gateway(short_code)
        
        long_url = data['long_url']
        doc_ref.update({'clicks': firestore.Increment(1)})
        return redirect(long_url)
    else:
        return abort(404)

def render_password_gateway(short_code):
    # This function remains mostly the same, but the BASE_URL is now dynamic
    html_template = """
    <!DOCTYPE html>
    <html lang="en">
        <script>
            // ... inside your script tag ...
            const API_BASE_URL = "{BASE_URL}"; // This will be replaced
            // ... rest of the script ...
        </script>
    </html>
    """
    return html_template.replace('{short_code}', short_code).replace('{BASE_URL}', BASE_URL)

def render_expired_page():
    return """
    <!DOCTYPE html>
    <html lang="en">
        </html>
    """, 410

@app.route('/api/links/<user_id>', methods=['GET'])
def get_user_links(user_id):
    try:
        links_ref = db.collection('links').where('user_id', '==', user_id).order_by('created_at', direction=firestore.Query.DESCENDING)
        docs = links_ref.stream()
        
        links = []
        for doc in docs:
            link_data = doc.to_dict()
            links.append({
                'id': doc.id,
                'long_url': link_data.get('long_url'),
                'short_code': link_data.get('short_code'),
                'short_url': f"{BASE_URL}/{link_data.get('short_code')}",
                'clicks': link_data.get('clicks', 0),
                'created_at': link_data.get('created_at').isoformat() if link_data.get('created_at') else None,
                'expires_at': link_data.get('expires_at').isoformat() if link_data.get('expires_at') else None,
                'is_protected': link_data.get('is_protected', False)
            })
        return jsonify({"links": links})

    except Exception as e:
        print(f"Error fetching user links: {e}")
        return jsonify({"error": "Failed to fetch links due to an internal server error."}), 500

@app.route('/api/link/<short_code>', methods=['DELETE'])
def delete_link(short_code):
    try:
        db.collection('links').document(short_code).delete()
        return jsonify({"message": f"Link {short_code} deleted successfully."})

    except fb_exceptions.NotFound:
        return jsonify({"error": "Link not found."}), 404
    except Exception as e:
        print(f"Error deleting link: {e}")
        return jsonify({"error": "Failed to delete link due to internal error."}), 500

# NOTE: The if __name__ == '__main__': block is REMOVED for production.
# Render will use a WSGI server like Gunicorn to run the 'app' object directly.
