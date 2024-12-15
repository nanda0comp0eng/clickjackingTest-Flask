import requests
from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse

app = Flask(__name__)

def check_clickjacking(url):
    """
    Check a website for clickjacking vulnerabilities
    by examining X-Frame-Options and Content-Security-Policy headers
    """
    try:
        # Validate URL
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            return {
                'vulnerable': True, 
                'reason': 'Invalid URL format',
                'details': {}
            }

        # Send HEAD request to check headers
        response = requests.head(url, timeout=10)
        
        # Check X-Frame-Options header
        x_frame_options = response.headers.get('X-Frame-Options', '').upper()
        
        # Check Content-Security-Policy header
        csp = response.headers.get('Content-Security-Policy', '')
        
        # Determine vulnerability
        is_vulnerable = True
        reasons = []

        # X-Frame-Options checks
        if x_frame_options == 'DENY':
            is_vulnerable = False
            reasons.append('X-Frame-Options: DENY (Good Protection)')
        elif x_frame_options == 'SAMEORIGIN':
            is_vulnerable = False
            reasons.append('X-Frame-Options: SAMEORIGIN (Good Protection)')
        else:
            reasons.append('No X-Frame-Options header found')

        # CSP checks for frame-ancestors
        if 'frame-ancestors' in csp.lower():
            frame_ancestors = [part.strip() for part in csp.lower().split('frame-ancestors')[1].split(';')[0].split()]
            if "'none'" in frame_ancestors or 'https:' in frame_ancestors:
                is_vulnerable = False
                reasons.append('Content-Security-Policy protects against clickjacking')
            else:
                reasons.append('Weak Content-Security-Policy')
        else:
            reasons.append('No frame-ancestors in Content-Security-Policy')

        return {
            'vulnerable': is_vulnerable,
            'reason': ', '.join(reasons),
            'details': {
                'X-Frame-Options': x_frame_options or 'Not Set',
                'Content-Security-Policy': csp or 'Not Set'
            }
        }

    except requests.RequestException as e:
        return {
            'vulnerable': True, 
            'reason': f'Request failed: {str(e)}',
            'details': {}
        }

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    url = None
    if request.method == 'POST':
        url = request.form.get('url')
        result = check_clickjacking(url)
    return render_template('index.html', result=result, url=url)

@app.route('/test', methods=['GET'])
def test_page():
    return render_template('main.html')

if __name__ == '__main__':
    app.run(debug=True)