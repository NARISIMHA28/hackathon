import os
import mimetypes
import requests
from flask import Flask, request, jsonify, render_template, url_for
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

app = Flask(__name__)

# Configurations
UPLOAD_FOLDER = "uploads"
STATIC_PREVIEW_FOLDER = "static/previews"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['STATIC_PREVIEW_FOLDER'] = STATIC_PREVIEW_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(STATIC_PREVIEW_FOLDER, exist_ok=True)

# VirusTotal API Key and URL
API_KEY = 'aa61986da7c1355a4aed4ea0be931451b887e2902a1f7f58718abd08874f97dc'  # Replace with your VirusTotal API key
UPLOAD_URL = 'https://www.virustotal.com/api/v3/files'


def upload_and_analyze_apk(file_path):
    """Uploads an APK file to VirusTotal for analysis."""
    with open(file_path, 'rb') as apk_file:
        headers = {'x-apikey': API_KEY}
        files = {'file': apk_file}
        print("Uploading the file to VirusTotal...")
        
        response = requests.post(UPLOAD_URL, headers=headers, files=files)
        if response.status_code == 200:
            data = response.json()
            analysis_id = data['data']['id']
            print("File uploaded successfully!")
            print(f"Analysis ID: {analysis_id}")
            return analysis_id
        else:
            print("Error uploading file!")
            print(response.json())
            return None


def get_analysis_results(analysis_id):
    """Retrieves the analysis results from VirusTotal."""
    ANALYSIS_URL = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
    headers = {'x-apikey': API_KEY}
    print("Retrieving the analysis results...")
    
    response = requests.get(ANALYSIS_URL, headers=headers)
    if response.status_code == 200:
        data = response.json()
        return data
    else:
        print("Error retrieving analysis results!")
        return response.json()


def analyze_malicious_results(analysis_results):
    """Analyzes the VirusTotal results to determine if the APK is harmful."""
    if not analysis_results:
        return "Unable to retrieve analysis results."

    # Example of how you might determine malicious behavior
    malicious = False
    for engine in analysis_results['data']['attributes']['last_analysis_results']:
        if analysis_results['data']['attributes']['last_analysis_results'][engine]['category'] == "malicious":
            malicious = True
            break

    return "Harmful" if malicious else "Safe"


def generate_preview_for_website(url):
    """Generates a screenshot preview for a given website URL."""
    try:
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--window-size=1200x800")

        driver = webdriver.Chrome(options=chrome_options)
        driver.get(url)

        screenshot_path = os.path.join(app.config['STATIC_PREVIEW_FOLDER'], "preview_website.png")
        driver.save_screenshot(screenshot_path)
        driver.quit()

        return screenshot_path
    except Exception as e:
        return str(e)


def process_uploaded_file(file_path):
    """Processes the uploaded file to extract its metadata and content preview."""
    try:
        file_info = {
            "filename": os.path.basename(file_path),
            "size": os.path.getsize(file_path),
            "type": mimetypes.guess_type(file_path)[0]
        }

        if file_info["type"] in ["text/plain", "text/html"]:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
                if file_info["type"] == "text/html":
                    soup = BeautifulSoup(content, "html.parser")
                    text = soup.get_text()
                    file_info["content_preview"] = text[:500]
                else:
                    file_info["content_preview"] = content[:500]

        return file_info
    except Exception as e:
        return {"error": str(e)}


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'url' in request.form:
        url = request.form['url']
        preview = generate_preview_for_website(url)
        if os.path.exists(preview):
            return jsonify({"url": url, "preview": url_for('static', filename=f"previews/{os.path.basename(preview)}")})
        else:
            return jsonify({"error": preview}), 400

    elif 'file' in request.files:
        file = request.files['file']
        if file:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(file_path)

            # Handle APK analysis
            if file.filename.endswith('.apk'):
                analysis_id = upload_and_analyze_apk(file_path)
                if analysis_id:
                    analysis_results = get_analysis_results(analysis_id)
                    malicious = analyze_malicious_results(analysis_results)
                    return jsonify({"malicious": malicious, "analysis_results": analysis_results})

            file_info = process_uploaded_file(file_path)
            return jsonify(file_info)

    return jsonify({"error": "Invalid request"}), 400


if __name__ == '__main__':
    app.run(debug=True)
