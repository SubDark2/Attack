import requests
import re
import os
import json
import time
from urllib.parse import urljoin, urlparse, parse_qs
import concurrent.futures
import shodan
from bs4 import BeautifulSoup
from db_manager import DatabaseManager

# إعدادات متقدمة
base_url = "https://tayseerme.com"
wordlist_file = "common_dirs.txt"
SHODAN_API_KEY = "cSQ4hGoR819UH3JebfAiO9E3vSunI7pG"
timeout = 5
max_threads = 20
output_dir = "scan_results"

# نتائج مُجمعة
found = {
    "metadata": {
        "target": base_url,
        "scan_date": None,
        "scan_duration": None
    },
    "paths": [],
    "js_analysis": {},
    "forms": [],
    "headers": {},
    "technologies": [],
    "shodan": [],
    "vulnerabilities": []
}

analyzed_js = set()
db = DatabaseManager()

def setup_scan():
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    found["metadata"]["scan_date"] = time.strftime("%Y-%m-%d %H:%M:%S")

def load_wordlist():
    with open(wordlist_file, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def parse_robots():
    try:
        response = requests.get(urljoin(base_url, '/robots.txt'), timeout=timeout)
        if response.status_code == 200:
            paths = []
            for line in response.text.split('\n'):
                if line.lower().startswith('disallow:'):
                    path = line.split(':', 1)[1].strip()
                    if path:
                        paths.append(path)
            return paths
    except:
        pass
    return []

def analyze_headers(url):
    try:
        response = requests.head(url, timeout=timeout)
        found["headers"][url] = dict(response.headers)
        
        # تحليل التقنيات من الهيدرز
        server = response.headers.get("Server")
        if server:
            found["technologies"].append({"type": "server", "name": server})
            
        powered_by = response.headers.get("X-Powered-By")
        if powered_by:
            found["technologies"].append({"type": "powered_by", "name": powered_by})
    except:
        pass

def analyze_forms(url, content):
    soup = BeautifulSoup(content, 'html.parser')
    forms = soup.find_all('form')
    
    for form in forms:
        form_data = {
            "action": form.get('action', ''),
            "method": form.get('method', 'get'),
            "inputs": []
        }
        
        for input_field in form.find_all(['input', 'textarea']):
            input_data = {
                "type": input_field.get('type', 'text'),
                "name": input_field.get('name', ''),
                "id": input_field.get('id', '')
            }
            form_data["inputs"].append(input_data)
            
        found["forms"].append(form_data)

def check_common_vulnerabilities(url, content):
    # فحص نقاط الضعف المحتملة
    checks = [
        {
            "type": "information_disclosure",
            "pattern": r"(?i)error|exception|warning|stack trace|debug",
            "description": "Possible information disclosure"
        },
        {
            "type": "sensitive_files",
            "pattern": r"(?i)backup|old|.bak|.swp|.config",
            "description": "Potential sensitive file exposure"
        }
    ]
    
    for check in checks:
        if re.search(check["pattern"], content):
            found["vulnerabilities"].append({
                "url": url,
                "type": check["type"],
                "description": check["description"]
            })

def check_url(path):
    url = urljoin(base_url, path)
    try:
        response = requests.get(url, timeout=timeout)
        status_code = response.status_code
        
        if status_code in [200, 403]:
            result = {
                "url": url,
                "status_code": status_code,
                "content_type": response.headers.get("content-type", "")
            }
            found["paths"].append(result)
            
            if status_code == 200:
                analyze_headers(url)
                content = response.text
                
                if "text/html" in response.headers.get("content-type", ""):
                    analyze_forms(url, content)
                    check_common_vulnerabilities(url, content)
                    
                elif url.endswith(".js"):
                    analyze_js(url, content)
    except:
        pass

def analyze_js(url, content=None):
    if url in analyzed_js:
        return
        
    try:
        if content is None:
            response = requests.get(url, timeout=timeout)
            content = response.text

        analysis = {
            "urls": [],
            "api_endpoints": [],
            "sensitive_data": []
        }

        # تحليل URLs
        urls = re.findall(r'https?://[^\s"\'>]+', content)
        analysis["urls"] = list(set(urls))

        # تحليل نقاط النهاية API
        api_patterns = [
            r'/api/[\w-]+',
            r'/v\d+/[\w-]+'
        ]
        
        for pattern in api_patterns:
            endpoints = re.findall(pattern, content)
            analysis["api_endpoints"].extend(endpoints)

        # البحث عن بيانات حساسة
        sensitive_patterns = {
            "api_key": r'(?i)(api[_-]?key|token|auth|secret)["\']?\s*[:=]\s*["\']([^"\'>]+)',
            "password": r'(?i)(password|pwd|pass)["\']?\s*[:=]\s*["\']([^"\'>]+)',
            "email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        }

        for key, pattern in sensitive_patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                analysis["sensitive_data"].append({
                    "type": key,
                    "matches": matches if isinstance(matches[0], str) else [m[1] for m in matches]
                })

        found["js_analysis"][url] = analysis
        analyzed_js.add(url)

    except Exception as e:
        print(f"Error analyzing JS {url}: {str(e)}")

def search_shodan():
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        results = api.search(f"hostname:tayseerme.com")
        
        for result in results.get("matches", []):
            host_info = {
                "ip": result.get("ip_str"),
                "port": result.get("port"),
                "org": result.get("org"),
                "location": {
                    "country": result.get("location", {}).get("country_name"),
                    "city": result.get("location", {}).get("city")
                },
                "services": result.get("data", "")
            }
            found["shodan"].append(host_info)
    except Exception as e:
        print(f"Shodan error: {str(e)}")

def save_results():
    # حفظ في ملف JSON
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(output_dir, f"scan_results_{timestamp}.json")
    
    with open(filename, 'w') as f:
        json.dump(found, f, indent=2)
    
    # حفظ في قاعدة البيانات
    scan_id = db.save_scan_results(found)
    
    print(f"\n[+] Detailed results saved to {filename}")
    print(f"[+] Results stored in database with scan ID: {scan_id}")

def show_scan_history():
    history = db.get_scan_history()
    print("\n=== Scan History ===")
    for scan in history:
        print(f"\nScan ID: {scan['id']}")
        print(f"Target: {scan['target_url']}")
        print(f"Date: {scan['scan_date']}")
        print(f"Duration: {scan['scan_duration']} seconds")
        print(f"Paths Found: {scan['total_paths']}")
        print(f"Vulnerabilities: {scan['total_vulnerabilities']}")

def main():
    start_time = time.time()
    setup_scan()
    
    print(f"[~] Starting comprehensive ASM scan for {base_url}")
    
    paths = load_wordlist() + parse_robots()
    custom_js = ["/assets/index.2f0ea05e.js", "/static/project_react/src/@core/js/bootstrap.min.js"]
    all_paths = set(paths + custom_js)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as ex:
        ex.map(check_url, all_paths)
    
    search_shodan()
    
    found["metadata"]["scan_duration"] = round(time.time() - start_time, 2)
    save_results()
    show_scan_history()

if __name__ == "__main__":
    main()