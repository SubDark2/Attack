import requests, json, re
from urllib.parse import urljoin, urlparse, parse_qs
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import concurrent.futures
import shodan

# إعدادات
base_url = "https://tayseerme.com"
wordlist_file = "common_dirs.txt"
SHODAN_API_KEY = "IVYPa91tXBuOvKLJiRnlivqMQYEeSnLD"
timeout = 6

results = {
    "paths": [],
    "js_analysis": {},
    "security_headers": {},
    "shodan": [],
    "dom_snapshot": ""
}

analyzed_js = set()

# تحميل الكلمات
def load_wordlist():
    with open(wordlist_file, 'r') as f:
        return [line.strip() for line in f if line.strip()]

# تحليل robots.txt
def parse_robots():
    try:
        resp = requests.get(urljoin(base_url, "/robots.txt"), timeout=timeout)
        return [line.split(":",1)[1].strip() for line in resp.text.splitlines() if line.lower().startswith("disallow")]
    except:
        return []

# تحليل رؤوس HTTP الأمنية
def analyze_security_headers():
    try:
        resp = requests.get(base_url, timeout=timeout)
        headers = resp.headers
        sec_keys = [
            'Content-Security-Policy', 'Strict-Transport-Security', 'X-Frame-Options',
            'X-Content-Type-Options', 'Referrer-Policy', 'Permissions-Policy'
        ]
        results['security_headers'] = {k: headers.get(k, 'Missing') for k in sec_keys}
    except:
        results['security_headers'] = {}

# تحليل ملفات JS
def analyze_js(js_url):
    if js_url in analyzed_js:
        return
    analyzed_js.add(js_url)
    entry = {"external_urls": [], "possible_keys": [], "source_map": None, "xss_candidates": []}
    try:
        resp = requests.get(js_url, timeout=timeout)
        content = resp.text
        urls = set(re.findall(r'https?://[^\s"\'<>]+', content))
        entry["external_urls"] = list(urls)
        keys = re.findall(r'(?i)(api[_-]?key|token|auth|secret)["\']?\s*[:=]\s*["\']([^"\']+)', content)
        entry["possible_keys"] = [{"type": k, "value": v} for k,v in keys]
        m = re.search(r'\/\/#\s*sourceMappingURL=(.+\.map)', content)
        if m:
            entry["source_map"] = urljoin(js_url, m.group(1))
        for u in urls:
            parsed = urlparse(u)
            params = parse_qs(parsed.query)
            for pname in params:
                entry["xss_candidates"].append({"url": u, "param": pname})
    except:
        pass
    results["js_analysis"][js_url] = entry

# التحقق من المسارات
def check_url(path):
    url = urljoin(base_url, path)
    try:
        resp = requests.get(url, timeout=timeout)
        status = resp.status_code
        if status in [200, 403]:
            results["paths"].append({"url": url, "status": status})
            if url.endswith(".js"):
                analyze_js(url)
    except:
        pass

# فحص Shodan
def search_shodan():
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        res = api.search(f"hostname:tayseerme.com")
        for m in res.get("matches", []):
            results["shodan"].append({
                "ip": m.get("ip_str"),
                "port": m.get("port"),
                "org": m.get("org"),
                "data": m.get("data","")
            })
    except:
        pass

# تحليل DOM باستخدام Selenium
def capture_dom():
    try:
        opts = Options()
        opts.add_argument("--headless")
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-dev-shm-usage")
        driver = webdriver.Chrome(options=opts)
        driver.set_page_load_timeout(timeout)
        driver.get(base_url)
        results["dom_snapshot"] = driver.page_source[:5000]  # ملخص أول 5000 حرف
        driver.quit()
    except:
        results["dom_snapshot"] = "Failed to capture DOM"

# تشغيل الأداة
def main():
    print(f"[~] Starting advanced ASM scan on {base_url}")

    paths = load_wordlist() + parse_robots()
    custom_js = ["/assets/index.2f0ea05e.js", "/static/project_react/src/@core/js/bootstrap.min.js"]
    all_paths = set(paths + custom_js)

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        ex.map(check_url, all_paths)

    analyze_security_headers()
    search_shodan()
    capture_dom()

    with open("attack_surface_advanced.json", "w") as f:
        json.dump(results, f, indent=2)

    print("\n[+] Advanced scan complete. Results saved in attack_surface_advanced.json\n")

if __name__ == "__main__":
    main()
