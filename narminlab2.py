import re,csv,json,os
from collections import Counter
class RegexSystemLogAnalysis:
    def __init__(self, log_file, blacklist_file):
        self.log_file = log_file
        self.blacklist_file = blacklist_file
        self.urls_and_statuses = []
        self.status_404_counts = Counter()
        self.blacklisted_domains = set()
        self.matched_url_details = []
    def extract_urls_and_statuses(self):
        with open(self.log_file, 'r', encoding='utf-8') as log:
            for line in log:
                match = re.search(r'"(?:GET|POST|PUT|DELETE) (http://[^\s]+) HTTP/1\.1" (\d{3})', line)
                if match:
                    url, status = match.groups()
                    self.urls_and_statuses.append((url, status))
                    if status == "404":
                        self.status_404_counts[url] += 1
    def create_url_status_report(self, file_path):
        with open(file_path, 'w', encoding='utf-8') as file:
            for url, status in self.urls_and_statuses:
                file.write(f"{url} {status}\n")
    def create_404_status_csv(self, csv_path):
        with open(csv_path, 'w', newline='', encoding='utf-8') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(["URL", "404 Count"])
            for url, count in self.status_404_counts.items():
                writer.writerow([url, count])
    def extract_blacklisted_domains(self):
        if not os.path.exists(self.blacklist_file):
            raise FileNotFoundError(f"Blacklist file not found: {self.blacklist_file}")
        with open(self.blacklist_file, 'r', encoding='utf-8') as html_file:
            for line in html_file:
                domains = re.findall(r'<li>(.*?)</li>', line)
                self.blacklisted_domains.update(domains)
    def compare_with_blacklist(self):
        for url, status in self.urls_and_statuses:
            domain = re.search(r'://(.*?)/', url)
            if domain and domain.group(1) in self.blacklisted_domains:
                self.matched_url_details.append({
                    "url": url,
                    "status": status,
                    "count": self.status_404_counts.get(url, 0)
                })
    def create_alert_json(self, file_path):
        with open(file_path, 'w', encoding='utf-8') as json_file:
            json.dump(self.matched_url_details, json_file, indent=4, ensure_ascii=False)
    def create_summary_report(self, file_path):
        summary = {
            "total_url_count": len(self.urls_and_statuses),
            "total_404_count": len(self.status_404_counts),
            "blacklist_matches": len(self.matched_url_details)
        }
        with open(file_path, 'w', encoding='utf-8') as json_file:
            json.dump(summary, json_file, indent=4, ensure_ascii=False)
# File paths
log_file = "access_log.txt"
blacklist_file = "threat_feed.html"
url_status_report = "url_status_report.txt"
status_404_csv = "malware_candidates.csv"
alert_json = "alert.json"
summary_json = "summary_report.json"
# Analysis operations
analysis = RegexSystemLogAnalysis(log_file, blacklist_file)
analysis.extract_urls_and_statuses()
analysis.create_url_status_report(url_status_report)
analysis.create_404_status_csv(status_404_csv)
analysis.extract_blacklisted_domains()
analysis.compare_with_blacklist()
analysis.create_alert_json(alert_json)
analysis.create_summary_report(summary_json)
