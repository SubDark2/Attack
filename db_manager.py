import sqlite3
import json
from datetime import datetime

class DatabaseManager:
    def __init__(self, db_name="scan_history.db"):
        self.db_name = db_name
        self.init_database()
    
    def init_database(self):
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            
            # جدول المسح الرئيسي
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                scan_date TEXT NOT NULL,
                scan_duration REAL,
                total_paths INTEGER,
                total_vulnerabilities INTEGER
            )
            """)
            
            # جدول المسارات المكتشفة
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS discovered_paths (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                url TEXT NOT NULL,
                status_code INTEGER,
                content_type TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (id)
            )
            """)
            
            # جدول تحليل JavaScript
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS js_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                js_url TEXT NOT NULL,
                analysis_data TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (id)
            )
            """)
            
            # جدول نقاط الضعف
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                url TEXT NOT NULL,
                vulnerability_type TEXT,
                description TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (id)
            )
            """)
            
            conn.commit()
    
    def save_scan_results(self, results):
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            
            # حفظ معلومات المسح الرئيسية
            cursor.execute("""
            INSERT INTO scans (target_url, scan_date, scan_duration, total_paths, total_vulnerabilities)
            VALUES (?, ?, ?, ?, ?)
            """, (
                results["metadata"]["target"],
                results["metadata"]["scan_date"],
                results["metadata"]["scan_duration"],
                len(results["paths"]),
                len(results["vulnerabilities"])
            ))
            
            scan_id = cursor.lastrowid
            
            # حفظ المسارات المكتشفة
            for path in results["paths"]:
                cursor.execute("""
                INSERT INTO discovered_paths (scan_id, url, status_code, content_type)
                VALUES (?, ?, ?, ?)
                """, (
                    scan_id,
                    path["url"],
                    path["status_code"],
                    path["content_type"]
                ))
            
            # حفظ تحليل JavaScript
            for js_url, analysis in results["js_analysis"].items():
                cursor.execute("""
                INSERT INTO js_analysis (scan_id, js_url, analysis_data)
                VALUES (?, ?, ?)
                """, (
                    scan_id,
                    js_url,
                    json.dumps(analysis)
                ))
            
            # حفظ نقاط الضعف
            for vuln in results["vulnerabilities"]:
                cursor.execute("""
                INSERT INTO vulnerabilities (scan_id, url, vulnerability_type, description)
                VALUES (?, ?, ?, ?)
                """, (
                    scan_id,
                    vuln["url"],
                    vuln["type"],
                    vuln["description"]
                ))
            
            conn.commit()
            return scan_id
    
    def get_scan_history(self):
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT id, target_url, scan_date, scan_duration, total_paths, total_vulnerabilities
            FROM scans
            ORDER BY scan_date DESC
            LIMIT 10
            """)
            
            columns = ["id", "target_url", "scan_date", "scan_duration", "total_paths", "total_vulnerabilities"]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]
    
    def get_scan_details(self, scan_id):
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            
            # الحصول على معلومات المسح الأساسية
            cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
            scan_info = cursor.fetchone()
            
            if not scan_info:
                return None
            
            # الحصول على المسارات المكتشفة
            cursor.execute("SELECT * FROM discovered_paths WHERE scan_id = ?", (scan_id,))
            paths = cursor.fetchall()
            
            # الحصول على تحليل JavaScript
            cursor.execute("SELECT * FROM js_analysis WHERE scan_id = ?", (scan_id,))
            js_analysis = cursor.fetchall()
            
            # الحصول على نقاط الضعف
            cursor.execute("SELECT * FROM vulnerabilities WHERE scan_id = ?", (scan_id,))
            vulnerabilities = cursor.fetchall()
            
            return {
                "scan_info": scan_info,
                "paths": paths,
                "js_analysis": js_analysis,
                "vulnerabilities": vulnerabilities
            }