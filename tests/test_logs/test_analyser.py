"""
Tests for the Log Analyser module.
Uses realistic sample logs — no external APIs needed.
"""
import pytest
from sentinelai.modules.logs.analyser import LogAnalyser


@pytest.fixture
def analyser():
    return LogAnalyser()


@pytest.fixture
def apache_log_sample():
    return """192.168.1.100 - - [22/Jun/2026:14:32:01 +0000] "GET / HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
10.0.0.5 - - [22/Jun/2026:14:32:15 +0000] "GET /index.php?id=1 UNION SELECT * FROM users-- HTTP/1.1" 500 892 "-" "sqlmap/1.7"
10.0.0.5 - - [22/Jun/2026:14:32:16 +0000] "GET /../../../etc/passwd HTTP/1.1" 403 512 "-" "Nikto/2.1.6"
203.0.113.42 - - [22/Jun/2026:14:33:00 +0000] "POST /wp-login.php HTTP/1.1" 401 892 "-" "python-requests/2.28"
203.0.113.42 - - [22/Jun/2026:14:33:01 +0000] "POST /wp-login.php HTTP/1.1" 401 892 "-" "python-requests/2.28"
203.0.113.42 - - [22/Jun/2026:14:33:02 +0000] "POST /wp-login.php HTTP/1.1" 401 892 "-" "python-requests/2.28"
192.168.1.1 - - [22/Jun/2026:14:35:00 +0000] "GET /shell.php?cmd=id HTTP/1.1" 200 89 "-" "curl/7.81.0"
"""


@pytest.fixture
def auth_log_sample():
    return """Jun 22 14:30:01 server sshd: Failed password for root from 10.0.0.5 port 22 ssh2
Jun 22 14:30:02 server sshd: Failed password for root from 10.0.0.5 port 22 ssh2
Jun 22 14:30:03 server sshd: Failed password for admin from 10.0.0.5 port 22 ssh2
Jun 22 14:30:04 server sshd: Accepted password for ubuntu from 192.168.1.50 port 22 ssh2
Jun 22 14:31:00 server sudo: ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/bash
"""


class TestLogIngestion:

    def test_ingest_apache_log(self, analyser, apache_log_sample):
        result = analyser.ingest_log_text(apache_log_sample, "apache")
        assert result["log_type"] == "apache"
        assert result["parsed_count"] > 0
        assert result["total_lines"] == 7

    def test_ingest_auth_log(self, analyser, auth_log_sample):
        result = analyser.ingest_log_text(auth_log_sample, "auth")
        assert result["parsed_count"] > 0

    def test_auto_detect_apache(self, analyser, apache_log_sample):
        lines = apache_log_sample.split("\n")[:5]
        log_type = analyser._detect_log_type("access.log", lines)
        assert log_type == "apache"

    def test_auto_detect_auth(self, analyser, auth_log_sample):
        log_type = analyser._detect_log_type("auth.log", [])
        assert log_type == "auth"


class TestAnomalyDetection:

    def test_detects_sql_injection(self, analyser, apache_log_sample):
        log_data  = analyser.ingest_log_text(apache_log_sample, "apache")
        anomalies = analyser.detect_anomalies(log_data)
        types = [a["type"] for a in anomalies["anomalies"]]
        assert "sql_injection" in types

    def test_detects_path_traversal(self, analyser, apache_log_sample):
        log_data  = analyser.ingest_log_text(apache_log_sample, "apache")
        anomalies = analyser.detect_anomalies(log_data)
        types = [a["type"] for a in anomalies["anomalies"]]
        assert "path_traversal" in types

    def test_detects_scanner_ua(self, analyser, apache_log_sample):
        log_data  = analyser.ingest_log_text(apache_log_sample, "apache")
        anomalies = analyser.detect_anomalies(log_data)
        types = [a["type"] for a in anomalies["anomalies"]]
        assert "scanner_ua" in types

    def test_detects_brute_force_in_auth_log(self, analyser, auth_log_sample):
        log_data  = analyser.ingest_log_text(auth_log_sample, "auth")
        anomalies = analyser.detect_anomalies(log_data)
        types = [a["type"] for a in anomalies["anomalies"]]
        assert "brute_force" in types

    def test_returns_suspicious_ips(self, analyser, apache_log_sample):
        log_data  = analyser.ingest_log_text(apache_log_sample, "apache")
        anomalies = analyser.detect_anomalies(log_data)
        assert len(anomalies["suspicious_ips"]) > 0
        assert "10.0.0.5" in anomalies["suspicious_ips"]

    def test_anomaly_has_mitre_mapping(self, analyser, apache_log_sample):
        log_data  = analyser.ingest_log_text(apache_log_sample, "apache")
        anomalies = analyser.detect_anomalies(log_data)
        for anomaly in anomalies["anomalies"]:
            assert "mitre_ttp" in anomaly
            assert anomaly["mitre_ttp"] is not None

    def test_severity_classification(self, analyser):
        assert analyser._pattern_severity("sql_injection") == "high"
        assert analyser._pattern_severity("xss_attempt") == "medium"
        assert analyser._pattern_severity("scanner_ua") == "low"


class TestIOCExtraction:

    def test_extracts_ips(self, analyser, apache_log_sample):
        iocs = analyser.extract_iocs(apache_log_sample)
        assert len(iocs["ips"]) > 0
        assert "10.0.0.5" in iocs["ips"]

    def test_extracts_urls(self, analyser):
        text = 'Connecting to http://malicious.example.com/payload.exe for download'
        iocs = analyser.extract_iocs(text)
        assert len(iocs["urls"]) > 0

    def test_filters_localhost(self, analyser):
        text = "Connection from 127.0.0.1 and 192.168.1.1"
        iocs = analyser.extract_iocs(text)
        # 127.0.0.1 should be filtered (localhost)
        assert "127.0.0.1" not in iocs["ips"]
