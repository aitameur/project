from crawler import Crawler, Endpoint
from detectors import FileUploadDetector


def test_crawler_detects_file_field(vulnerable_app):
    crawler = Crawler(base_url=vulnerable_app, max_depth=2, timeout=5)
    endpoints = crawler.crawl()
    file_eps = [e for e in endpoints if e.file_fields]
    assert file_eps, "Le crawler doit trouver au moins un endpoint d'upload"
    assert "uploaded" in file_eps[0].file_fields


def test_file_upload_detector_finds_unrestricted_upload(vulnerable_app):
    ep = Endpoint(
        url=f"{vulnerable_app}/upload",
        method="POST",
        form_fields={"MAX_FILE_SIZE": "100000", "Upload": "Upload"},
        file_fields=["uploaded"],
        enctype="multipart/form-data",
    )
    vulns = FileUploadDetector(timeout=5).scan(ep)
    assert any(v.name == "Unrestricted File Upload" for v in vulns)
    v = vulns[0]
    assert v.owasp_id == "A04"
    assert v.parameter == "uploaded"


def test_file_upload_detector_skips_non_upload_endpoints():
    ep = Endpoint(
        url="http://example.com/search",
        method="GET",
        params={"q": "test"},
    )
    vulns = FileUploadDetector(timeout=1).scan(ep)
    assert vulns == []
