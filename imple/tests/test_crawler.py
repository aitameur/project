from crawler import Crawler


def test_crawler_discovers_pages_and_endpoints(vulnerable_app):
    crawler = Crawler(base_url=vulnerable_app, max_depth=2, max_pages=20, timeout=5)
    endpoints = crawler.crawl()

    # Au moins la page d'accueil doit avoir été visitée
    assert len(crawler.visited) >= 1

    # Les endpoints avec paramètres GET doivent être découverts
    urls = {ep.url for ep in endpoints}
    assert any("/search" in u for u in urls)
    assert any("/greet" in u for u in urls)
    assert any("/user" in u for u in urls)


def test_crawler_respects_domain(vulnerable_app):
    crawler = Crawler(base_url=vulnerable_app, max_depth=1, timeout=5)
    crawler.crawl()
    for url in crawler.visited:
        assert "127.0.0.1" in url
