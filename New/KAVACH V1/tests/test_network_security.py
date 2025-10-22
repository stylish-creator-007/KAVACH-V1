from src.detection_engines.network_analyzer import NetworkAnalyzer


def test_network_analyzer_returns_alerts_list():
    na = NetworkAnalyzer()
    res = na.analyze()
    assert isinstance(res, dict)
    assert 'alerts' in res
