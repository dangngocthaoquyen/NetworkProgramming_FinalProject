from app.normalizers.enum_normalizer import normalize_enum_payload


def test_ports_with_urls_are_normalized_into_host_web_inventory():
    payload = {
        "scan_id": "normalize-web",
        "target": "authorized-lab",
        "hosts": [
            {
                "ip": "192.168.1.10",
                "ports": [
                    {
                        "port": 80,
                        "service": "http",
                        "product": "Apache httpd",
                        "version": "2.4.7",
                        "url": "http://192.168.1.10/",
                        "discovered_paths": ["/admin"],
                        "technologies": ["Apache httpd"],
                    }
                ],
            }
        ],
    }

    normalized = normalize_enum_payload(payload)

    web = normalized["hosts"][0]["web"]
    assert len(web) == 1
    assert web[0]["url"] == "http://192.168.1.10/"
    assert web[0]["interesting_paths"] == ["/admin"]
    assert web[0]["technologies"] == ["Apache httpd"]


def test_web_like_ports_without_url_get_derived_url():
    payload = {
        "scan_id": "normalize-ipp",
        "target": "authorized-lab",
        "hosts": [
            {
                "ip": "172.28.128.3",
                "ports": [
                    {
                        "port": 631,
                        "service": "ipp",
                        "product": "CUPS",
                    }
                ],
            }
        ],
    }

    normalized = normalize_enum_payload(payload)

    assert normalized["hosts"][0]["ports"][0]["url"] == "http://172.28.128.3:631/"
    assert normalized["hosts"][0]["web"][0]["url"] == "http://172.28.128.3:631/"
