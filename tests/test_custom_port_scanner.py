import sys, socket
sys.path.insert(0, ".")
from scanner import parse_ports, COMMON_SERVICES

def test_parse_ports_range():
    ports = parse_ports("1-5")
    assert ports == [1, 2, 3, 4, 5], f"Expected [1..5], got {ports}"

def test_parse_ports_list():
    ports = parse_ports("22,80,443")
    assert 22 in ports and 80 in ports and 443 in ports

def test_parse_ports_mixed():
    ports = parse_ports("22,80-82,443")
    assert ports == [22, 80, 81, 82, 443]

def test_common_services():
    assert COMMON_SERVICES[22] == "SSH"
    assert COMMON_SERVICES[80] == "HTTP"
    assert COMMON_SERVICES[443] == "HTTPS"

def test_no_duplicate_ports():
    ports = parse_ports("80,80,80")
    assert len(ports) == 1

if __name__ == "__main__":
    test_parse_ports_range()
    test_parse_ports_list()
    test_parse_ports_mixed()
    test_common_services()
    test_no_duplicate_ports()
    print("All tests passed.")
