from pathlib import Path
from loghound.parsers import syslog
from loghound.parsers.detector import detect_and_parse

PLAIN = Path(__file__).parent / "fixtures" / "sample_auth.log"
GZIPPED = Path(__file__).parent / "fixtures" / "sample_auth.log.gz"


def test_gzip_same_as_plain():
    plain_events = list(syslog.parse_file(PLAIN))
    gz_events = list(syslog.parse_file(GZIPPED))
    assert len(plain_events) == len(gz_events)
    for p, g in zip(plain_events, gz_events):
        assert p.raw == g.raw
        assert p.timestamp == g.timestamp


def test_detector_handles_gzip():
    parser_name, events = detect_and_parse(GZIPPED)
    events_list = list(events)
    assert len(events_list) > 0
