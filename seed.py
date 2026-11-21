import sys
sys.path.insert(0, '.')
from parse.parser import parse_line, SlidingWindowDetector
from vault.db import get_connection, insert_event, insert_alert

conn = get_connection()
detector = SlidingWindowDetector()

with open('data/sample.log') as f:
    for line in f:
        event = parse_line(line, source='server1')
        insert_event(conn, event['timestamp'], event['severity'], event['category'], event['source'], event['message'])
        if event['severity'] in ('ERROR', 'FATAL') and detector.record(event['category']):
            insert_alert(conn, event['timestamp'], event['category'], detector.threshold,
                         f"Spike detected in category '{event['category']}'")
