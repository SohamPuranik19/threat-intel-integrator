import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scripts import bulk_import_iocs as bi


def make_temp_file(lines):
    fd, path = tempfile.mkstemp(text=True)
    with os.fdopen(fd, 'w') as f:
        for l in lines:
            f.write(l + '\n')
    return path


class BulkImportTests(unittest.TestCase):
    def test_bulk_import_with_mocked_api_and_db(self):
        path = make_temp_file(['192.0.2.1', '198.51.100.2'])

        class DummyAPI:
            def __init__(self, **kwargs):
                pass

            def fetch_all_sources(self, indicator):
                return [{'source': 'Mock', 'score': 90.0, 'tags': 'abuse'}]

        inserted = []

        class DummyDB:
            def insert_threat(self, data):
                inserted.append(data)

        # patch environment and classes
        os.environ['ABUSEIPDB_KEY'] = 'x'
        os.environ['VIRUSTOTAL_KEY'] = 'x'
        os.environ['OTX_KEY'] = 'x'

        orig_api = bi.ThreatIntelAPI
        orig_db = bi.ThreatDatabase
        try:
            bi.ThreatIntelAPI = DummyAPI
            bi.ThreatDatabase = lambda: DummyDB()
            orig_argv = sys.argv[:]
            sys.argv = ['bulk_import_iocs.py', '--file', path, '--analyze-ips', '--batch-size', '1', '--batch-delay', '0']
            bi.main()
            self.assertEqual(len(inserted), 2)
        finally:
            bi.ThreatIntelAPI = orig_api
            bi.ThreatDatabase = orig_db
            sys.argv = orig_argv

    def test_heuristic_results_emails(self):
        r1 = bi.heuristic_results('spammy@normal-domain.com', assume_email_phishing=False, default_score=40.0)
        self.assertTrue(r1 and r1[0]['score'] > 40.0)

        r2 = bi.heuristic_results('user@mailinator.com', assume_email_phishing=False, default_score=40.0)
        self.assertTrue(r2 and r2[0]['score'] <= 40.0)


if __name__ == '__main__':
    unittest.main()
