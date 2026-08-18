import socket
import unittest
import urllib.request


class DisposableServicesTests(unittest.TestCase):
    def test_postgres_accepts_connections(self) -> None:
        with socket.create_connection(("postgres", 5432), timeout=3):
            pass

    def test_kafka_accepts_connections(self) -> None:
        with socket.create_connection(("kafka", 9092), timeout=3):
            pass

    def test_opensearch_is_healthy(self) -> None:
        with urllib.request.urlopen("http://opensearch:9200/_cluster/health", timeout=5) as response:
            self.assertEqual(response.status, 200)

    def test_candidate(self) -> None:
        from tests.test_subject import NormalizeSubjectTests

        suite = unittest.defaultTestLoader.loadTestsFromTestCase(NormalizeSubjectTests)
        result = unittest.TestResult()
        suite.run(result)
        self.assertTrue(result.wasSuccessful(), result.failures + result.errors)


if __name__ == "__main__":
    unittest.main(verbosity=2)
