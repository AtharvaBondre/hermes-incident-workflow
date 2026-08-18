import unittest

from app.subject import normalize_subject


class NormalizeSubjectTests(unittest.TestCase):
    def test_normalizes_case_and_repeated_whitespace(self) -> None:
        self.assertEqual(normalize_subject("  Payment   FAILED  "), "payment failed")

    def test_preserves_empty_subject(self) -> None:
        self.assertEqual(normalize_subject("   "), "")


if __name__ == "__main__":
    unittest.main()
