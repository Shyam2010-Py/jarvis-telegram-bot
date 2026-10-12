import os
import tempfile
import unittest
from unittest.mock import patch, MagicMock

os.environ.setdefault("TELEGRAM_BOT_TOKEN", "test_token")
os.environ.setdefault("OWNER_TELEGRAM_ID", "12345")
os.environ.setdefault("OLLAMA_BASE_URL", "http://localhost:11434")
import hashlib
_test_salt = bytes.fromhex("00112233445566778899aabbccddeeff")
_test_digest = hashlib.pbkdf2_hmac("sha256", b"test-pass", _test_salt, 260000).hex()
os.environ.setdefault("JARVIS_PASSWORD_HASH", f"pbkdf2_sha256$260000${_test_salt.hex()}${_test_digest}")

import bot

class TestJarvisBot(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        bot.DB_PATH = os.path.join(self.tmp.name, "test.db")
        bot.user_contexts.clear()
        bot.init_db()

    def tearDown(self):
        self.tmp.cleanup()

    def test_password_hash_verify(self):
        self.assertTrue(bot.verify_password("test-pass"))
        self.assertFalse(bot.verify_password("wrong-pass"))

    def test_password_hash_format_validation(self):
        self.assertTrue(bot.verify_password_hash_format(os.environ["JARVIS_PASSWORD_HASH"]))
        self.assertFalse(bot.verify_password_hash_format("plain-text-password"))

    def test_approval_and_authentication_persist(self):
        self.assertTrue(bot.is_approved(12345))
        self.assertFalse(bot.is_approved(99999))
        self.assertFalse(bot.is_authenticated(12345))
        bot.authenticate_user(12345)
        self.assertTrue(bot.is_authenticated(12345))
        bot.logout_user(12345)
        self.assertFalse(bot.is_authenticated(12345))

    def test_failed_password_attempt_cooldown(self):
        for _ in range(bot.AUTH_MAX_ATTEMPTS):
            bot.record_failed_auth(999)
        allowed, remaining = bot.check_auth_attempt(999)
        self.assertFalse(allowed)
        self.assertGreater(remaining, 0)

    @patch("bot.requests.post")
    def test_ollama_failure_is_handled(self, mock_post):
        mock_post.side_effect = TimeoutError("test timeout")
        self.assertIn("trouble connecting", bot.call_ollama(12345, "hello"))

    @patch("bot.requests.post")
    def test_context_isolation_without_network(self, mock_post):
        response = MagicMock()
        response.json.return_value = {"message": {"content": "mock answer"}}
        response.raise_for_status.return_value = None
        mock_post.return_value = response
        bot.call_ollama(1, "User 1")
        bot.call_ollama(2, "User 2")
        self.assertNotEqual(bot.user_contexts[1], bot.user_contexts[2])
        self.assertEqual(mock_post.call_count, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
