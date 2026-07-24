import unittest
from unittest.mock import Mock, patch

import llm_config
import main


class LlmConfigTests(unittest.TestCase):
    def test_nvidia_nim_preset_uses_official_cloud_endpoint(self):
        config = llm_config.normalize_llm_config({
            "provider": "nvidia_nim",
            "api_base": "",
            "model": "meta/llama-3.3-70b-instruct",
        })
        self.assertEqual(config["api_base"], "https://integrate.api.nvidia.com/v1")
        self.assertEqual(config["provider"], "nvidia_nim")

    def test_full_chat_url_is_normalized_to_base_url(self):
        config = llm_config.normalize_llm_config({
            "provider": "openai_compatible",
            "api_base": "https://example.test/v1/chat/completions",
        })
        self.assertEqual(config["api_base"], "https://example.test/v1")

    def test_public_config_never_exposes_provider_secrets(self):
        public = llm_config.public_llm_config({
            "provider": "openai_compatible",
            "api_base": "https://example.test/v1",
            "api_key": "secret-token",
            "extra_headers": {"X-Secret": "hidden"},
        })
        self.assertEqual(public["api_key"], "")
        self.assertTrue(public["api_key_configured"])
        self.assertEqual(public["extra_headers"], {})
        self.assertEqual(public["extra_header_names"], ["X-Secret"])

    @patch("llm_config.requests.get")
    def test_model_discovery_uses_configured_auth_header(self, request_get):
        response = Mock()
        response.json.return_value = {"data": [{"id": "model-b"}, {"id": "model-a"}]}
        response.raise_for_status.return_value = None
        request_get.return_value = response

        models = llm_config.list_available_models({
            "provider": "nvidia_nim",
            "api_base": "https://integrate.api.nvidia.com/v1",
            "api_key": "nvapi-test",
        })

        self.assertEqual(models, ["model-a", "model-b"])
        _, kwargs = request_get.call_args
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer nvapi-test")

    @patch("llm_config.requests.post")
    def test_openai_compatible_chat_supports_custom_headers_and_body(self, request_post):
        response = Mock()
        response.json.return_value = {"choices": [{"message": {"content": "OK"}}]}
        response.raise_for_status.return_value = None
        request_post.return_value = response

        result = llm_config.run_llm_chat(
            [{"role": "user", "content": "ping"}],
            {
                "provider": "openai_compatible",
                "api_base": "https://example.test/v1",
                "api_key": "custom-key",
                "api_key_header": "api-key",
                "api_key_prefix": "",
                "model": "security-model",
                "extra_body": {"seed": 7},
            },
        )

        self.assertEqual(result, "OK")
        _, kwargs = request_post.call_args
        self.assertEqual(kwargs["headers"]["api-key"], "custom-key")
        self.assertEqual(kwargs["json"]["seed"], 7)
        self.assertEqual(kwargs["json"]["model"], "security-model")

    @patch("llm_config.run_llm_chat", return_value="OK")
    @patch("llm_config.list_available_models", side_effect=RuntimeError("catalog disabled"))
    def test_probe_can_validate_inference_without_model_catalog(self, _models, _chat):
        result = llm_config.probe_llm_connection({
            "provider": "openai_compatible",
            "api_base": "https://example.test/v1",
            "model": "manual-model",
        })
        self.assertTrue(result["inference_ok"])
        self.assertEqual(result["models_count"], 0)
        self.assertIn("catalog disabled", result["models_error"])

    @patch("main.load_llm_config")
    def test_browser_request_preserves_secret_only_for_same_endpoint(self, load_config):
        load_config.return_value = llm_config.normalize_llm_config({
            "provider": "nvidia_nim",
            "api_base": "https://integrate.api.nvidia.com/v1",
            "api_key": "saved-secret",
            "model": "model-a",
        })
        same_endpoint = main.LLMConfigRequest(
            provider="nvidia_nim",
            api_base="https://integrate.api.nvidia.com/v1",
            api_key="",
            model="model-b",
        )
        changed_endpoint = main.LLMConfigRequest(
            provider="openai_compatible",
            api_base="https://other.example/v1",
            api_key="",
            model="model-b",
        )

        self.assertEqual(main._effective_llm_config(same_endpoint)["api_key"], "saved-secret")
        self.assertEqual(main._effective_llm_config(changed_endpoint)["api_key"], "")


if __name__ == "__main__":
    unittest.main()
