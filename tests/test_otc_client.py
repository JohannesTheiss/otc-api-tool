import unittest
import json
from unittest.mock import patch, MagicMock
from otc_client import OTCClient, AuthMethod

class TestOTCClient(unittest.TestCase):

    @patch("otc_client.requests.post")
    def test_password_authentication(self, mock_post):
        # Mock a successful authentication response
        mock_post.return_value.status_code = 201
        mock_post.return_value.headers = {"X-Subject-Token": "mock_token"}
        
        # Initialize client with API Password method
        client = OTCClient(
            project_id="test_project_id",
            auth_method=AuthMethod.PASSWORD,
            username="test_user",
            password="test_password",
            user_domain_name="test_domain",
            region="eu-de",
            service_type="ecs"
        )
        
        client._authenticate()  # Call private auth method

        # Verify token was set and mock request was called
        self.assertEqual(client.session_token, "mock_token")
        mock_post.assert_called_once()

    def test_validate_auth_config_ak_sk(self):
        # Should pass with valid AK/SK configuration
        client = OTCClient(
            project_id="test_project_id",
            auth_method=AuthMethod.AK_SK,
            ak="test_ak",
            sk="test_sk"
        )
        client._validate_auth_config()  # Should not raise any exceptions

    def test_validate_auth_config_password(self):
        # Should pass with valid password configuration
        client = OTCClient(
            project_id="test_project_id",
            auth_method=AuthMethod.PASSWORD,
            username="test_user",
            password="test_password",
            user_domain_name="test_domain"
        )
        client._validate_auth_config()  # Should not raise any exceptions

    def test_validate_auth_config_missing_ak_sk(self):
        # Should raise ValueError due to missing AK/SK
        with self.assertRaises(ValueError):
            OTCClient(project_id="test_project_id", auth_method=AuthMethod.AK_SK)

    def test_validate_auth_config_missing_password(self):
        # Should raise ValueError due to missing password credentials
        with self.assertRaises(ValueError):
            OTCClient(project_id="test_project_id", auth_method=AuthMethod.PASSWORD)

    def test_construct_endpoint(self):
        # Tests that endpoint is correctly constructed based on version and project_id
        client = OTCClient(
            project_id="test_project_id",
            auth_method=AuthMethod.AK_SK,
            ak="test_ak",
            sk="test_sk",
            version="v2.1"
        )
        endpoint = client.construct_endpoint("servers")
        self.assertEqual(endpoint, "/v2.1/test_project_id/servers")

    @patch("otc_client.requests.get")
    def test_call_get_request(self, mock_get):
        # Mock a successful GET response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": "example_data"}
        mock_get.return_value = mock_response

        client = OTCClient(
            project_id="test_project_id",
            auth_method=AuthMethod.AK_SK,
            ak="test_ak",
            sk="test_sk",
            region="eu-de",
            service_type="ecs"
        )
        
        response = client.call("GET", "servers", query={"status": "active"})
        self.assertEqual(response, {"data": "example_data"})
        mock_get.assert_called_once()

    @patch("otc_client.requests.post")
    def test_call_post_request(self, mock_post):
        # Mock a successful POST response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": "post_example"}
        mock_post.return_value = mock_response

        client = OTCClient(
            project_id="test_project_id",
            auth_method=AuthMethod.AK_SK,
            ak="test_ak",
            sk="test_sk",
            region="eu-de",
            service_type="ecs"
        )

        response = client.call("POST", "servers", payload=json.dumps({"name": "test_server"}))
        self.assertEqual(response, {"data": "post_example"})
        mock_post.assert_called_once()

    @patch("otc_client.requests.get")
    def test_call_error_handling(self, mock_get):
        # Mock an error response from the API
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.text = "Not Found"
        mock_get.return_value = mock_response

        client = OTCClient(
            project_id="test_project_id",
            auth_method=AuthMethod.AK_SK,
            ak="test_ak",
            sk="test_sk",
            region="eu-de",
            service_type="ecs"
        )

        with self.assertRaises(Exception) as context:
            client.call("GET", "nonexistent_resource")

        self.assertIn("Error: 404", str(context.exception))
        self.assertIn("Not Found", str(context.exception))


if __name__ == "__main__":
    unittest.main()
