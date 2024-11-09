import unittest
from request_builder import (
    Request,
    sha256_hash,
    sign_request,
    build_canonical_headers,
    build_canonical_request,
    get_sorted_header_names,
    validate_http_method,
    format_query_string,
    build_and_sign_request
)

class TestRequestBuilder(unittest.TestCase):

    def test_request_initialization(self):
        # Test initializing a Request object with headers and query
        request = Request(
            base_url="https://ecs.eu-de.otc.t-systems.com",
            http_method="GET",
            endpoint="/v2.1/test_project_id/servers",
            query={"status": "active"},
            headers={"Custom-Header": "TestValue"},
            payload=""
        )

        self.assertEqual(request.url, "https://ecs.eu-de.otc.t-systems.com/v2.1/test_project_id/servers")
        self.assertIn("Host", request.headers)
        self.assertIn("X-Sdk-Date", request.headers)
        self.assertEqual(request.headers["Custom-Header"], "TestValue")

    def test_build_canonical_headers(self):
        # Test canonical headers formatting
        headers = {
            "Content-Type": "application/json",
            "X-Sdk-Date": "20230101T123456Z",
            "Host": "ecs.eu-de.otc.t-systems.com"
        }
        expected_canonical_headers = "content-type:application/json\nhost:ecs.eu-de.otc.t-systems.com\nx-sdk-date:20230101T123456Z\n"
        self.assertEqual(build_canonical_headers(headers), expected_canonical_headers)

    def test_get_sorted_header_names(self):
        # Test sorted header names generation
        headers = {
            "X-Sdk-Date": "20230101T123456Z",
            "Content-Type": "application/json",
            "Host": "ecs.eu-de.otc.t-systems.com"
        }
        expected_sorted_names = "content-type;host;x-sdk-date"
        self.assertEqual(get_sorted_header_names(headers), expected_sorted_names)

    def test_validate_http_method(self):
        # Test HTTP method validation
        self.assertEqual(validate_http_method("get"), "GET")
        self.assertEqual(validate_http_method("POST"), "POST")
        
        # Check invalid method raises ValueError
        with self.assertRaises(ValueError):
            validate_http_method("invalid_method")

    def test_format_query_string(self):
        # Test query string formatting
        params = {"status": "active", "name": "test server"}
        expected_query_string = "name=test%20server&status=active"
        self.assertEqual(format_query_string(params), expected_query_string)

    def test_build_canonical_request(self):
        # Test building of canonical request (for signature)
        request = Request(
            base_url="https://ecs.eu-de.otc.t-systems.com",
            http_method="GET",
            endpoint="/v2.1/test_project_id/servers",
            query={"status": "active"},
            headers={
                "Host": "ecs.eu-de.otc.t-systems.com",
                "X-Sdk-Date": "20230101T123456Z"
            },
            payload=""
        )
        canonical_request, signed_headers = build_canonical_request(request)
        
        # Expected values based on setup
        expected_signed_headers = "content-type;host;x-sdk-date"
        expected_canonical_request = (
            "GET\n"
            "/v2.1/test_project_id/servers/\n"
            "status=active\n"
            "content-type:application/json\n"
            "host:ecs.eu-de.otc.t-systems.com\n"
            "x-sdk-date:20230101T123456Z\n\n"
            "content-type;host;x-sdk-date\n"
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # SHA256 of empty payload
        )
        
        self.assertEqual(canonical_request, expected_canonical_request)
        self.assertEqual(signed_headers, expected_signed_headers)

    def test_build_and_sign_request(self):
        # Test the full request signing process
        request = Request(
            base_url="https://ecs.eu-de.otc.t-systems.com",
            http_method="GET",
            endpoint="/v2.1/test_project_id/servers",
            query={"status": "active"},
            headers={
                "Content-Type": "application/json",
                "Host": "ecs.eu-de.otc.t-systems.com",
                "X-Sdk-Date": "20230101T123456Z"
            },
            payload=""
        )
        ak = "test_access_key"
        sk = "test_secret_key"
        
        # Sign the request and ensure Authorization header is added
        build_and_sign_request(request, ak, sk)
        self.assertIn("Authorization", request.headers)
        self.assertTrue(request.headers["Authorization"].startswith("SDK-HMAC-SHA256"))

if __name__ == "__main__":
    unittest.main()

