import requests
from enum import Enum
from datetime import datetime
from request_builder import Request, build_and_sign_request

class AuthMethod(Enum):
    AK_SK = "AK/SK"
    PASSWORD = "API Password"

class OTCClient:
    """
    A client for interacting with the Open Telekom Cloud (OTC) API, supporting both AK/SK and API Password authentication.
    """

    def __init__(self, project_id, auth_method=AuthMethod.AK_SK, ak=None, sk=None, username=None, password=None, user_domain_name=None, 
                 region="eu-de", service_type="ecs", version="v2.1"):
        """
        Initialize the OTCClient

        Parameters:
            project_id (str): The project ID for API endpoint structure.
            auth_method (AuthMethod): Authentication method (AuthMethod.AK_SK or AuthMethod.PASSWORD).
            ak (str): Access Key for AK/SK authentication.
            sk (str): Secret Key for AK/SK authentication.
            username (str): Username for API Password authentication.
            password (str): Password for API Password authentication.
            user_domain_name (str): The domain name associated with the user (e.g., "OTC-EU-DE-XXXX").
            region (str): The region for the API requests (e.g., "eu-de").
            service_type (str): Service type for the base URL (e.g., "ecs", "iam").
            version (str): Default API version (e.g., "v2.1").
        """
        self.project_id = project_id
        self.auth_method = auth_method
        self.ak = ak
        self.sk = sk
        self.username = username
        self.password = password
        self.user_domain_name = user_domain_name;
        self.region = region
        self.service_type = service_type
        self.version = version
        self.session_token = None

        # Construct the base URL based on the region and service type
        self.base_url = f"https://{self.service_type}.{self.region}.otc.t-systems.com"

        # Validate the authentication configuration
        self._validate_auth_config()

    def _validate_auth_config(self):
        """
        Validates the provided authentication configuration based on the chosen authentication method.
        """
        if self.auth_method == AuthMethod.AK_SK and (not self.ak or not self.sk or not self.project_id):
            raise ValueError("AK and SK are required for AK/SK authentication.")
        elif self.auth_method == AuthMethod.PASSWORD and (not self.username or not self.password 
                                                          or not self.user_domain_name or not self.project_id):
            raise ValueError("Username and password are required for API Password authentication.")
    
    def _authenticate(self):
        """
        Authenticates via API Password and caches the token for future requests.
        """
        if self.auth_method == AuthMethod.PASSWORD and not self.session_token:
            url = f"https://iam.{self.region}.otc.t-systems.com/v3/auth/tokens"
            post_data = {
                "auth": {
                    "identity": {
                        "methods": ["password"],
                        "password": {
                            "user": {
                                "name": self.username,
                                "password": self.password,
                                "domain": {
                                    "name": self.user_domain_name,
                                }
                            }
                        }
                    },
                    "scope": {
                        "project": {
                            "id": self.project_id
                        }
                    }
                }
            }
            headers = {"Content-Type": "application/json"}
            response = requests.post(url, json=post_data, headers=headers)

            if response.status_code == 201:
                self.session_token = response.headers.get("X-Subject-Token")
            else:
                raise Exception("Failed to authenticate: " + response.text)

    def _generate_auth_headers(self, request):
        """
        Generates the appropriate headers for authentication based on the auth method.
        
        Parameters:
            request (Request): The request object to be signed.
        """
        if self.auth_method == AuthMethod.AK_SK:
            build_and_sign_request(request, self.ak, self.sk)  # Use AK/SK signing for authorization
        elif self.auth_method == AuthMethod.PASSWORD:
            self._authenticate()  # Ensure we have a valid session token
            request.headers.update({"X-Auth-Token": self.session_token})

    def construct_endpoint(self, resource):
        """
        Constructs the full endpoint path based on the project ID, version, and resource.

        Parameters:
            resource (str): The resource path (e.g., "servers").

        Returns:
            str: The full endpoint path.
        """
        return f"/{self.version}/{self.project_id}/{resource}"

    def call(self, http_method, resource, query=None, headers=None, payload="", print_request=False):
        """
        Sends a request to the OTC API with the specified parameters.

        Parameters:
            http_method (str): HTTP method (e.g., 'GET', 'POST').
            resource (str): The resource path (e.g., "servers").
            query (dict): Query parameters.
            headers (dict): Additional headers.
            payload (str): Request payload.

        Returns:
            JSON response
        """
        # Construct the full endpoint and URL
        endpoint = self.construct_endpoint(resource)
        url = f"{self.base_url}{endpoint}"

        # Create a Request object
        request = Request(self.base_url, http_method, endpoint, query or {}, headers or {}, payload)

        # Add authentication headers
        self._generate_auth_headers(request)

        if print_request:
            print(request)

        # Determine if payload should be used
        use_payload = http_method.lower() in {"post", "put", "patch"}

        # Prepare request parameters
        request_args = {
            "url": request.url,
            "headers": request.headers,
            "params": query,               # Pass query parameters directly
            "data": payload if use_payload and isinstance(payload, str) else None,
            "json": payload if use_payload and isinstance(payload, dict) else None,
        }

        # Filter out None values in request_args
        request_args = {k: v for k, v in request_args.items() if v is not None}

        # Send the request using the specified HTTP method
        response = getattr(requests, http_method.lower())(**request_args)

        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Error: {response.status_code}, Message: {response.text}")

