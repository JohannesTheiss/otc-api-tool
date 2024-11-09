from urllib.parse import urlparse, quote
from hashlib import sha256
import hashlib
import hmac
import datetime

class Request:

    def __init__(self, base_url, http_method, endpoint, query={}, headers={}, payload=""):
        """
        Initialize the Request object.
        
        Adds default headers (Host, X-Sdk-Date, Content-type) if they are not provided.

        Parameters:
            base_url (str): The base URL for the request (e.g., "https://ecs.eu-de.otc.t-systems.com").
            http_method (str): The HTTP method (e.g., 'GET', 'POST').
            endpoint (str): The API endpoint path (e.g., '/v1/resource').
            query (dict): The query parameters as a dictionary.
            headers (dict): HTTP headers as a dictionary.
            payload (str): The request payload (body content).
        """
        self.base_url = base_url
        self.http_method = http_method
        self.endpoint = endpoint
        self.query = query
        self.payload = payload
        self.headers = headers or {}
        self.date_time = datetime.datetime.now(datetime.UTC).strftime('%Y%m%dT%H%M%SZ')
        self.url = self.base_url + self.endpoint

        # Add default headers if they are missing
        self.add_default_headers()

    def add_default_headers(self):
        """
        Adds default headers if they are not already present:
            - Host: Extracted from the provided URL.
            - X-Sdk-Date: Current date/time in ISO format.
            - Content-type: Set to "application/json".
        """
        if "Host" not in self.headers:
            self.headers["Host"] = urlparse(self.url).hostname.strip()
        
        if "X-Sdk-Date" not in self.headers:
            self.headers["X-Sdk-Date"] = self.date_time 
        
        if "Content-type" not in self.headers:
            self.headers["Content-type"] = "application/json"

    def add_header(self, name, value):
        """
        Adds or updates a header in the request's headers dictionary.

        Parameters:
            name (str): The header name.
            value (str): The header value.
        """
        self.headers[name] = value

    def __str__(self):
        """
        Defines the string representation of the Request object.
        """
        # ANSI escape code for bold text
        bold_start = "\033[1m"
        bold_end = "\033[0m"
        green_start = "\033[92m"
        green_end = "\033[0m"
        gray_start = "\033[90m"
        gray_end = "\033[0m"

        def display_or_empty(value):
            if value is None or value == "" or (isinstance(value, dict) and not value):
                return f"{gray_start}empty{gray_end}"
            return value

        # Format each component, using "empty" where fields are empty
        query_string = display_or_empty(format_query_string(self.query))
        payload = display_or_empty(self.payload)

        # Format headers with indentation
        headers = "\n".join(f"    {k}: {v}" for k, v in self.headers.items())

        # Create the full string representation of the Request object with bold labels
        return (
             f"{bold_start}{green_start}Request:{green_end}{bold_end}\n"
             f"  {bold_start}Base URL:{bold_end} {self.base_url}\n"
             f"  {bold_start}HTTP Method:{bold_end} {self.http_method.upper()}\n"
             f"  {bold_start}Endpoint:{bold_end} {self.endpoint}\n"
             f"  {bold_start}Query:{bold_end} {query_string}\n"
             f"  {bold_start}Headers:{bold_end}\n{headers}\n"
             f"  {bold_start}Payload:{bold_end} {payload}\n"
             )

def sha256_hash(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def sign_request(secret_key, message):
    """
    Generates an HMAC (Hash-based Message Authentication Code) for the given message and secret key.

    Note:
    - HMAC is not a digital signing algorithm but a Message Authentication Code (MAC). 
      It verifies both data integrity and authenticity but does not provide non-repudiation 
      (a key feature of digital signatures). HMAC is typically used to ensure that a message 
      has not been altered and is from a known sender, as both sender and receiver share the same secret key.

    Parameters:
        secret_key (str): The secret key used to generate the HMAC.
        message (str): The message to authenticate.

    Returns:
        str: The HMAC signature as a hexadecimal string.
    """
    # HMAC with the Secret key
    return hmac.new(secret_key.encode('utf-8'), message.encode('utf-8'), hashlib.sha256).hexdigest()

def build_canonical_headers(headers):
    # Sort the dictionary by key (header name) alphabetically
    sorted_headers = sorted(headers.items())
    formatted_headers = [f"{key.lower()}:{value.strip()}\n" for key, value in sorted_headers]
    return "".join(formatted_headers)

def get_sorted_header_names(headers):
    # Get the header names, convert them to lowercase, and sort them alphabetically
    sorted_header_names = sorted(header.lower() for header in headers.keys())
    # Join the sorted header names with semicolons
    return ";".join(sorted_header_names)

def validate_http_method(http_method):
    # List of standard HTTP methods
    valid_methods = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT"}
    
    # Convert the method to uppercase
    method = http_method.upper()
    
    # Check if the method is in the list of valid methods
    if method in valid_methods:
        return method
    else:
        raise ValueError(f"Invalid HTTP method '{http_method}'. Valid methods are: {', '.join(valid_methods)}")

def format_query_string(params):
    # URI-encode parameter names and values, according to RFC 3986 non-reserved character rules
    def uri_encode(value):
        return quote(value, safe='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~')

    # Encode each parameter and value, using an empty string if value is None
    encoded_params = {}
    for key, value in params.items():
        encoded_key = uri_encode(key)
        encoded_value = uri_encode(value) if value is not None else ''
        encoded_params[encoded_key] = encoded_value

    # Sort parameters by encoded keys in alphabetically ascending order
    sorted_params = sorted(encoded_params.items())

    # Build the query string by joining each "encoded_key=encoded_value" pair
    query_string = "&".join(f"{key}={value}" for key, value in sorted_params)

    return query_string

def build_canonical_request(request, print_request=False):
    """
    Constructs a canonical request string for a given HTTP request, based on OTC signing conventions.
    Parameters:
        request (object): The request object to be converted
        print_request (bool): If True, prints the canonical request for debugging.

    Returns:
        tuple: (canonical_request, signed_headers)
            - canonical_request (str): The canonical request string.
            - signed_headers (str): Semicolon-separated list of headers used in the canonical request.
    """

    # Validate and format the HTTP method in uppercase (e.g., "GET")
    validated_method = validate_http_method(request.http_method)

    # Generate the canonical query string by encoding, sorting, and formatting query parameters
    canonical_query_string = format_query_string(request.query)
    
    # Build canonical headers by sorting and formatting them for signature
    canonical_headers = build_canonical_headers(request.headers)
    
    # Generate a semicolon-separated list of header names, sorted alphabetically
    signed_headers = get_sorted_header_names(request.headers)
    
    # Hash the payload (body content) to include in the canonical request
    hashed_payload = sha256_hash(request.payload)
    
    # Construct the canonical request string using the specified format
    canonical_request = (
        f'{validated_method}\n'             # HTTP method
        f'{request.endpoint}/\n'            # Endpoint path with a trailing slash
        f'{canonical_query_string}\n'       # Canonical query string
        f'{canonical_headers}\n'            # Canonical headers string
        f'{signed_headers}\n'               # Signed headers (names only)
        f'{hashed_payload}'                 # SHA-256 hash of the payload
    )

    # Optionally print the canonical request for debugging purposes
    if print_request:
        print("==== Canonical Request ====")
        print(canonical_request)
        print("==== End Canonical Request ====")

    # Return the canonical request string and the signed headers string
    return canonical_request, signed_headers

def build_and_sign_request(request, ak, sk, print_request=False):
    """
    Builds and signs the canonical request for the given Request object.

    Parameters:
        request (Request): The Request object containing request details.
        ak (str): Access Key for AK/SK authentication.
        sk (str): Secret Key for AK/SK authentication.
        print_request (bool): If True, prints the canonical request and string to sign for debugging.

    Returns:
        None. The function directly updates the request headers with the Authorization header.
    """
    # Build the canonical request and obtain the list of signed headers
    canonical_request, signed_headers = build_canonical_request(request, print_request)
    
    # Hash the canonical request using SHA-256 and convert to lowercase
    hashed_canonical_request = sha256_hash(canonical_request).lower()
    
    # Construct the string to sign
    string_to_sign = (
        "SDK-HMAC-SHA256\n"
        f"{request.date_time}\n"                   # Timestamp for signing
        f"{hashed_canonical_request}"              # Hashed canonical request
    )

    # Optionally print the string to sign for debugging
    if print_request:
        print("==== String to Sign ====")
        print(string_to_sign)
        print("==== End String to Sign ====")

    # Calculate the signature using the secret key (sk)
    signature = sign_request(sk, string_to_sign)

    # Add the Authorization header with the required format
    authorization_header = (
        f"SDK-HMAC-SHA256 Access={ak}, "
        f"SignedHeaders={signed_headers}, "
        f"Signature={signature}"
    )
    request.add_header("Authorization", authorization_header)

