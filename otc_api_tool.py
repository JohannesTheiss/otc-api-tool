import csv
import json
import os
from dotenv import load_dotenv
from otc_client import OTCClient, AuthMethod

def load_credentials(filepath):
    with open(filepath, mode='r') as file:
        reader = csv.DictReader(file)
        credentials = next(reader)
    return credentials["Access Key Id"], credentials["Secret Access Key"]

if __name__ == "__main__":
    # Load environment variables from a .env file in the current directory.
    # This file should contain sensitive information like project ID, username, and password.
    load_dotenv()  # Automatically loads .env file in the current directory

    client = None  # Initialize the client variable to be set later based on the authentication method
    auth = AuthMethod.AK_SK  # Set the desired authentication method. Change to AuthMethod.PASSWORD if using API Password.

    # If using API Password authentication, create an OTCClient instance with relevant credentials
    if auth == AuthMethod.PASSWORD:
        client = OTCClient(
            project_id=os.getenv("PROJECT_ID"),               # Load the project ID from environment variables
            auth_method=AuthMethod.PASSWORD,                  # Set the authentication method to API Password
            username=os.getenv("OTC_USERNAME"),               # Load the OTC username from environment variables
            password=os.getenv("OTC_PASSWORD"),               # Load the OTC password from environment variables
            user_domain_name=os.getenv("USER_DOMAIN_NAME"),   # Load the user domain name from environment variables
            region="eu-de",                                   # Specify the region (e.g., "eu-de")
            service_type="ecs",                               # Specify the service type (e.g., "ecs" for Elastic Cloud Server)
            version="v2.1"                                    # Specify the API version (e.g., "v2.1")
        )
    else:
        # If using AK/SK (Access Key/Secret Key) authentication, load the credentials from a file
        ak, sk = load_credentials('credentials.csv')  # Load AK and SK from a credentials file
        client = OTCClient(
            project_id=os.getenv("PROJECT_ID"),               # Load the project ID from environment variables
            auth_method=AuthMethod.AK_SK,                     # Set the authentication method to AK/SK
            ak=ak,                                            # Pass in the Access Key loaded from the credentials file
            sk=sk                                             # Pass in the Secret Key loaded from the credentials file
        )

    # Make a GET request to the "servers" resource using the configured OTC client
    # `print_request=True` enables printing of the request details for debugging purposes
    response = client.call("GET", "servers", print_request=True)

    # Print the response in a formatted JSON output, making it easier to read
    print(json.dumps(response, sort_keys=True, indent=4))

    response = client.call("GET", "servers", query={"status":"active"}, print_request=True)
    print(json.dumps(response, sort_keys=True, indent=4))

