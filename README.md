# OTC API Tool

A Python tool for interacting with the Open Telekom Cloud (OTC) API, supporting both Access Key/Secret Key (AK/SK) and API Password-based authentication methods. 
This tool allows users to authenticate with OTC services and perform API requests to retrieve data about their resources.

**Note:** This is an unofficial tool developed independently and is not affiliated with, endorsed, or supported by Open Telekom Cloud (OTC) or its parent organizations.

## Features
- Supports AK/SK and API Password authentication.
- Retrieves information about active servers.
- Provides detailed logging of requests and responses.

## Requirements
- Python 3.12.5+
- Packages listed in `requirements.txt`.

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/JohannesTheiss/otc-api-tool.git
   cd otc-api-tool
   ```

2. **Install required packages:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Environment Setup:**
   - Create a `.env` file in the project root:
     ```
     PROJECT_ID=your_project_id
     OTC_USERNAME=your_otc_username
     OTC_PASSWORD=your_otc_password
     USER_DOMAIN_NAME=your_user_domain_name
     ```
   - Create a `credentials.csv` file containing your AK/SK credentials:
     ```csv
     Access Key Id,Secret Access Key
     your_access_key_id,your_secret_access_key
     ```

## Usage

1. **Run the tool**:
   - The tool will use the default authentication method set in `otc_api_tool.py` (`AuthMethod.AK_SK` or `AuthMethod.PASSWORD`).
   ```bash
   python otc_api_tool.py
   ```

2. **Example Output**:
   After running the tool, the output for the list of servers might look like this:
   ```json
   {
       "servers": [
           {
               "id": "server-id-1",
               "name": "Example Server",
           },
           {
               "id": "server-id-2",
               "name": "Another Server",
           },
       ]
   }
   ```

## Configuration
The `auth` variable in `otc_api_tool.py` can be adjusted to switch between `AuthMethod.AK_SK` and `AuthMethod.PASSWORD`:
```python
auth = AuthMethod.AK_SK  # or AuthMethod.PASSWORD
```


