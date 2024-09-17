import boto3
import json
import base64
import requests
import logging
import os
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.session import get_session

# Set up logging
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'ERROR')  # Default to 'ERROR' if LOG_LEVEL is not set
LOGGER = logging.getLogger()
LOGGER.setLevel(getattr(logging, LOG_LEVEL.upper(), logging.ERROR))  # Default to ERROR if an invalid level is provided
LOGGER.info(f"Log level set to {LOG_LEVEL}")

logging.getLogger('boto3').setLevel(logging.CRITICAL)
logging.getLogger('botocore').setLevel(logging.CRITICAL)

def sign_vault_iam_request(vault_url, vault_aws_auth_role):
    """Authenticate to Vault using AWS IAM Authentication."""
    session = get_session()
    credentials = session.get_credentials()
    region = 'us-east-1'  # Update with your AWS region

    # Create the STS request
    request = AWSRequest(
        method='POST',
        url='https://sts.amazonaws.com/',
        data='Action=GetCallerIdentity&Version=2011-06-15',
        headers={'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8'}
    )

    # Sign the request using SigV4
    SigV4Auth(credentials, 'sts', region).add_auth(request)

    signed_headers = dict(request.headers)
    signed_request_body = request.body
    encoded_body = base64.b64encode(signed_request_body).decode('utf-8')

    # Vault login request
    login_data = {
        'role': vault_aws_auth_role,
        'iam_http_request_method': 'POST',
        'iam_request_url': base64.b64encode(b'https://sts.amazonaws.com').decode('utf-8'),
        'iam_request_body': encoded_body,
        'iam_request_headers': base64.b64encode(json.dumps(signed_headers).encode('utf-8')).decode('utf-8')
    }

    response = requests.post(f'{vault_url}/v1/auth/aws/login', json=login_data)

    if response.status_code == 200:
        return response.json()['auth']['client_token']
    else:
        raise Exception(f"Vault Authentication Failed: {response.text}")

def check_mount_path_exists(vault_url, vault_token, mount_path):
    """Check if the specified mount path exists in Vault."""
    headers = {
        'X-Vault-Token': vault_token
    }

    # List all mount paths
    response = requests.get(f'{vault_url}/v1/sys/mounts', headers=headers)

    if response.status_code == 200:
        mounts = response.json()
        # Check if the mount path exists in the available mounts
        if f"{mount_path}/" in mounts:
            return True
        else:
            return False
    else:
        raise Exception(f"Error listing mount paths: {response.text}")

def create_vault_policy(vault_url, vault_token, vault_dynamic_policy, aws_mount_paths):
    """Create a Vault policy dynamically for AWS secret engines."""
    headers = {
        'X-Vault-Token': vault_token
    }

    # Initialize policy content
    policy_content = ''

    # Create paths based on the provided mount paths
    creds_paths = set()
    roles_paths = set()
    for path in aws_mount_paths:
        creds_paths.add(f'{path}/creds/*')
        roles_paths.add(f'{path}/roles/*')

    # Add paths for creds with additional "update" capability
    for path in sorted(creds_paths):
        policy_content += f'path "{path}" {{\n'
        policy_content += '  capabilities = ["read", "list", "update"]\n'
        policy_content += '}\n\n'

    # Add paths for roles
    for path in sorted(roles_paths):
        policy_content += f'path "{path}" {{\n'
        policy_content += '  capabilities = ["read", "list"]\n'
        policy_content += '}\n'

    # Add the path for sys/mounts with read capability
    policy_content += 'path "sys/mounts" {\n'
    policy_content += '  capabilities = ["read"]\n'
    policy_content += '}\n'

    # Write the policy to Vault
    policy_data = {
        'policy': policy_content.strip()  # Strip trailing newline
    }
    response = requests.put(f'{vault_url}/v1/sys/policies/acl/{vault_dynamic_policy}', headers=headers, json=policy_data)

    if response.status_code != 204:
        raise Exception(f"Error creating Vault policy: {response.text}")

def attach_policy_to_role(vault_url, vault_token, vault_aws_auth_role, vault_dynamic_policy):
    """Attach the created policy to the Vault role in addition to existing policies."""
    headers = {
        'X-Vault-Token': vault_token
    }

    # Get the current role configuration
    role_response = requests.get(f'{vault_url}/v1/auth/aws/role/{vault_aws_auth_role}', headers=headers)
    if role_response.status_code != 200:
        raise Exception(f"Error retrieving role configuration: {role_response.text}")

    role_data = role_response.json().get('data', {})
    current_policies = role_data.get('token_policies', [])

    # Ensure the new policy is added without replacing existing ones
    if vault_dynamic_policy not in current_policies:
        current_policies.append(vault_dynamic_policy)

    # Preserve other role configurations (bound_iam_principal_arn, auth_type, etc.)
    updated_role_data = {
        'policies': current_policies
    }

    # Update the role with the new list of policies
    update_response = requests.post(f'{vault_url}/v1/auth/aws/role/{vault_aws_auth_role}', headers=headers, json=updated_role_data)

    if update_response.status_code != 204:
        raise Exception(f"Error updating role with new policies: {update_response.text}")

def generate_aws_credentials(vault_url, vault_token, mount_path, aws_secret_engine_role):
    """Generate AWS credentials using the Vault AWS secret engine."""
    headers = {
        'X-Vault-Token': vault_token
    }

    # Check if the mount path exists
    if check_mount_path_exists(vault_url, vault_token, mount_path):
        # If mount path exists, generate AWS credentials
        response = requests.get(f'{vault_url}/v1/{mount_path}/creds/{aws_secret_engine_role}', headers=headers)

        if response.status_code == 200:
            data = response.json()
            access_key = data['data']['access_key'].strip()
            secret_key = data['data']['secret_key'].strip()
            return access_key, secret_key
        else:
            raise Exception(f"Error generating AWS credentials: {response.text}")
    else:
        # If mount path does not exist, print an error message
        LOGGER.debug(f"This account '{mount_path}' is not available in '{vault_url}' AWS secret engine")
        return None, None

def lambda_handler(event, context):
    # Please use the respective vault URL and vault IAM role
    # NON-PROD URL and vault IAM role
    vault_url = 'https://npd-esms.lllint.com'
    vault_aws_auth_role = 'esms-npd-lambda-aws-secret-validation'

    # PROD URL and vault IAM role
    # vault_url = 'https://prd-esms.lllint.com'
    # vault_aws_auth_role = 'esms-prd-lambda-aws-secret-validation'

    # Read JSON payload input to fetch the secret engines
    aws_mount_paths = event["Input"]["SecretEngines"]

    # Default role is used for generating access credentials
    aws_secret_engine_role = 'readonly'

    # Dynamic policy generated on each run
    vault_dynamic_policy = 'aws_secret_validation_dynamic_policy'

    try:
        # Authenticate to Vault using AWS IAM Auth Method
        vault_token = sign_vault_iam_request(vault_url, vault_aws_auth_role)
        print(f"Vault Client Token is successfully generated")

        # Create a Vault policy dynamically based on the mount paths
        create_vault_policy(vault_url, vault_token, vault_dynamic_policy, aws_mount_paths)

        # Attach the dynamic policy in addition to existing policies to the existing Vault role
        attach_policy_to_role(vault_url, vault_token, vault_aws_auth_role, vault_dynamic_policy)

        # Re-authenticate to Vault after the policy attachment
        vault_token = sign_vault_iam_request(vault_url, vault_aws_auth_role)
        print(f"Updated Vault Client Token is successfully generated")

        # Generate AWS credentials from each AWS secret engine using the new token
        for mount_path in aws_mount_paths:
            access_key, secret_key = generate_aws_credentials(vault_url, vault_token, mount_path, aws_secret_engine_role)

            # Validate if AWS credentials are generated
            if access_key and secret_key:
                print(f"Access Key and Secret key successfully generated")
                LOGGER.debug(f"Validation successful for mount path: {mount_path}")
            else:
                LOGGER.debug(f"Failed to generate AWS credentials for mount path: {mount_path}")

        # Delete the dynamic policy after the test
        delete_response = requests.delete(f'{vault_url}/v1/sys/policies/acl/{vault_dynamic_policy}', headers={'X-Vault-Token': vault_token})
        if delete_response.status_code == 204:
            print("The temporary provisioned policy to perform this testing has been deleted.")
        else:
            LOGGER
