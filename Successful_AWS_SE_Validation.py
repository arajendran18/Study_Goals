import boto3
import json
import base64
import requests
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.session import get_session

def sign_vault_iam_request(vault_url, iam_role):
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
        'role': iam_role,
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

def create_vault_policy(vault_url, vault_token, policy_name, mount_paths):
    """Create a Vault policy dynamically for AWS secret engines."""
    headers = {
        'X-Vault-Token': vault_token
    }

    # Initialize policy content
    policy_content = ''

    # Create paths based on the provided mount paths
    creds_paths = set()
    roles_paths = set()
    for path in mount_paths:
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

    # Add the path for auth/token/lookup-self with read capability
    policy_content += 'path "auth/token/lookup-self" {\n'
    policy_content += '  capabilities = ["read"]\n'
    policy_content += '}\n'

    # Add the path for sys/mounts/aws-dev with read capability
    policy_content += 'path "sys/mounts/aws-dev" {\n'
    policy_content += '  capabilities = ["read"]\n'
    policy_content += '}\n'

    # Add the path for sys/mounts/aws with read capability
    policy_content += 'path "sys/mounts/aws" {\n'
    policy_content += '  capabilities = ["read"]\n'
    policy_content += '}\n'

    # Write the policy to Vault
    policy_data = {
        'policy': policy_content.strip()  # Strip trailing newline
    }
    response = requests.put(f'{vault_url}/v1/sys/policies/acl/{policy_name}', headers=headers, json=policy_data)
    
    if response.status_code != 204:
        raise Exception(f"Error creating Vault policy: {response.text}")

def attach_policy_to_role(vault_url, vault_token, role_name, policy_name, iam_principal_arn):
    """Attach the created policy to the Vault role and specify bound parameters."""
    headers = {
        'X-Vault-Token': vault_token
    }
    
    # Update the role with the new policy, auth_type as IAM, and the bound IAM principal ARN
    role_data = {
        'policies': policy_name,
        'bound_iam_principal_arn': iam_principal_arn,  # Specify the bound IAM principal ARN
        'auth_type': 'iam'  # Explicitly set the auth_type to 'iam'
    }
    
    response = requests.post(f'{vault_url}/v1/auth/aws/role/{role_name}', headers=headers, json=role_data)
    
    if response.status_code != 204:
        raise Exception(f"Error attaching policy to role: {response.text}")

def generate_aws_credentials(vault_url, vault_token, mount_path, role_name):
    """Generate AWS credentials using the Vault AWS secret engine."""
    headers = {
        'X-Vault-Token': vault_token
    }
    response = requests.get(f'{vault_url}/v1/{mount_path}/creds/{role_name}', headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        access_key = data['data']['access_key'].strip()
        secret_key = data['data']['secret_key'].strip()
        return access_key, secret_key
    else:
        raise Exception(f"Error generating AWS credentials: {response.text}")

def lambda_handler(event, context):
    vault_url = 'http://13.232.30.155:8200'  # Replace with your Vault URL
    iam_role = 'my_vault_lambda_role'  # Replace with your Vault IAM role
    iam_principal_arn = 'arn:aws:iam::058264471863:role/LambdaVaultAccessRole'  # Your IAM Role ARN
    role_name = 'my_vault_lambda_role'  # Existing Vault role to attach the policy
    policy_name = 'dynamic_policy'  # Name of the new Vault policy
    aws_secret_role_name = 'vault-aws-role'  # AWS role used to generate credentials

    # Get the secret engines from the event payload
    payload = event.get('secret_engines', [])
    mount_paths = [engine['mount_path'] for engine in payload]

    try:
        # Step 1: Authenticate to Vault using AWS IAM Auth Method
        vault_token = sign_vault_iam_request(vault_url, iam_role)
        print(f"Vault Client Token: {vault_token}")

        # Step 2: Create a Vault policy dynamically based on the mount paths
        create_vault_policy(vault_url, vault_token, policy_name, mount_paths)

        # Step 3: Attach the dynamic policy to the existing Vault role
        attach_policy_to_role(vault_url, vault_token, role_name, policy_name, iam_principal_arn)

        # Step 4: Re-authenticate to Vault after the policy attachment
        vault_token = sign_vault_iam_request(vault_url, iam_role)
        print(f"New Vault Client Token: {vault_token}")

        # Step 5: Generate AWS credentials from each AWS secret engine using the new token
        for mount_path in mount_paths:
            access_key, secret_key = generate_aws_credentials(vault_url, vault_token, mount_path, aws_secret_role_name)

            # Step 6: Validate if AWS credentials are generated
            if access_key and secret_key:
                print(f"Access Key: {access_key}, Secret Key: {secret_key}")
                print(f"Validation successful for mount path: {mount_path}")
            else:
                raise Exception(f"Failed to generate AWS credentials for mount path: {mount_path}")

        return {
            'statusCode': 200,
            'body': json.dumps({'message': 'AWS Secret Engine validation successful.'})
        }
    
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }
