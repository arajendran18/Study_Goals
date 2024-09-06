import requests
import json
import boto3

def authenticate_with_vault_aws():
    """Authenticate with Vault using AWS IAM role."""
    vault_url = 'http://13.232.30.155:8200'  # Hardcoded Vault URL
    iam_role = 'my_vault_lambda_role'  # Hardcoded Vault role
    aws_region = 'us-east-1'  # AWS Region

    sts_client = boto3.client('sts', region_name=aws_region)
    
    # Retrieve temporary credentials for the IAM role
    credentials = sts_client.get_session_token()
    access_key = credentials['Credentials']['AccessKeyId']
    secret_key = credentials['Credentials']['SecretAccessKey']
    session_token = credentials['Credentials']['SessionToken']

    # Create a signed request for authentication
    login_data = {
        'role': iam_role,
        'iam_http_request_method': 'POST',
        'iam_request_url': 'https://sts.amazonaws.com/',
        'iam_request_headers': json.dumps({
            'Authorization': f'AWS4-HMAC-SHA256 Credential={access_key}, SignedHeaders=host;x-amz-date, Signature=<signature>'
        })
    }

    response = requests.post(f'{vault_url}/v1/auth/aws/login', json=login_data)

    if response.status_code == 200:
        return response.json()['auth']['client_token']
    else:
        raise Exception(f"Vault Authentication Failed: {response.text}")

def create_vault_policy(vault_url, vault_token, mount_paths):
    """Create a dynamic Vault policy based on mount paths."""
    policy_name = 'dynamic_policy'
    policy_rules = []
    
    for path in mount_paths:
        policy_rules.append(f"path \"{path}/*\" {{ capabilities = [\"read\", \"list\"] }}")
    
    policy_document = "\n".join(policy_rules)
    
    policy_data = {
        'policy': policy_document
    }
    
    url = f'{vault_url}/v1/sys/policies/acl/{policy_name}'
    headers = {
        'X-Vault-Token': vault_token
    }
    
    response = requests.put(url, headers=headers, json=policy_data)
    
    if response.status_code == 204:
        print(f"Policy {policy_name} created successfully.")
    else:
        raise Exception(f"Failed to create policy: {response.text}")
    
    return policy_name

def attach_policy_to_role(vault_url, vault_token, policy_name, role_name):
    """Attach the policy to the Vault role."""
    url = f'{vault_url}/v1/identity/roles/{role_name}'
    headers = {
        'X-Vault-Token': vault_token
    }
    
    role_data = {
        'policies': policy_name
    }
    
    response = requests.post(url, headers=headers, json=role_data)
    
    if response.status_code == 204:
        print(f"Policy {policy_name} attached to role {role_name}.")
    else:
        raise Exception(f"Failed to attach policy: {response.text}")

def delete_vault_policy(vault_url, vault_token, policy_name):
    """Delete the dynamic Vault policy."""
    url = f'{vault_url}/v1/sys/policies/acl/{policy_name}'
    headers = {
        'X-Vault-Token': vault_token
    }
    
    response = requests.delete(url, headers=headers)
    
    if response.status_code == 204:
        print(f"Policy {policy_name} deleted successfully.")
    else:
        raise Exception(f"Failed to delete policy: {response.text}")

def generate_aws_credentials(vault_url, vault_token, mount_path, role_name):
    """Generate AWS credentials using direct API call."""
    headers = {
        'X-Vault-Token': vault_token
    }
    url = f'{vault_url}/v1/{mount_path}/creds/{role_name}'
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        access_key = data['data']['access_key'].strip()
        secret_key = data['data']['secret_key'].strip()
        return access_key, secret_key
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return None, None

def validate_secret_engine(vault_url, vault_token, mount_path):
    """Validate AWS secret engine by generating credentials."""
    role_name = 'readonly'  # Common role name for validation
    print(f"\nValidating AWS Secret Engine: {mount_path}/{role_name}")
    
    access_key, secret_key = generate_aws_credentials(vault_url, vault_token, mount_path, role_name)
    
    if access_key and secret_key:
        print(f"Credentials for {mount_path}/{role_name} were successfully generated.")
        return {'mount_path': mount_path, 'role_name': role_name, 'status': 'Success'}
    else:
        print(f"Failed to retrieve AWS credentials for {mount_path}/{role_name}.")
        return {'mount_path': mount_path, 'role_name': role_name, 'status': 'Failed'}

def lambda_handler(event, context):
    """Lambda function handler."""
    vault_url = 'http://13.232.30.155:8200'
    vault_token = authenticate_with_vault_aws()
    
    secret_engines = event.get('secret_engines', [])
    
    # Extract mount paths from the secret engines
    mount_paths = [engine['mount_path'] for engine in secret_engines]
    
    # Create a dynamic policy based on the mount paths
    policy_name = create_vault_policy(vault_url, vault_token, mount_paths)
    
    # Attach the newly created policy to the role
    role_name = 'my_vault_lambda_role'
    attach_policy_to_role(vault_url, vault_token, policy_name, role_name)
    
    # Validate all secret engines using the common role 'readonly'
    results = []
    for engine in secret_engines:
        mount_path = engine['mount_path']
        result = validate_secret_engine(vault_url, vault_token, mount_path)
        results.append(result)
    
    # Delete the policy after validation
    delete_vault_policy(vault_url, vault_token, policy_name)
    
    return {
        'statusCode': 200,
        'body': json.dumps(results)
    }
