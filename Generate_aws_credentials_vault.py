import requests

def generate_aws_credentials(vault_url, vault_token, mount_path, role_name):
    """Generate AWS credentials using direct API call."""
    headers = {
        'X-Vault-Token': vault_token
    }
    url = f'{vault_url}/v1/{mount_path}/creds/{role_name}'
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        return data['data']['access_key'], data['data']['secret_key']
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return None, None

# Example usage
vault_url = 'http://13.232.30.155:8200'
vault_token = 'hvs.eqvPnbyPz9fSgt5HnwLSmwTb'
mount_path = 'aws-dev'
role_name = 'vault-aws-role2'

access_key, secret_key = generate_aws_credentials(vault_url, vault_token, mount_path, role_name)

if access_key and secret_key:
    print("AWS Access Key:", access_key)
    print("AWS Secret Key:", secret_key)
else:
    print("Failed to retrieve AWS credentials.")
