import time
import csv
import requests
import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError

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

def list_s3_buckets(access_key, secret_key):
    """List S3 buckets using the provided AWS credentials."""
    try:
        # Initialize a session using the retrieved credentials
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name='us-east-1'  # Change as needed
        )
        # Create an S3 client
        s3_client = session.client('s3')

        # Perform an operation to validate credentials
        response = s3_client.list_buckets()
        bucket_names = [bucket['Name'] for bucket in response['Buckets']]
        return True, bucket_names
    except (NoCredentialsError, PartialCredentialsError) as e:
        print(f"Invalid AWS credentials: {e}")
        return False, []
    except ClientError as e:
        print(f"Client error during AWS operation: {e}")
        return False, []
    except Exception as e:
        print(f"Error listing S3 buckets: {e}")
        return False, []

def list_secret_engines(vault_url, vault_token):
    """List all AWS secret engines in Vault."""
    headers = {
        'X-Vault-Token': vault_token
    }
    url = f'{vault_url}/v1/sys/mounts'
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        engines = response.json()
        aws_engines = [mount_path.rstrip('/') for mount_path, details in engines['data'].items() if details['type'] == 'aws']
        return aws_engines
    else:
        print(f"Error listing secret engines: {response.status_code} - {response.text}")
        return []

def validate_secret_engine(vault_url, vault_token, mount_path, role_name):
    """Validate AWS secret engine by generating credentials and listing S3 buckets."""
    print(f"\nValidating AWS Secret Engine: {mount_path}/{role_name}")
    
    # Retrieve AWS credentials from Vault
    access_key, secret_key = generate_aws_credentials(vault_url, vault_token, mount_path, role_name)
    
    if access_key and secret_key:
        print("AWS Access Key:", access_key)
        print("AWS Secret Key:", secret_key)
        
        # Introduce a delay to allow AWS to propagate the new credentials
        time.sleep(10)
        
        # Validate AWS credentials by listing S3 buckets
        is_valid, buckets = list_s3_buckets(access_key, secret_key)
        if is_valid:
            print(f"Credentials for {mount_path}/{role_name} are valid and working.")
            return {'mount_path': mount_path, 'role_name': role_name, 'status': 'Success', 'buckets': ', '.join(buckets)}
        else:
            print(f"Credentials for {mount_path}/{role_name} are not working as expected.")
            return {'mount_path': mount_path, 'role_name': role_name, 'status': 'Failed', 'buckets': ''}
    else:
        print(f"Failed to retrieve AWS credentials for {mount_path}/{role_name}.")
        return {'mount_path': mount_path, 'role_name': role_name, 'status': 'Failed to retrieve credentials', 'buckets': ''}

def main():
    # Define Vault server URL and token
    vault_url = 'http://13.232.30.155:8200'  # Vault server URL
    vault_token = 'hvs.eqvPnbyPz9fSgt5HnwLSmwTb'  # Your Vault token
    
    # Specify the role name to use for all AWS secret engines
    role_name = 'vault-aws-role'
    
    # List all AWS secret engines
    secret_engines = list_secret_engines(vault_url, vault_token)
    
    # Prepare to store results
    results = []
    
    # Validate all secret engines using the specified role
    for mount_path in secret_engines:
        result = validate_secret_engine(vault_url, vault_token, mount_path, role_name)
        results.append(result)
    
    # Write results to CSV file
    csv_file = 'aws_secret_engine_validation_results.csv'
    with open(csv_file, 'w', newline='') as csvfile:
        fieldnames = ['mount_path', 'role_name', 'status', 'buckets']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            writer.writerow(result)
    
    print(f"Validation results saved to {csv_file}")

if __name__ == "__main__":
    main()
