
import requests
import json

# Values from Postman collection for local development
HOST = "localhost"
TENANT_ID = 1090529
TENANT_UUID = "4655e737-9938-4473-8ec7-2655dc8c70da"
DEPLOYMENT_ID = "1"
USERNAME = "XFabric"
EMAIL = "xfabric@fortinet.com"
ROLE = "Admin"
LICENSE_SERIAL = "test"
COMPANY = "Fortinet"
DEPLOYMENT_NAME = "instance1"
URL = f"https://{HOST}"


def get_portal_token():
    """Gets the portal token for the tenant."""
    # This URL appears to be a central service for development environments
    url = "https://xf.dev3.fortisoar.forticloud.com/api/cplane/v1/tenants/dev-get-tenant-deployment-access-url/"
    payload = {
        "tenantid": TENANT_ID,
        "tenantuuid": TENANT_UUID,
        "deploymentid": DEPLOYMENT_ID,
        "username": USERNAME,
        "email": EMAIL,
        "url": f"https://{HOST}:8181",  # The URL for your local deployment
        "role": ROLE,
    }
    headers = {"accept": "application/json", "Content-Type": "application/json"}
    response = requests.post(url, data=json.dumps(payload), headers=headers)
    response.raise_for_status()
    return response.json()["portal_token"]

def login(portal_token):
    """Logs in to the application and returns an auth token."""
    url = f"https://{HOST}/api/auth/login/"
    payload = {"portal_token": portal_token}
    headers = {
        "Authorization": f"Bearer {portal_token}",
        "Content-Type": "application/json",
    }
    response = requests.post(url, data=json.dumps(payload), headers=headers, verify=False)
    response.raise_for_status()
    return response.json()["access"]

def verify_token(auth_token):
    """Verifies the auth token and returns tenant info."""
    url = f"https://{HOST}/api/auth/token/verify/"
    payload = {"token": auth_token}
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json",
    }
    response = requests.post(url, data=json.dumps(payload), headers=headers, verify=False)
    response.raise_for_status()
    return response.json()

def provision_service(auth_token, service, tenant_info):
    """Provisions a service for the tenant."""
    url = f"https://{HOST}/api/{service}/tenants/provision/"
    payload = {
        "type": "prod",
        "regionid": "d6ac05d5-835b-443b-b22c-3764fc7c31ea",
        "license_serial": LICENSE_SERIAL,
        "company": COMPANY,
        "deployment_name": DEPLOYMENT_NAME,
        "hostname": HOST,
        "tenantuuid": tenant_info["tenantuuid"],
        "tenantid": tenant_info["tenantid"],
        "deploymentid": DEPLOYMENT_ID,
        "username": tenant_info["username"],
        "email": tenant_info["username"],
        "url": URL,
        "role": ROLE,
    }
    if service == "appmanager":
        payload["apps"] = []

    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Accept": "application/json",
        "published": "true",
        "Content-Type": "application/json",
    }
    response = requests.post(url, data=json.dumps(payload), headers=headers, verify=False)
    response.raise_for_status()
    print(f"{service} provisioned successfully.")

def main():
    """Main function to run the provisioning tests."""
    portal_token = get_portal_token()
    auth_token = login(portal_token)
    tenant_info = verify_token(auth_token)

    services_to_provision = [
        "workflow",
        "integration",
        "appmanager",
        "audit",
        "store",
        "tip",
    ]

    for service in services_to_provision:
        provision_service(auth_token, service, tenant_info)

if __name__ == "__main__":
    main()
