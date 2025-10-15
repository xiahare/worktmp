# FCP Dev Environment

## 0 Prerequisities

See step 1-6 in https://gitlab-van.corp.fortinet.com/fortisoar/xf/infrastructure/-/tree/development/dev-setup/docker-compose?ref_type=heads

## 1 Modifications

Ref: https://gitlab-van.corp.fortinet.com/fortisoar/xf/infrastructure/-/tree/development/dev-setup/docker-compose?ref_type=heads

1 Updated the Auth endpoint in [config.ini](https://gitlab-van.corp.fortinet.com/fortisoar/xf/auth/-/blob/development/configs/default/config.ini?ref_type=heads)

`https://xf.test.fortisoar.forticloud.com` -> `https://xf.dev3.fortisoar.forticloud.com`

2 Images in the docker-compose-app-remote.yaml is composed from [docker-compose-app.yaml](https://gitlab-van.corp.fortinet.com/fortisoar/xf/infrastructure/-/blob/development/dev-setup/docker-compose/app/docker-compose-app.yaml?ref_type=heads) but using the built 25.2.b GA images on corporate jFrog repo

## 2 Prerequisites

1 Pull the Source

```shell
git clone git@git-van.corp.fortinet.com:fortisoar/xf/infrastructure.git
cd infrastructure/dev-setup/docker-compose/app/

# Open git.sh and set VERSION=25.2.b, or from Mac
sed -i '' 's#VERSION=development#VERSION=release/25.2.b#' git.sh

# pull apps
sh git.sh

# rsync to your remote server if needed
--> rsync -avz --progress ./soar/ lei@172.24.172.110:/home/lei/soar
ssh-copy-id root@<your-remote-vm-ip>
--> ssh-copy-id lei@172.24.172.110
update rsync-platform.sh with your remove VM IP.
sh rsync-platform.sh
```

**Make sure ALL the repos in git.sh** are cloned to app/

2 If working with *Docker Desktop*, add the workdir path (absolute path to infrastructure/dev-setup/docker-compose/app) to Docker Desktop > Preferences > Resources > File sharing

## 3 To Launch

Option 1: Launch from built docker images from jFrog

```shell
cd infrastructure/dev-setup/docker-compose/app/
# put docker-compose-app-remote.yaml under app/
cp docker-compose-app-remote.yaml .
docker network create xf_default
docker-compose --project-name xf -f docker-compose-app-remote.yaml up --detach
--> cp -r ../../../../audit .
--> docker compose --project-name xf -f docker-compose-app-remote.yaml up --detach

```

Option 2: Build and run from the source

```shell
cd infrastructure/dev-setup/docker-compose/app/
docker network create xf_default
docker-compose --project-name xf -f docker-compose-app.yaml build ingress rabbitmq db redis 
--> docker compose --project-name xf -f docker-compose-app.yaml build ingress rabbitmq db redis 
docker-compose --project-name xf -f docker-compose-app.yaml up --detach
--> docker compose --project-name xf -f docker-compose-app.yaml up --detach
```

## 4 Set up Auth

1 wait for the containers to be up and execute to install dev license

`docker exec app-auth-1 python license/samples/install-dev-license.py`
--> `docker exec xf-auth-1 python license/samples/install-dev-license.py`
--> python license/samples/install-dev-license.py
--> ../../../../auth/configs/default/config.ini --> [portal] host = https://xf.dev3.fortisoar.forticloud.com

2 Open Postman and import `Provision.postman_environment.json` and `Provision.postman_collection.json`.  "Set active" the `Provision` Environment and make the following calls in sequence:

a. "get portal for tenant"
--> modify `test` to `dev3` in url address:
    --> 
    				"raw": "https://xf.dev3.fortisoar.forticloud.com/api/cplane/v1/tenants/dev-get-tenant-deployment-access-url/",
					...
					"host": [
						"xf",
						"dev3",
						"fortisoar",
						"forticloud",
						"com"
					],
b. "login"

c. provision the resources such as workflow, integration, etc.

--> workflow-provision api need to remove the 3rd param of "faz"

## 5 To Access

https://localhost/api/auth/docs/

https://localhost/api/workflow/docs/

https://localhost/api/tip/docs/

And `Authorize` with the `access` token received from the login call: `Bearer ${access_token}`


## ---
### test script

pip3 install requests
python3 provision_test.py

### Build xf-ui,
cd ../../../../xf-ui
./build.sh

### Install node and angular
brew install node
npm install -g @angular/cli

### Access to ui
get portal api first and then use response as token (NOT login API )

https://localhost/login?token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzU1MjgxMDA2LCJpYXQiOjE3NTUxOTQ2MDYsImp0aSI6ImM3ZThmOWRlZTZiZDQ3ZTE4NjhhYjdkZTZhMGJmY2NjIiwidGVuYW50aWQiOiIxMDkwNTI5X2RlcGxveV8xIiwidGVuYW50dXVpZCI6IjQ2NTVlNzM3LTk5MzgtNDQ3My04ZWM3LTI2NTVkYzhjNzBkYSIsIm9uZV90aW1lX2FjY2Vzc190b2tlbiI6dHJ1ZSwiZGVwbG95bWVudF90eXBlIjoicHJvZCIsImRlcGxveW1lbnRfaWQiOjEsInVzZXJuYW1lIjoiWEZhYnJpYyIsImVtYWlsIjoieGZhYnJpY0Bmb3J0aW5ldC5jb20iLCJyb2xlIjoiQWRtaW4iLCJob3N0aW5ndXVpZCI6IjQ3YTMyYjUwLWZjMmUtNDQ2Yi04MDllLTVjMjA4ZTBkNWFlNyJ9.0W4wMvrn2H34_r3O4WXxuSD67uXPkeXvTIJxObv_gw5KuIKjH3EIO0fjGsiK8LXDb3-ieSq79UWyBKkkN1PYvdRZQgRdaDiJcpF71RM4RypTrpL7kKlC8a5mvWf3B0SetoCWMzJEsLD6NaEbE-t2o8OME3RO4vgprVoMqncCJVQKAZy8sVFXB9WfpylPhalq8lvuYIK6Raiq3FyYlKaWar8pwg6Z7jq6V2l9N0wTfUiMm3R9Dz56S1Hl5ZN4dIoLy6FvyUsuHZBTi5Bl51G7aNjZXpUMMHp7H_yYbDCfnfmVfOfe3BQoQdAmsVDSSvU2ma4NpQ4s5GQsJQJK1lmJpg


### connector bugs
--> modify infrastructure/dev-setup/docker-compose/app/docker-compose-app.yaml
--> comment 2 occurances of the following
      - ../../../../integration/integration:/opt/integration
      - ../../../../integration/integration/connector_files:/opt/integration/connector_files/