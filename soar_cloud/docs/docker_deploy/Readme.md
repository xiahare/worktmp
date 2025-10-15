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
ssh-copy-id root@<your-remote-vm-ip>
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
```

Option 2: Build and run from the source

```shell
cd infrastructure/dev-setup/docker-compose/app/
docker network create xf_default
docker-compose --project-name xf -f docker-compose-app.yaml build ingress rabbitmq db redis 
docker-compose --project-name xf -f docker-compose-app.yaml up --detach
```

## 4 Set up Auth

1 wait for the containers to be up and execute to install dev license

`docker exec app-auth-1 python license/samples/install-dev-license.py`

2 Open Postman and import `Provision.postman_environment.json` and `Provision.postman_collection.json`.  "Set active" the `Provision` Environment and make the following calls in sequence:

a. "get portal for tenant"

b. "login"

c. provision the resources such as workflow, integration, etc.

## 5 To Access

https://localhost/api/auth/docs/

https://localhost/api/workflow/docs/

https://localhost/api/tip/docs/

And `Authorize` with the `access` token received from the login call: `Bearer ${access_token}`
