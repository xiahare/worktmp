the server is ready in soc-log-transport branch


login with LDAP first
```
docker login dops-jfrog.fortinet-us.com
```
then
```
cd ingestion.server/docker-compose-with-metrics
docker compose --project-name soc-ingestion-server-mock up
```
after that you can check metrics like log rate at http://localhost:3000/ admin/fortinet 
in Dashboards
