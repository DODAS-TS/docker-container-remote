# docker-container-remote

Access a docke container using an ssh server

## :rocket: Getting started

Build the executable:

```bash
go build -o server
```

Search with `docker ps` the target container:

```
CONTAINER ID   IMAGE           COMMAND       CREATED          STATUS          PORTS          NAMES
8c339fa9b54c   ubuntu/latest   "something"   29 hours ago     Up 29 hours     8888-8889/tcp  containerA
0c6a105bb567   ubuntu/latest   "something"   32 hours ago     Up 32 hours     8888-8889/tcp  containerB
```

Start the server:

```bash
./server containerB@localhost --server_key /your_server_key
```

By default, the server key is `/etc/ssh/ssh_host_rsa_key`. 
Then, connect to the container using the `ssh` server created to interact with it:

```bash
ssh -p 2232 containerB@localhost
```
