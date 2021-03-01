# docker-container-remote

Access a docke container using an ssh server.

```
                     +-------------------------+
+----------+         |                         |         +-------------+
|          |         |         service         |         |             |
|   SSH    +---------+ docker-container-remote +---------+ Container X |
|          |         |                         |         |             |
+-----+----+         +-------------------------+         +------+------+
      |                                                         ^
      |                                                         |
      +---------------------------------------------------------+
```

## :rocket: Getting started

First of all, create an ssh key for the server:

```bash
ssh-keygen -t rsa -C "test@remote.org" -f ./id_rsa
```

### Use case - Container with a ready bash command and a TTY

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
./server containerB@localhost --server_key ./id_rsa
```

By default, the server key is `/etc/ssh/ssh_host_rsa_key` and it will use the port `2232`. 
Then, connect to the container using the `ssh` server created to interact with it:

```bash
ssh -p 2232 containerB@localhost
```

### Use case - Container with no bash command or a TTY started

In the following example, we will create an shell ssh connection in a container without a TTY and a shell already running. First, start a container with a service, e.g. `nginx`:

```bash
docker run --rm -e IAM_CLIENT_ID=testiamclientid -e USERNAME=tester -d --name test_docker_ssh nginx
```

Now, run the container ssh service with the specific target image:

```bash
go run main.go -i id_rsa -d nginx -l localhost
```

Then, you can connect through ssh to the container:

```bash
ssh tester.test_docker_ssh@localhost -p 2232
```

### :books: References

* [docker-sshd](https://github.com/tg123/docker-sshd)
* [interactive-container](https://stackoverflow.com/questions/58732588/accept-user-input-os-stdin-to-container-using-golang-docker-sdk-interactive-co)

Con la nuova API non è possibile agganciarsi direttamente al nuovo exec creato, andrebbe implementato direttamente con la chiamata HTTP
