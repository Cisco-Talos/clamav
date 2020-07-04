# ClamAV in Docker

ClamAV can be run within a Docker container. This provides isolation from other
processes by running it in a containerized environment. If new or unfamiliar
with docker, containers or cgroups see [docker.com](https://www.docker.com).

## Building the ClamAV image

While it is recommended to pull the image from our
[docker hub registry](https://hub.docker.com/u/clamav/clamav), some may want
to build the image locally instead. All that is needed is
```console
docker build --tag "clamav:TICKET-123" .
```
in the current directory. This will build the ClamAV image and tag it with
the name "clamav:TICKET-123". Any name can generally be used and it is this
name that needs to be referred to later when running the image.

## Running clamd

To run `clamd` in a docker container, first, an image  either has to be built
or pulled from a docker registry. To pull ClamAV from the official docker hub
registry, the following command can be used.

> _Note_: Pulling is not always required, as `docker run` also pulls the image
> if it does not yet exist and `docker run --pull` will always pull beforehand
> to ensure the most up-to-date container is being used.

```console
docker run \
       --interactive \
       --name "clam_container_01" \
       --rm \
       --tty \
       "myclamav" --help
```

The above creates an interactive container with the current tty connected to
it. This is optional but useful when getting started as it allows one to
directly see the output and, in the case of `clamd`, send ctrl-c to close the
container. The `--rm` parameter ensures the container is cleaned up again after
it exists and the `--name` parameter names the container, so it can be
referenced through other (docker) commands, as several containers of the same
image "myclamav" can be started without conflicts.

## Running clam(d)scan

Scanning files using `clamscan` or `clamdscan` is possible in various ways with
docker. This section briefly describes them, but the other sections of this
document are best read before hand to better understand some of the concepts.

One important aspect is however to realize that docker by default does not have
access to any of the hosts files. And so to scan these within docker, they need
to be volume mounted to be made accessible.

For example, running the container with these arguments ...
```console
       --volume '/path/to/scan:/scandir'
```
... would make the hosts file/directory `/path/to/scan` available in the
container as `/scandir` and thus invoking `clamscan` would thus be done on
`/scandir`.

Note that while technically possible to run either scanners via `docker exec`
this is not described as it is unlikely the container has access to the files
to be scanned.

### clamscan

Using `clamscan` outside of the docker container is how normally `clamscan` is
invoked. To make use of the available shared dockerized resources however, it
is possible to expose the virus database and share that for example. E.g. it
could be possible to run a docker container with only `freshclamd` and share
the virus database directory `/var/lib/clamav`. This could be useful for file
servers for example, where only `clamscan` is installed on the host, and
`freshclam` is managed in a docker container.

> _Note_: Running `freshclamd` separated from `clamd` is less recommended,
> unless the `clamd` socket is shared with `freshclam` as `freshclam` would
> not be able to inform `clamd` of database updates.

### Dockerized clamscan

To run `clamscan` in a docker container, the docker container can be invoked
as:
```console
docker run \
       --interactive \
       --rm \
       --tty \
       --volume '/path/to/scan:/scandir' \
       "myclamav" clamscan /scandir
```
This would pull the virus database using `freshclam`, run the scan and cleanup.

> _Note_: This is very inefficient when done often, as the complete database is
> downloaded on each invocation.

### clamdscan

As with `clamscan`, `clamdscan` can also be run when installed on the host, by
connecting to the dockerized `clamd`. This can be done by either pointing
`clamdscan` to the exposed TCP/UDP port or unix socket.

### Dockerized clamdscan

Running both `clamd` and `clamdscan` is also easily possible, as all that is
needed is the shared socket between the two containers. The only cavaet here
is to mount the files to be scaned in the container that is expected to run
`clamdscan`.

For example:
```console
docker run \
       --interactive \
       --rm \
       --tty \
       --volume '/path/to/scan:/scandir' \
       --volume '/var/lib/docker/data/clamav/sockets/:/run/clamav/'
       "myclamav" clamdscan /scandir
```

## Controlling the container

The ClamAV container actually runs both `freshclamd` and `clamd` by default.
Optionally available to the container is also ClamAV's milter. To control the
behavior of the services started within the container, the following flags can
be passed to the `docker run` command with the `--environment` parameter.

* CLAMAV_NO_CLAMD [true|**false**] Do not start `clamd` (default: start `clamd`)
* CLAMAV_NO_FRESHCLAMD [true|**false**] Do not start `freshclamd` (default: start `freshclamd`)
* CLAMAV_NO_MILTERD [**true**|false] Do not start `clamav-milter` (default: nomilter)
* CLAMD_STARTUP_TIMEOUT [integer] Seconds to wait for `clamd` to start (default: 1800)
* FRESHCLAM_CHECKS [integer] `freshclam` daily update frequency (default: once per day)

So to additionally also enable `clamav-milter`, the following flag can be added:
```console
       --environment 'CLAMAV_NO_MILTERED=false'
```

Further more, all of the configuration files that live in `/etc/clamav` can be
overridden by doing a volume-mount to the specific file. The following argument
can be added for this purpose. The example uses the entire configuration
directory, but this can be supplied multiple times if individual files deem to
be replaced.
```console
       --volume '/full/path/to/clamav/:/etc/clamav'
```

> _Note_: Even when disabling `freshclamd`, `freshclam` will always run at
> least once during container startup if there is no virus database. While not
> recommended, the virus database location itself `/var/lib/clamav/` could be
> a persistent docker volume. This however is slightly more advanced and out of
> scope of this document.

## Connecting to the container

### Executing commands within a running container

To connect to a running ClamAV container, `docker exec` can be used to run a
command on an already running container. To do so, the name needs to be either
obtained from `docker ps` or supplied during container start via the `--name`
parameter. The most interesting command in this case can be `clamdtop`.
```console
docker exec --interactive --tty "clamav_container_01" clamdtop
```
Alternatively, a shell can be started to inspect and run commands within the
container as well.
```console
docker exec --interactive --tty "clamav_container_01" /bin/sh
```

### Unix sockets

The default socket for `clamd` is located inside the container as
`/run/clamav/clamd.sock` and can be connected to when exposed via a docker
volume mount. To ensure, that `clamd` within the container can freely create
and remove the socket, the path for the socket is to be volume-mounted, to
expose it for others on the same host to use. The following volume can be used
for this purpose. Do ensure that the directory on the host actually exists and
clamav inside the container has permission to access it.
Caution is required when managing permissions, as incorrect permission could
open clamd for anyone on the host system.
```console
       --volume '/var/lib/docker/data/clamav/sockets/:/run/clamav/'
```

With the socket exposed to the host, any other service can now talk to `clamd`
as well. If for example `clamdtop` where installed on the local host, calling
```console
clamdtop "/var/lib/docker/data/clamav/sockets/clamd.sock"
```
should work just fine. Likewise, running `clamdtop` in a different container,
but sharing the socket will equally work. While `clamdtop` works well as an
example here, it is of course important to realize, this can also be used to
connect a mail server to `clamd`.

### TCP

While `clamd` and `clamav-milter` will listen on the default TCP ports as per
configuration directives, docker does not expose these by default to the host.
Only within  containers can these ports be accessed. To expose, or publish,
these ports to the host, and thus potentially over the (inter)network, the
`--publish` (or `--publish-all`) flag to `docker run` can be used. While more
advanced/secure mappings can be done as per documentation, the basic way is to
`--publish [<host_port>:]<container_port>` to make the port available to the
host.
```console
       --publish 73310:3310 \
       --publish 7357
```
The above would thus publish the milter port 3310 as 73310 on the host and the
clamd port 7357 as a random to the host. The random port can be inspected via
`docker ps`.

> **Warning** extreme caution is to be taken when using `clamd` over TCP as
> there are no protections on that level. All traffic is un-encrypted. Extra
> care is to be taken when using TCP communications.

## Virus database

The virus database in `/var/lib/clamav` is by default unique to each container
and thus is normally not shared. For simple setups this is fine, where only one
instance of `clamd` is expected to run in a dockerized environment. However
some use cases may want to efficiently share the database. To do so, the
`docker volume` command can be used to create a persistent virus database.

## Container clamd healthcheck

Docker has the ability to run simple `ping` checks on services running inside
containers. If `clamd` is running inside the container, docker will on
occasion send a `ping` to `clamd` on the default port and wait for the pong
from `clamd`. If `clamd` fails to respond, docker will treat this as an error.
The healthcheck results can be viewed with `docker inspect`.

## Performance

The performance impact of running `clamd` in docker is negligible. Docker is
in essence just a wrapper around Linux's cgroups and cgroups can be thought of
as `chroot` or FreeBSD's `jail`. All code is executed on the host without any
translation. Docker does however do some isolation (through cgroups) to isolate
the various systems somewhat.

Of course, nothing in life is free, and so there is some overhead. Disk-space
being the most prominent one. The docker container might have some duplication
of files for example between the host and the container. Further more, also RAM
memory may be duplicated for each instance, as there is no RAM-deduplication.
Both of which can be solved on the host however. A filesystem that supports
disk-deduplication and a memory manager that does RAM-deduplication.

The base container in itself is already very small ~16 MiB, at the time of this
writing, this cost is still very tiny, where the advantages are very much worth
the cost in general.

The container including the virus database is about ~240 MiB at the time of
this writing.

## Bandwidth

Please, be kind when using 'free' bandwidth. Both for the virus databases
but also the docker registry.
