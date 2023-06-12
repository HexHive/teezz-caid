
## Setup and Run

Clone repo and use the `Makefile` to build/run docker.

```
$ git clone --recursive git@github.com:HexHive/teezz-caid.git
$ cd teezz-caid
$ make build
$ make run DEVICE_ID=<device id> LIB_PATH=<on-device tee lib path>
```

By default, we map `<repo>/inout` into the docker container. All results can
be found there.

See `Dockerfile` for dependencies.
See `docker/docker-entrypoint.sh` for more usage info.

## Dependency Graphs

Some illustrations of TEE library dependencies.

### Huawei P20 Lite

![](/images/huaweip20lite.png)

### Pixel 2XL

![](/images/pixel2xl.png)

### Nexus 5X

![](/images/nexus5x.png)

### Huawei P9 Lite

![](/images/p9lite.png)

## Troubleshooting

Q: I cannot see my Android device inside of the container.

A: Kill the adb server on the host (`adb kill-server`) and try again.

