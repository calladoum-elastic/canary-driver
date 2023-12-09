# Canary Monitor

[![Build Project](https://github.com/calladoum-elastic/canary-driver/actions/workflows/build.yml/badge.svg)](https://github.com/calladoum-elastic/canary-driver/actions/workflows/build.yml)

## Warning

This is not production quality code. Most of this code was developed in under a week, no serious testing was done.
Use at own risk.

## Setup

Download the pre-build binaries from GithubActions artifacts.

## Build

You'll need cmake, VS2022, and the SDK/WDK 2022

```
git clone https://github.com/calladoum-elastic/canary-driver
mkdir build
cmake -B ./build -S . -A x64
cmake --build ./build
cmake --install ./build
```

The binary `CanaryMonitor.exe` contains the driver embedded, it will self-extract and install on execution.

## Demo

[![](https://github.com/calladoum-elastic/canary-driver/assets/85187342/49df767f-24f4-4247-b71a-bb0fa415b5f8)](https://youtu.be/dIUV175EV3Q)

