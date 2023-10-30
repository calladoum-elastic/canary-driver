Build with

```
git clone https://github.com/calladoum-elastic/canary-driver
mkdir build
cmake -B ./build -S . -A x64
cmake --build ./build
cmake --install ./build
```

The binary `ProcessDumper.exe` contains the driver embedded, it will auto-extract on execution.
