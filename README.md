# go-msspi

[go-msspi](https://github.com/deemru/go-msspi) is an adoption of [msspi](https://github.com/deemru/msspi) to crypto/tls like interface.

## Notice

- This is a demo implementation
- There are very few functions available

## Installation

```bash
git clone https://github.com/deemru/go-msspi --recursive
cd go-msspi/msspi/build_linux
make
cd ../..
go get
go test
```

## Notice for Windows

The `make` step can be for example `mingw32-make.exe -B static`

## Usage

- import "github.com/deemru/go-msspi"
- before: `tls.Client(conn, &tls.Config{})`
- after: `msspi.Client(conn, &tls.Config{})`
