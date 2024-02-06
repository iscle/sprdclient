# sprdclient

sprdclient aims to be a simple and easy to use tool to interact with Spreadtrum / Unisoc BootROM and FDLs.

## Goals

- [x] Talk to the BootROM
- [ ] Read flash memory
- [ ] Write flash memory

## Supported chipsets

- SC8541E
- SC9832E
- UMS512

## Build

### Linux

```sh
git clone https://github.com/iscle/sprdclient
cd sprdclient
mkdir build
cd build
cmake ..
make
```

## License

This project is licensed under the GPL-3.0 license - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [TomKing062](https://github.com/TomKing062): Provided dumps of the BootROM for various chipsets.
- [Ilya Kurdyukov](https://github.com/ilyakurdyukov): Created the original tool that this project is inspired on.
