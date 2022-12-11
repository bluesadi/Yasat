# Yasat - Yet Another Static Analysis Tool to detect cryptographic API misuses in firmware

## Preparation

Python virtual environment is highly recommended because Yasat is based on angr, which is a tool usually used in virtual environment. See [Installing angr](https://docs.angr.io/introductory-errata/install).

```
mkvirtualenv --python=$(which python3) Yasat
```

First manually install the latest binwalk by following its [offical document](https://github.com/ReFirmLabs/binwalk/blob/master/INSTALL.md).

Then install other required packages by:
```
pip install -r requirements.txt
```

## Usage

The behavior of Yasat is fully controlled by the configuration file, which you can specify by `-c` option. If you don't specify this option, Yasat will use [config.yml](config.yml) by default.
```
python run.py -c [configuration file]
```

You may also want to run Yasat on some firmware samples to test whether it works well.
```
python tests/test_sole/test_sole.py
```

## Misuse types targeted by Yasat

- Constant encryption keys
- Constant salts for password-based encryption (PBE)
- // TODO