# Yasat - Yet Another Static Analysis Tool to detect cryptographic API misuses in firmware

## Misuse types targeted by Yasat

- Constant encryption keys (working)
- Constant salts for password-based encryption (PBE) (working)
- *etc.*

## Preparation

I would strongly suggest you use Python virtual environment, as Yasat is based on angr, which is a tool usually used in a virtual environment (See [Installing angr](https://docs.angr.io/introductory-errata/install)). Let's create a virtual environment first:

```
mkvirtualenv --python=$(which python3) Yasat
```

Install [binwalk](https://github.com/ReFirmLabs/binwalk) on the virtual environment you just created:
```
workon Yasat
git clone https://github.com/ReFirmLabs/binwalk.git
cd binwalk
sudo `which python` setup.py install
cd ..
sudo rm -rf binwalk
```

Then install other required packages by:
```
pip install -r requirements.txt
```

## Usage

The behavior of Yasat is fully controlled by the configuration file, which you can specify by `-c` option. If you don't specify this option, Yasat will use [config.yml](config.yml) by default.
```
python run.py -c [configuration file]
```

You may run Yasat on our handmade *Minimum Working Cases* (MWEs) to test whether Yasat works well:
```
python tests/test_mwes/test_mwes.py
```