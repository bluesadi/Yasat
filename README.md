# Yasat - Yet Another Static Analysis Tool to detect cryptographic API misuses in firmware

This is my undergraduate capstone project, and my very first attempt to develop a project using 
[angr](https://github.com/angr/angr). Thanks for angr's developers for offering such a powerful tool!

Yasat's aims are as follows:
- Minimize the false alarm rate
- Provide an accurate bird's-eye view of the number and severity of cryptographic misuses in firmware
- Try to exploit some misuses found in firmware

> 12/15/2022\
> Now I've completed an initial version only covering the two misuse types below. To detect the two misuse types is basically equivalent to detecting constant strings. So I simply utilize angr's built-in ReachingDefinitions analysis. It's a quite naive implemenation, because angr's ReachingDefinitions is an intraprocedural analysis and can't handle function calls. As such, my next step would be implementing an interprocedural context-sensitive ReachingDefinitions analysis to achieve better completeness.

## Misuse types targeted by Yasat

- Constant encryption keys
- Constant salts for password-based encryption (PBE)
- // TODO

## Preparation

I would strongly suggest you use Python virtual environment, as Yasat is based on angr, which is a tool usually used in a virtual environment; see [Installing angr](https://docs.angr.io/introductory-errata/install)). Let's create a virtual environment first:

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

You may run Yasat on our handmade test cases to test whether Yasat works well. For example:
```
python tests/test_constant_keys_checker/test.py
```
One of the generated reports would be:
```
*** Summary ***
Firmware path: tests/test_constant_keys_checker/input/test_constant_keys_checker_arm.bin

*** Misuses Found (Grouped by Checkers) ***
# ConstantKeysChecker
# ConstantSaltsChecker
## Misuse 1/1
[-] Binary path: /home/bluesadi/Yasat/tests/test_constant_keys_checker/tmp/_test_constant_keys_checker_arm.bin.extracted/squashfs-root/crypt
[-] Rule descrption: Do not use constant salts for password-based encryption (PBE)
[-] Misuse description: Call to `crypt(salt="XX")` at address 0x400675
```