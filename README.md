# Yasat - Yet Another Static Analysis Tool to detect cryptographic API misuses in firmware

This is my undergraduate capstone project, and my very first attempt to develop a project using 
[angr](https://github.com/angr/angr). Thanks for angr's developers for offering such a powerful tool!

Yasat's aims are as follows:
- Minimize the false alarm rate
- Provide an accurate bird's-eye view of the number and severity of cryptographic misuses in firmware
- Try to exploit some misuses found in firmware

> 12/25/2022\
> Merry Chrismas! Now I've completed an initial version only covering the two misuse types below. To detect the two misuse types is basically equivalent to detecting constant strings. So I simply utilize angr's built-in ReachingDefinitions analysis. It's a quite naive implemenation, because angr's ReachingDefinitions is an intraprocedural analysis and can't handle function calls. As such, my next step would be implementing an interprocedural context-sensitive ReachingDefinitions analysis to achieve better completeness.\
> 1/16/2023\
> I gradually realized ReachingDefinitions maybe not the best way to implement constant values dectection, so I ended up turning to implementing an on-demand BackwardSlicing analysis based on AIL (Angr Intermediate Language) CFG. Now I've completed an initial version (see: [Yasat/analyses/backward_slicing](Yasat/analyses/backward_slicing)), which is able to under-approximatively calculate the values of the slicing criterion (i.e., the argument of a callsite). However, current BackwardSlicing analysis is still imperfect. So I write a todo list to show what I've done and what I plan to do next.
> 1/28/2023\
> Completed an initial version of inter-procedural backward slicing. May there's still room for improvement.

## BackwardSlicing analysis development Process
- [x] A skeleton of intra-procedural BackwardSlicing
- [x] Make it able to handle global variables
- [ ] Refine [SimEngineBackwardSlicing](Yasat/analyses/backward_slicing/engine_ail.py)
- [x] Make it inter-procedural
- [ ] Make it able to handle some standard functions (e.g., memcpy, malloc)
- [ ] ...

## Misuse types targeted by Yasat

- Constant encryption keys
- Constant salts for password-based encryption (PBE)
- // TODO

## Installation

Python virtual environment is highly recommended as Yasat is based on angr, which is a tool usually used in a virtual environment (see [Installing angr](https://docs.angr.io/introductory-errata/install)). Let's create a virtual environment first:

```
mkvirtualenv --python=$(which python3) Yasat
```

Install [binwalk](https://github.com/ReFirmLabs/binwalk) in the virtual environment you just created:
```
workon Yasat
git clone https://github.com/ReFirmLabs/binwalk.git
cd binwalk
sudo `which python` setup.py install
cd ..
sudo rm -rf binwalk
```

Then install other required packages:
```
pip install -r requirements.txt
```

## Usage

**Configuration:** Yasat's behavior is fully controlled by the configuration file, which you can specify by `-c` option. If not specified, Yasat will use [config.yml](config.yml) by default. 

**Multiprocessing:** Use `-p` option to specify the maximum CPU cores for analyzing input files. Set this option to `1` if you do not want to use multiprocessing. The default number is half of the CPU cores of your machine.
```
python run.py [-c <config>] [-p <processes>]
```

## Test

You may run Yasat on our handmade test cases to test whether Yasat works well. For example:
```
python test.py constant_salts_checker
```
One of the generated reports would be:
```
*** Summary ***
Firmware path: tests/test_constant_salts_checker/input/test_constant_salts_checker_arm.bin

*** Misuses Found (Grouped by Checkers) ***
# ConstantKeysChecker
# ConstantSaltsChecker
## Misuse 1/1
[-] Binary path: /home/bluesadi/Yasat/tests/test_constant_salts_checker/tmp/_test_constant_salts_checker_arm.bin.extracted/squashfs-root/crypt
[-] Rule descrption: Do not use constant salts for password-based encryption (PBE)
[-] Misuse description: Call to `crypt(salt="XX")` at address 0x400675
```