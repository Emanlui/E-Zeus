# E-Zeus
[![Build Status](https://travis-ci.org/joemccann/dillinger.svg?branch=master)](https://travis-ci.org/joemccann/dillinger)

>This tool does an static analysis on executables or files, it uses yara rules to detect malicious code and prints out data from the sample file.

## Usage

Analyze the file
```sh
python3 e-zeus.py -a [file]
```
Prints out the strings of the file and compares the output with a local database of common strings
```sh
python3 e-zeus.py -s [file]
```
Prints out all the strings but it verifies if the line of the string has at least 4 letters
```sh
python3 e-zeus.py -s -v [file]
```


## Images

![Windows](https://github.com/Emanlui/E-Zeus/blob/main/images/win_analysis.png?raw=true)

## References

- https://github.com/VectraThreatLab/reyara/blob/master/re.yar
- https://github.com/reversinglabs/reversinglabs-yara-rules
- https://github.com/InQuest/yara-rules
- https://github.com/intezer/yara-rules
- https://github.com/fboldewin/YARA-rules
- https://github.com/f0wl/yara_rules