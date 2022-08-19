# tf-ob-tfe-aws-airgap-asglb diagram

This manual is dedicated to generate diagram in format png from definition in the python code

## Requirements

- Python 3 recent version installed
[Python 3 Mac OS X installation manual](https://docs.python-guide.org/starting/install3/osx/)

## Preparation 

- Change folder to diagram (current folder)

- Run `pip3 install -r requirements.txt`

Example result

```
$ pip3 install -r requirements.txt
DEPRECATION: Configuring installation scheme with distutils config files is deprecated and will no longer work in the near future. If you are using a Homebrew or Linuxbrew Python, please see discussion at https://github.com/Homebrew/homebrew-core/issues/76621
Collecting diagrams>=0.20.0
  Using cached diagrams-0.20.0-py3-none-any.whl (23.2 MB)
Requirement already satisfied: graphviz<0.17.0,>=0.13.2 in /usr/local/lib/python3.7/site-packages (from diagrams>=0.20.0->-r requirements.txt (line 1)) (0.16)
Requirement already satisfied: jinja2<3.0,>=2.10 in /usr/local/lib/python3.7/site-packages (from diagrams>=0.20.0->-r requirements.txt (line 1)) (2.11.3)
Requirement already satisfied: MarkupSafe>=0.23 in /usr/local/lib/python3.7/site-packages (from jinja2<3.0,>=2.10->diagrams>=0.20.0->-r requirements.txt (line 1)) (2.0.1)
Installing collected packages: diagrams
DEPRECATION: Configuring installation scheme with distutils config files is deprecated and will no longer work in the near future. If you are using a Homebrew or Linuxbrew Python, please see discussion at https://github.com/Homebrew/homebrew-core/issues/76621
Successfully installed diagrams-0.20.0
```

- Run `python3 daigram.py`

Expected result

```
$ python3 diagram.py 
$ 

```

- Open generated diagram image called `diagram.png`
