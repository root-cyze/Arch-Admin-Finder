# Arch Admin Finder

- Arch Admin Finder is a Python-based tool designed to discover admin panels on specific websites. 

- This tool scans a given web address, checking various paths to identify URLs that return a 200 status code.

## Vısual

![Screenshot_2024-11-26-00-04-57-480_com termux-edit](https://github.com/user-attachments/assets/49367fd2-4e0e-42ff-ba09-a581fae4f1f8)


## Features

- Proxy support
- Custom wordlist usage
- Delay adjustment for scanning
- Display of the last output when the admin panel is found

## Requirements

- Python 3.x
- `requests` library

## Installation

1. Clone this repository:

```
git clone https://github.com/cyze-afresh/Arch-Admin-Finder
```

```
cd Arch-Admin-Finder
```
2. Install the required libraries:
```
pip install requests
```


## Usage

Run the tool using the following command structure:

`python3 arch.py [OPTIONS]`

Options

`+site <website URL>`

The website to scan.


`+proxy <protocol>://<proxyserverip:port>`

`Use a proxy server.`


`+t <seconds>`

`Delay for scanning.`


`+w <custom/wordlist/path>`

`Custom wordlist file for scanning.`



## Example Usage

`python3 arch.py +site 
http://example.com`

`python3 arch.py +proxy http://1.2.3.4:8080 +site http://example.com`

`python3 arch.py +site https://example.com +t 1`

`python3 arch.py +site 
https://example.com +w /custom/wordlist/list.txt`

## Contribution
Feel free to contribute to the project by submitting issues or pull requests. All contributions are welcome!


