# Hash Cracker

Hash Cracker is a Python application with a graphical user interface (GUI) for cracking hash values using various hashing services.

## Features

- **Single Hash Cracking:** Crack a single hash interactively.
- **File/Directory Hash Cracking:** Crack hashes from a file or directory using multiple threads.
- **MD5 and Non-MD5 Support:** Supports MD5 hash cracking and non-MD5 hash cracking using hashtoolkit.com.
- **GUI Interface:** Provides a user-friendly interface with progress bars and output display.

## Usage

1. Run the `hashcracker.py` script using Python.
2. Use the GUI to either crack a single hash or crack hashes from a file/directory.

### Running the Executable

An executable version of the Hash Cracker has been provided. Follow these steps:

#### Download the Executable

Download the executable file [hashcrackerV1.0](https://github.com/MrRedhu/hashcracker/blob/main/hashcrackerV1.0) from the project repository.

#### Run in Terminal

Navigate to the directory containing the downloaded executable in your terminal and execute the following command:

```bash
./hashcrackerV1.0
```
## Dependencies

- Python 3.x
- Tkinter (usually included with Python)
- Requests
- BeautifulSoup4

Install dependencies using:

```bash
pip install requests beautifulsoup4
```
