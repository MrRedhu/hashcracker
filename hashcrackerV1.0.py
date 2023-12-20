import re
import os 
import requests
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
import time

class HashCrackerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Hash Cracker")
        self.results = {} # Dictionary to store cracked hash results
         # Create GUI widgets
        self.create_widgets()

    def create_widgets(self):
        # Frame for single hash cracking
        single_frame = ttk.LabelFrame(self.root, text="Single Hash")
        single_frame.grid(row=0, column=0, padx=10, pady=5, sticky="w")

        ttk.Label(single_frame, text="Enter Hash:").grid(row=0, column=0, padx=5, pady=5)
        self.single_hash_entry = ttk.Entry(single_frame, width=40)
        self.single_hash_entry.grid(row=0, column=1, padx=5, pady=5)

        single_crack_button = ttk.Button(single_frame, text="Crack", command=self.crack_single_hash)
        single_crack_button.grid(row=0, column=2, padx=5, pady=5)

        # Frame for file or directory hashing
        file_frame = ttk.LabelFrame(self.root, text="File/Directory")
        file_frame.grid(row=1, column=0, padx=10, pady=5, sticky="w")

        ttk.Label(file_frame, text="Select File or Directory:").grid(row=0, column=0, padx=5, pady=5)
        self.file_entry = ttk.Entry(file_frame, width=30, state="readonly")
        self.file_entry.grid(row=0, column=1, padx=5, pady=5)

        file_browse_button = ttk.Button(file_frame, text="Browse", command=self.browse_file)
        file_browse_button.grid(row=0, column=2, padx=5, pady=5)

        file_crack_button = ttk.Button(file_frame, text="Crack", command=self.crack_file)
        file_crack_button.grid(row=0, column=3, padx=5, pady=5)

        # Progress bar
        self.progress_var = tk.DoubleVar()
        progress_bar = ttk.Progressbar(self.root, variable=self.progress_var, maximum=100)
        progress_bar.grid(row=2, column=0, pady=5, sticky="we")

        # Output area
        self.output_text = tk.Text(self.root, height=10, width=60, wrap="word")
        self.output_text.grid(row=3, column=0, pady=5, padx=10, sticky="we")
        self.output_text.config(state=tk.DISABLED)

    def browse_file(self):
        # Allow user to select a file and display its path in the entry widget
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            self.file_entry.config(state=tk.NORMAL)  # Enable the entry field
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, file_path)
            self.file_entry.config(state="readonly")  # Disable the entry field again

    def crack_single_hash(self):
        # Crack a single hash and display the result in the GUI
        hash_value = self.single_hash_entry.get().strip()
        if hash_value:
            self.output_text.config(state=tk.NORMAL)
            self.output_text.delete(1.0, tk.END)  # Clear previous output
            result = self.crack(hash_value)
            if result:
                self.output_text.insert(tk.END, result)
            else:
                self.output_text.insert(tk.END, "Hash was not found in any database.")
            self.output_text.config(state=tk.DISABLED)

    def crack_file(self):
        # Crack hashes from a file and display the results in the GUI
        file_path = self.file_entry.get().strip()
        if file_path:
            hashes = self.extract_hashes_from_file(file_path)
            thread_count = 4  # You can customize this
            self.results = {}  # Initialize results dictionary

            with ThreadPoolExecutor(max_workers=thread_count) as executor:
                futures = [executor.submit(self.crack, hash_value) for hash_value in hashes]
                for i, future in enumerate(futures):
                    try:
                        hash_value = hashes[i]  # Retrieve the corresponding hash_value
                        result = future.result()
                        if result:
                            self.results[hash_value] = result
                    except Exception as e:
                        print(f"Error processing hash: {e}")

                    if i + 1 == len(hashes) or (i + 1) % thread_count == 0:
                        progress_value = ((i + 1) / len(hashes)) * 100
                        self.progress_var.set(progress_value)
                        self.root.update_idletasks()

            self.progress_var.set(0)  

            # Display cracked hashes in the output area
            self.output_text.config(state=tk.NORMAL)
            self.output_text.delete(1.0, tk.END)  # Clear previous output
            for hash_value, result in self.results.items():
                self.output_text.insert(tk.END, f"{hash_value}: {result}\n")
            self.output_text.insert(tk.END, f"Results saved in cracked-{os.path.basename(file_path)}")
            self.output_text.config(state=tk.DISABLED)

    def crack(self, hash_value):
        # Crack a hash and return the result
        if len(hash_value) == 32:  # MD5
            self.results[hash_value] = self.md5(hash_value)
            return self.md5(hash_value)
        else:
            # For non-MD5 hashes, use hashtoolkit.com
            self.results[hash_value] = self.sha(hash_value, 'sha')
            return self.sha(hash_value, 'sha')

    def extract_hashes_from_file(self, file_path):
        # Extract hashes from a file and return a list of unique hashes
        hashes = set()
        with open(file_path, 'r') as file:
            for line in file:
                matches = re.findall(r'[a-f0-9]{128}|[a-f0-9]{96}|[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32}', line)
                hashes.update(matches)
        return list(hashes)

    def md5(self, hashvalue):
        # Crack an MD5 hash using nitrxgen.net and hashtoolkit.com
        response_nitrxgen = requests.get('https://www.nitrxgen.net/md5db/' + hashvalue, verify=False).text
        if response_nitrxgen:
            return response_nitrxgen
        return self.extract_result_from_hashtoolkit(hashvalue)

    def sha(self, hashvalue, hashtype):
        # Use the updated logic to extract results from hashtoolkit.com
        return self.extract_result_from_hashtoolkit(hashvalue)

    def extract_result_from_hashtoolkit(self, hashvalue):
        # Extract the result from hashtoolkit.com for a given hash
        url = f'https://hashtoolkit.com/decrypt-hash/?hash={hashvalue}'

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        time.sleep(1)
        with requests.Session() as session:
            try:
                response = session.get(url, headers=headers)

                if response.status_code == 200:
                    # Parse the HTML content
                    soup = BeautifulSoup(response.text, 'html.parser')

                    # Attempt to find the 'td' element with class 'res-text' and the nested 'a' element
                    td_element = soup.find('td', class_='res-text')
                    if td_element:
                        a_element = td_element.find('a')
                        if a_element:
                            # Extract decrypted text
                            decrypted_text = a_element.text.strip()
                            return decrypted_text
                        else:
                            return 'Error: Anchor element not found.'
                    else:
                        return 'Error: No Match Found.'
                else:
                    return f'Error: Unable to retrieve data. Status code: {response.status_code}'

            except Exception as e:
                return f'Error: {e}'


if __name__ == "__main__":
    root = tk.Tk()
    app = HashCrackerApp(root)
    root.mainloop()
