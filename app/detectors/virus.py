import os
import hashlib
import requests
from colorama import Fore, Style
from dotenv import load_dotenv
from app.helpers.genai import get_ai_response_textual

# Load env
load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def check_virus_file(file_path="test/virus.bin"):
    
    print(f"\n{Style.BRIGHT}{Fore.YELLOW}Doing Malware Analysis...{Fore.RESET}{Style.RESET_ALL}\n")
    
    # Perform local malware check
    response_by_api = check_virus_by_api(file_path)
    analysis_by_ai = get_ai_analysis(response_by_api)
    
    # Analysis 
    print()
    print(analysis_by_ai)
    print()

def check_virus_by_api(file_path):
    try:
        # Read the file in binary mode
        # Calculate the SHA-256 hash of the file
        with open(file_path, "rb") as file:
            file_data = file.read()  
            file_hash = hashlib.sha256(file_data).hexdigest()
            
            # Check the hash against a known list of malware hashes by calling the api
            try :
                url = f"https://www.virustotal.com/api/v3/files/{file_hash}/behaviour_summary"
                headers = {
                    "accept": "application/json",
                    "x-apikey": VIRUSTOTAL_API_KEY   
                }
            
                response = requests.get(url=url, headers=headers, timeout=30)
                return response.text
            except Exception as e :
                print(f"Error: {e}")
    
    except Exception as e:
        print(e)
        return f"{Style.BRIGHT}{Fore.RED}An error occurred: {str(e)}{Fore.RESET}{Style.RESET_ALL}"
    
def get_ai_analysis(data):
    prompt = f''' Here is the data of a analysis of a file which can be malware or virus analyse the data return from the api after behaviour analysis.
    
    One more thing don't use markdown or html just plain text response also no using of * for any purpose only plain text, also the response should be concise. Also if you feel further analysis is needed, you can recommend user to analyse the file in virtual environment.
    
    Here is the data :
    
    {data}
    '''
    
    # Get Ai Assessment
    response = get_ai_response_textual(prompt=prompt)
    return response