import os
from google import genai
from dotenv import load_dotenv

# Load the .env file and configure a client
load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
client = genai.Client(api_key=GEMINI_API_KEY)
generation_config_json = {
    "max_output_tokens": 8192,
    "response_mime_type": "application/json"
}
generation_config_plain_text = {
    "max_output_tokens": 8192,
    "response_mime_type": "text/plain"
}



def get_ai_response_json(prompt):
    # Get the response 
    try :
        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt,
            config=generation_config_json
        )
        return response.text
    except Exception as e:
        return str(e)
    
def get_ai_response_textual(prompt):
    # Get the response 
    try :
        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt,
            config=generation_config_plain_text
        )
        return response.text
    except Exception as e:
        return str(e)