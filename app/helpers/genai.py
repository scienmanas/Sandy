import os
from google import genai
from dotenv import load_dotenv
from google.genai import types

# Load the .env file and configure a client
load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
client = genai.Client(api_key=GEMINI_API_KEY)
generate_content_config_json = types.GenerateContentConfig(
    temperature=1,
    top_p=0.95,
    top_k=40,
    max_output_tokens=8192,
    safety_settings=[
        types.SafetySetting(
            category=types.HarmCategory.HARM_CATEGORY_HATE_SPEECH,
            threshold=types.HarmBlockThreshold.BLOCK_NONE,
        ),
    ],
    response_mime_type="application/json",
)
generate_content_config_plain_text = types.GenerateContentConfig(
    temperature=1,
    top_p=0.95,
    top_k=40,
    max_output_tokens=8192,
    safety_settings=[
        types.SafetySetting(
            category=types.HarmCategory.HARM_CATEGORY_HATE_SPEECH,
            threshold=types.HarmBlockThreshold.BLOCK_NONE,
        ),
    ],
    response_mime_type="text/plain",
)


def get_ai_response_json(prompt):
    # Get the response
    try:
        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt,
            config=generate_content_config_json
        )
        return response.text
    except Exception as e:
        return str(e)


def get_ai_response_textual(prompt):
    # Get the response
    try:
        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt,
            config=generate_content_config_plain_text
        )
        return response.text
    except Exception as e:
        return str(e)
