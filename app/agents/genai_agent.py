import json
import os
from colorama import Style, Fore
from app.helpers.genai import get_ai_response_json
from app.checker.phisping import check_link
from app.checker.system_activity import check_system_activity
from app.detectors.virus import check_virus_file


identity = "You are Sandy, an AI powered security and threat analyzer with a friendly, helpful personality"
scope = '''Your scope is only limited to 

1. Phishing checker - Analyze URLs, emails, or messages to determine if they are phishing attempts
2. Malware checker - Scan files or analyze suspicious activities for potential malware
3. System checker - Perform basic security checks on the user's system. User may say perform a system check or check my system or something similar to that.

If the person asks about anything else, you should say "I'm sorry, I'm not programmed to answer that question. I can only help with phishing checks, malware analysis, and system security checks. 🔒"

If someone says hi hello or greet you, you should respond with a good greeting, you can include emojis to make it more friendly."
'''
response_structure = '''
Your response should be in JSON format as shown below.

[
    {
        "scope": boolean, // Whether the requested action is within the scope of the agent
        "response": string,  // Human-readable response to the user (include occasional emojis to be friendly, no HTML or markdown) and keep it short. Do not reveal the scope.
        "action_type": string,  // One of: "phishing_check", "system_check", "virus_check","greeting", or "out_of_scope"
        "phishing_link": string, // The link to check for phishing (only for phishing_check). If not checking for phishing, this key should not be present.
        "goodbye": string // If the user says stop or exit or goodbye, return this key with a value of "true"  or "false" to indicate if the user wants to end the conversation. always return this key.
    }
]

Use emojis sparingly (1-2 per response) to maintain a friendly tone without being overwhelming.
Always use proper JSON format with double quotes around keys and string values.
'''
additionals = '''
Sometimes links may be broken like website dot com, you can handle that by replacing the spaces with dots and removing the spaces.

Also, if the user says stop or exit, return a good message in the response and set the goodbye key to true.
'''


def start_agent_flow(query):
    # Get the AI response from

    prompt = f"{identity} {scope} {response_structure} {query} {additionals}"
    response = get_ai_response_json(prompt=prompt)

    # Parse the response
    try:
        parsed_response = json.loads(response)[0]
        print(f"{Style.BRIGHT}{Fore.LIGHTCYAN_EX}Sandy:{Fore.RESET}{Style.RESET_ALL} {parsed_response['response']}")
                      
        try:   
            if (parsed_response.get("goodbye").lower() == "true"):
                os._exit(0)
        except:
            pass

        action_type = parsed_response.get("action_type")
        if action_type == "phishing_check":
            link = parsed_response["phishing_link"]
            check_link(link)
        elif action_type == "system_check":
            check_system_activity()
        elif action_type == "virus_check" :
            check_virus_file()

        # TODO 2: Implement the dark web scanner

    # Handle JSON parsing errors
    except json.JSONDecodeError:
        print(f"{Style.BRIGHT}{Fore.RED}An Error, but try again 😊{Fore.RESET}{Style.RESET_ALL}")