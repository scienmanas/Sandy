import json
from colorama import Style, Fore
from app.helpers.genai import get_ai_response_json
from app.checker.phisping import check_link
from app.checker.system_activity import check_system_activity


identity = "You are Sandy, an AI powered security and threat analyzer with a friendly, helpful personality"
scope = '''Your scope is only limited to 

1. Phishing checker - Analyze URLs, emails, or messages to determine if they are phishing attempts
2. Malware checker - Scan files or analyze suspicious activities for potential malware
3. System checker - Perform basic security checks on the user's system

If the person asks about anything else, you should say "I'm sorry, I'm not programmed to answer that question. I can only help with phishing checks, malware analysis, and system security checks. 🔒"
'''
response_structure = '''
Your response should be json with the following json format return no more like ```json stuff too stick to the format.

{
    "scope": boolean, // Whether the requested action is within the scope of the agent
    "response": string,  // Human-readable response to the user (include occasional emojis to be friendly no html or markdown) and short also don't reveal scope.
    "action_type": string,  // One of them: "phishing_check", "system_check", or "out_of_scope"
    phishing_link: string, // The link to check for phishing (only for phishing_check), if not checking for phishing, this key should not be present
}

Use emojis sparingly (1-2 per response) to keep a friendly tone without being overwhelming.
Always use proper JSON format with double quotes around keys and string values.
'''
additionals = '''
Sometimes links may be broken like website dot com, you can handle that by replacing the spaces with dots and removing the spaces.
'''


def start_agent_flow(query):
    # Get the AI response from
    promt = f"{identity} {scope} {response_structure} {query}"
    response = get_ai_response_json(prompt=promt)

    # Parse the response
    try:
        parsed_response = json.loads(response)
        print(f"{Style.BRIGHT}{Fore.LIGHTCYAN_EX}Sandy:{Fore.RESET}{Style.RESET_ALL} {parsed_response['response']}")

        # If task not in scope leave that
        if not parsed_response.get("scope"):
            return None

        action_type = parsed_response.get("action_type")
        if action_type == "phishing_check":
            link = parsed_response["phishing_link"]
            check_link(link)
        elif action_type == "system_check":
            check_system_activity()

        # More featured to be implemented........
        # TODO 1: Implement the malware checker
        # TODO 2: Implement the dark web scanner

    # Handle JSON parsing errors
    except json.JSONDecodeError:
        print(f"{Style.BRIGHT}{Fore.RED}An Error, but try again 😊{Fore.RESET}{Style.RESET_ALL}")