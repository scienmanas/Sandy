import os
import re
import requests
from urllib.parse import urlparse
from colorama import Style, Fore
from app.helpers.genai import get_ai_response_textual
from dotenv import load_dotenv

# Load the .env file
load_dotenv()
G_SAFE_BROWSING_API_KEY = os.getenv("G_SAFE_BROWSING_API_KEY")


def check_link(link):
    print(f"{Style.BRIGHT}{Fore.BLUE}Starting phishing analysis for: {link}{Style.RESET_ALL}")

    # Step 1: Manual checks
    print(f"{Style.BRIGHT}{Fore.YELLOW}Performing manual checks...{Style.RESET_ALL}")
    manual_results = perform_manual_checks(link)

    # Step 2: API checks
    print(f"{Style.BRIGHT}{Fore.YELLOW}Checking against phishing databases...{Style.RESET_ALL}")
    api_results = check_via_api(link)

    # Step 3: AI analysis of combined results
    print(f"{Style.BRIGHT}{Fore.YELLOW}Performing final AI analysis...{Style.RESET_ALL}")
    final_result = get_final_analysis(link, manual_results, api_results)

    # Telling the assesstment result to the user
    print()
    print(final_result)
    print()
    

# Mannual checks - Phishing indicators
def perform_manual_checks(link):
    """
    Performs manual checks on the URL to identify phishing indicators
    """
    results = {
        "is_suspicious": False,
        "risk_score": 0,
        "indicators": []
    }

    try:

        # Normalize the URL for analysis
        if not link.startswith(('http://', 'https://')):
            link = 'http://' + link
            print(f"Normalized link to: {link}")

        # Parsed the URL to extract domain
        parsed_url = urlparse(link)
        domain = parsed_url.netloc

        # Check 1: Domain length (unusually long domains are suspicious)
        if len(domain) > 30:
            results["indicators"].append("Unusually long domain name")
            results["risk_score"] += 20

        # Check 2: Excessive subdomains
        subdomain_count = domain.count('.')
        if subdomain_count > 3:
            results["indicators"].append("Excessive number of subdomains")
            results["risk_score"] += 10

        # Check 3: Check for IP address as domain
        ip_pattern = re.compile(
            r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')
        if ip_pattern.match(domain):
            results["indicators"].append("IP address used as domain")
            results["risk_score"] += 20

        # Check 4: Check for common brands in domain (potential spoofing)
        common_brands = ['paypal', 'apple', 'microsoft', 'amazon', 'google',
                         'facebook', 'instagram', 'netflix', 'bank', 'secure', 'account']
 # Potential subdomain spoofing
        for brand in common_brands:
            # If brand is in domain but not as top level domain, it's suspicious
            domain_parts = domain.split('.')
            if brand in domain and brand not in domain_parts[-2]:
                results["indicators"].append(
                    f"Potential brand spoofing ({brand})")
                results["risk_score"] += 100
                break
            # If brand is the top level domain (e.g., whatsapp.com), set risk to zero for this check
            elif brand in domain_parts[-2]:
                results["risk_score"] = 0
                results["indicators"].append(
                    f"Brand used as top-level domain ({brand})")
                results["is_suspicious"] = False
                return results

        # Check 5: Check for suspicious TLDs
        suspicious_tlds = ['.xyz', '.top', '.club',
                           '.online', '.site', '.tk', '.ml', '.ga', '.cf']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            results["indicators"].append("Suspicious top-level domain")
            results["risk_score"] += 10

        # Check 6: Check for suspicious keywords in the URL
        suspicious_keywords = ['login', 'signin', 'verify', 'secure', 'account',
                               'update', 'confirm', 'password', 'banking', 'authenticate', 'validation']

        path = parsed_url.path.lower()
        for keyword in suspicious_keywords:
            if keyword in path:
                results["indicators"].append(
                    f"Suspicious keyword in URL path: '{keyword}'")
                results["risk_score"] += 10

        # Check 7: Check for excessive use of special characters
        special_char_count = len(re.findall(r'[^a-zA-Z0-9\.]', domain))
        if special_char_count > 4:
            results["indicators"].append(
                "Excessive special characters in domain")
            results["risk_score"] += 30

        # Set the final suspicious flag based on risk score
        if results["risk_score"] >= 30:
            results["is_suspicious"] = True

    except Exception as e:
        results["indicators"].append(f"Error during manual analysis: {str(e)}")
        results["is_suspicious"] = True  # Err on the side of caution
        results["risk_score"] = 50

    return results

# API checks - Google Safe Browsing API


def check_via_api(link):
    try:
        # Using Google Safe Browsing Lookup API
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={G_SAFE_BROWSING_API_KEY}"

        # Parse the URL
        parsed_url = urlparse(link)
        domain = parsed_url.netloc

        # Prepare the request payload according to Google Safe Browsing API requirements
        payload = {
            "client": {
                "clientId": "sandy-phishing-checker",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": link}
                ]
            }
        }

        # Make the actual API request
        response = requests.post(api_url, json=payload, timeout=30)
        return response.text

    except Exception as e:
        return {
            "is_suspicious": False,
            "api_response": None,
            "error": str(e)
        }


# Final analysis
def get_final_analysis(link, manual_results, api_results):
    """
    Uses AI to analyze the combined results and provide a final assessment
    """
    # Prepare the data for AI analysis
    manual_suspicious = manual_results["is_suspicious"]
    manual_score = manual_results["risk_score"]
    manual_indicators = manual_results["indicators"]

    # Create a prompt for the AI
    prompt = f"""
    Analyzes result for this URL: {link} for phishing potential
    
    Manual analysis results:
    - Suspicious: {manual_suspicious}
    - Risk score: {manual_score}/100
    - Indicators: {', '.join(manual_indicators) if manual_indicators else 'None'}
    
    API analysis results (done by Google): {api_results}
    
    API results are from google if api results doesn't tell anything about the link then give importance to manual results more.
    
    Based on these results, provide a comprehensive analysis of whether this URL is likely a phishing attempt. Please don't return markdown or HTML in the response. Keep it plain text. Don't use * for bold or _ for italic.
    
    Include specific reasons why it might be dangerous or safe, and a final verdict.
    Keep your response concise and user-friendly. 
    """

    # Get AI analysis
    ai_analysis = get_ai_response_textual(prompt=prompt)
    return ai_analysis
