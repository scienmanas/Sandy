import re
import time
from urllib.parse import urlparse
from colorama import Style, Fore
from app.helpers.genai import get_ai_response_textual

def check_link(link):
    print(f"{Style.BRIGHT}{Fore.BLUE}Starting phishing analysis for: {link}{Style.RESET_ALL}")
    print(f"DEBUG: Received link: {link}")
    
    # Step 1: Manual checks
    print(f"{Style.BRIGHT}{Fore.YELLOW}Performing manual checks...{Style.RESET_ALL}")
    manual_results = perform_manual_checks(link)
    print(f"DEBUG: Manual check results: {manual_results}")
    
    # Step 2: API checks
    print(f"{Style.BRIGHT}{Fore.YELLOW}Checking against phishing databases...{Style.RESET_ALL}")
    api_results = check_via_api(link)
    print(f"DEBUG: API check results: {api_results}")
    
    # Step 3: AI analysis of combined results
    print(f"{Style.BRIGHT}{Fore.YELLOW}Performing final AI analysis...{Style.RESET_ALL}")
    final_result = get_final_analysis(link, manual_results, api_results)
    print(f"DEBUG: Final analysis results: {final_result}")
    
    return final_result

def perform_manual_checks(link):
    """
    Performs manual checks on the URL to identify phishing indicators
    """
    print(f"DEBUG: Starting manual checks for: {link}")
    results = {
        "is_suspicious": False,
        "risk_score": 0,
        "indicators": []
    }
    
    try:
        # Normalize the URL for analysis
        if not link.startswith(('http://', 'https://')):
            link = 'http://' + link
            print(f"DEBUG: Normalized link to: {link}")
        
        parsed_url = urlparse(link)
        domain = parsed_url.netloc
        print(f"DEBUG: Parsed domain: {domain}")
        
        # Check 1: Domain length (unusually long domains are suspicious)
        if len(domain) > 30:
            results["indicators"].append("Unusually long domain name")
            results["risk_score"] += 10
            print(f"DEBUG: Domain length check failed: {len(domain)} characters")
        
        # Check 2: Excessive subdomains
        subdomain_count = domain.count('.')
        print(f"DEBUG: Subdomain count: {subdomain_count}")
        if subdomain_count > 3:
            results["indicators"].append("Excessive number of subdomains")
            results["risk_score"] += 15
            print(f"DEBUG: Excessive subdomains detected: {subdomain_count}")
        
        # Check 3: Check for IP address as domain
        ip_pattern = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')
        if ip_pattern.match(domain):
            results["indicators"].append("IP address used as domain")
            results["risk_score"] += 25
            print(f"DEBUG: IP address used as domain: {domain}")
        
        # Check 4: Check for common brands in domain (potential spoofing)
        common_brands = ['paypal', 'apple', 'microsoft', 'amazon', 'google', 'facebook', 'instagram', 'netflix', 'bank', 'secure', 'account']
        print(f"DEBUG: Checking for brand spoofing in: {domain}")
        
        for brand in common_brands:
            if brand in domain and brand not in domain.split('.')[0]:
                results["indicators"].append(f"Potential brand spoofing ({brand})")
                results["risk_score"] += 20
                print(f"DEBUG: Brand spoofing detected: {brand} in {domain}")
                break
        
        # Check 5: Check for suspicious TLDs
        suspicious_tlds = ['.xyz', '.top', '.club', '.online', '.site', '.tk', '.ml', '.ga', '.cf']
        print(f"DEBUG: Checking for suspicious TLDs")
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            tld_found = next((tld for tld in suspicious_tlds if domain.endswith(tld)), None)
            results["indicators"].append("Suspicious top-level domain")
            results["risk_score"] += 15
            print(f"DEBUG: Suspicious TLD detected: {tld_found}")
        
        # Check 6: Check for suspicious keywords in the URL
        suspicious_keywords = ['login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm','password', 'banking', 'authenticate', 'validation']
        
        path = parsed_url.path.lower()
        print(f"DEBUG: Checking for suspicious keywords in path: {path}")
        for keyword in suspicious_keywords:
            if keyword in path:
                results["indicators"].append(f"Suspicious keyword in URL path: '{keyword}'")
                results["risk_score"] += 10
                print(f"DEBUG: Suspicious keyword detected: {keyword}")
                break
        
        # Check 7: Check for excessive use of special characters
        special_char_count = len(re.findall(r'[^a-zA-Z0-9\.]', domain))
        print(f"DEBUG: Special character count: {special_char_count}")
        if special_char_count > 4:
            results["indicators"].append("Excessive special characters in domain")
            results["risk_score"] += 15
            print(f"DEBUG: Excessive special characters detected: {special_char_count}")
        
        # Set the final suspicious flag based on risk score
        if results["risk_score"] >= 30:
            results["is_suspicious"] = True
            print(f"DEBUG: URL marked as suspicious with risk score: {results['risk_score']}")
            
    except Exception as e:
        results["indicators"].append(f"Error during manual analysis: {str(e)}")
        results["is_suspicious"] = True  # Err on the side of caution
        results["risk_score"] = 50
        print(f"DEBUG: Error in manual checks: {str(e)}")
    
    print(f"DEBUG: Manual check results: {results}")
    return results

def check_via_api(link):
    """
    Checks the URL against phishing databases using free APIs
    """
    print(f"DEBUG: Starting API checks for: {link}")
    results = {
        "is_suspicious": False,
        "api_response": None,
        "error": None
    }
    
    try:
        # Using Google Safe Browsing Lookup API (you would need an API key in production)
        # This is a placeholder - in a real implementation, you'd use your API key
        # api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key=YOUR_API_KEY"
        
        # For demonstration, we'll use a mock API call to ipqualityscore.com (free tier available)
        api_url = f"https://ipqualityscore.com/api/json/url/YOUR_API_KEY/{link}"
        print(f"DEBUG: API URL: {api_url}")
        
        # Simulating API response for demonstration
        time.sleep(1)  # Simulate API call delay
        print(f"DEBUG: API call simulated")
        
        # In a real implementation, you would do:
        # response = requests.get(api_url)
        # api_data = response.json()
        
        # For demonstration, we'll create a mock response
        parsed_url = urlparse(link)
        domain = parsed_url.netloc
        print(f"DEBUG: Parsed domain for API check: {domain}")
        
        # Simple mock logic - in reality, this would come from the API
        suspicious_domains = ['suspicious-site.com', 'phishing-example.net', 'malware.xyz']
        is_suspicious = any(s in domain for s in suspicious_domains)
        print(f"DEBUG: Domain suspicious check: {is_suspicious}")
        
        results["api_response"] = {
            "success": True,
            "unsafe": is_suspicious,
            "domain": domain,
            "spamming": False,
            "malware": False,
            "phishing": is_suspicious,
            "suspicious": is_suspicious,
            "risk_score": 85 if is_suspicious else 12
        }
        
        results["is_suspicious"] = is_suspicious
        print(f"DEBUG: API response generated: {results['api_response']}")
        
    except Exception as e:
        results["error"] = str(e)
        print(f"DEBUG: Error in API checks: {str(e)}")
    
    print(f"DEBUG: API check results: {results}")
    return results

def get_final_analysis(link, manual_results, api_results):
    """
    Uses AI to analyze the combined results and provide a final assessment
    """
    print(f"DEBUG: Starting final analysis for: {link}")
    # Prepare the data for AI analysis
    manual_suspicious = manual_results["is_suspicious"]
    manual_score = manual_results["risk_score"]
    manual_indicators = manual_results["indicators"]
    
    api_suspicious = api_results["is_suspicious"]
    api_error = api_results["error"]
    api_response = api_results["api_response"]
    
    print(f"DEBUG: Manual suspicious: {manual_suspicious}, API suspicious: {api_suspicious}")
    
    # Create a prompt for the AI
    prompt = f"""
    Analyze this URL for phishing potential: {link}
    
    Manual analysis results:
    - Suspicious: {manual_suspicious}
    - Risk score: {manual_score}/100
    - Indicators: {', '.join(manual_indicators) if manual_indicators else 'None'}
    
    API analysis results:
    - Suspicious: {api_suspicious}
    - API error: {api_error if api_error else 'None'}
    - API details: {api_response}
    
    Based on these results, provide a comprehensive analysis of whether this URL is likely a phishing attempt.
    Include specific reasons why it might be dangerous or safe, and a final verdict.
    Keep your response concise and user-friendly.
    """
    
    print(f"DEBUG: AI prompt created")
    
    # Get AI analysis
    ai_analysis = get_ai_response_textual(prompt=prompt)
    print(f"DEBUG: AI analysis received")
    
    # Compile final results
    final_result = {
        "url": link,
        "is_phishing": manual_suspicious or api_suspicious,
        "manual_analysis": manual_results,
        "api_analysis": api_results,
        "ai_analysis": ai_analysis,
        "timestamp": time.time()
    }
    
    print(f"DEBUG: Final result compiled: is_phishing={final_result['is_phishing']}")
    return final_result
