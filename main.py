import argparse
import logging
import requests
import pandas as pd
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(description='Analyze HTTP headers for security vulnerabilities and misconfigurations.')
    parser.add_argument('url', type=str, help='The URL to analyze.')
    parser.add_argument('--output', type=str, help='The output file to write results to (CSV). If not specified, prints to console.', required=False)
    parser.add_argument('--user-agent', type=str, default='HTTPHeaderAnalyzer/1.0', help='Custom User-Agent string to use. Default: HTTPHeaderAnalyzer/1.0')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout for the HTTP request in seconds. Default: 10')
    parser.add_argument('--insecure', action='store_true', help='Disable SSL certificate verification (INSECURE!).')
    return parser

def validate_url(url):
    """
    Validates that the input URL is a valid and well-formed URL.

    Args:
        url (str): The URL to validate.

    Returns:
        bool: True if the URL is valid, False otherwise.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False


def analyze_headers(url, user_agent='HTTPHeaderAnalyzer/1.0', timeout=10, insecure=False):
    """
    Analyzes the HTTP headers from a given URL.

    Args:
        url (str): The URL to analyze.
        user_agent (str): The User-Agent string to use for the request.
        timeout (int): Timeout for the HTTP request in seconds.
        insecure (bool): Disable SSL certificate verification.

    Returns:
        dict: A dictionary containing the header names and values.  Returns None on error.
    """
    try:
        headers = {'User-Agent': user_agent}
        logging.info(f"Sending request to {url} with User-Agent: {user_agent}, timeout: {timeout}, verify: {not insecure}")
        response = requests.get(url, headers=headers, timeout=timeout, verify=not insecure)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        return dict(response.headers)
    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None

def assess_security_headers(headers):
    """
    Assesses the presence and configuration of common security headers.

    Args:
        headers (dict): A dictionary containing the HTTP headers.

    Returns:
        dict: A dictionary containing the assessment results for each security header.
    """
    assessment = {}

    # Strict-Transport-Security (HSTS)
    hsts = headers.get('Strict-Transport-Security')
    if hsts:
        assessment['HSTS'] = 'Present'
        if 'max-age' not in hsts:
            assessment['HSTS_max_age'] = 'Missing max-age directive'
        else:
            assessment['HSTS_max_age'] = 'OK'

        if 'includeSubDomains' not in hsts:
            assessment['HSTS_includeSubDomains'] = 'Missing includeSubDomains directive'
        else:
            assessment['HSTS_includeSubDomains'] = 'OK'

        if 'preload' not in hsts:
            assessment['HSTS_preload'] = 'Missing preload directive'
        else:
            assessment['HSTS_preload'] = 'OK'
    else:
        assessment['HSTS'] = 'Missing'

    # Content-Security-Policy (CSP)
    csp = headers.get('Content-Security-Policy')
    if csp:
        assessment['CSP'] = 'Present'
        if 'default-src' not in csp:
            assessment['CSP_default_src'] = 'Missing default-src directive. Potentially very insecure.'
        else:
            assessment['CSP_default_src'] = 'OK'
    else:
        assessment['CSP'] = 'Missing'

    # X-Frame-Options
    xfo = headers.get('X-Frame-Options')
    if xfo:
        assessment['XFO'] = 'Present'
    else:
        assessment['XFO'] = 'Missing'

    # X-Content-Type-Options
    xcto = headers.get('X-Content-Type-Options')
    if xcto:
        assessment['XCTO'] = 'Present'
        if xcto.lower() == 'nosniff':
            assessment['XCTO_nosniff'] = 'OK'
        else:
            assessment['XCTO_nosniff'] = 'Invalid value'
    else:
        assessment['XCTO'] = 'Missing'

    # Referrer-Policy
    rp = headers.get('Referrer-Policy')
    if rp:
        assessment['Referrer-Policy'] = 'Present'
    else:
        assessment['Referrer-Policy'] = 'Missing'

    # Permissions-Policy (formerly Feature-Policy)
    pp = headers.get('Permissions-Policy') or headers.get('Feature-Policy')  # Check both
    if pp:
        assessment['Permissions-Policy'] = 'Present'
    else:
        assessment['Permissions-Policy'] = 'Missing'

    return assessment

def analyze_server_version(headers):
    """
    Analyzes the server version to identify outdated or vulnerable versions.

    Args:
        headers (dict): A dictionary containing the HTTP headers.

    Returns:
        str: A string describing the server version.
    """
    server = headers.get('Server')
    if server:
        return f"Server: {server}"
    else:
        return "Server information not disclosed."

def analyze_cookies(headers):
    """
    Analyzes cookies for security flags like HttpOnly and Secure.

    Args:
        headers (dict): A dictionary containing the HTTP headers.

    Returns:
        list: A list of strings describing the cookie security status.
    """
    cookies = headers.get('Set-Cookie')
    cookie_analysis = []

    if cookies:
        for cookie in cookies.split(', '):  # Handle multiple cookies in one header
            cookie = cookie.strip()
            if 'HttpOnly' not in cookie:
                cookie_analysis.append(f"Cookie '{cookie.split(';')[0]}' missing HttpOnly flag")
            if 'Secure' not in cookie:
                cookie_analysis.append(f"Cookie '{cookie.split(';')[0]}' missing Secure flag")
    else:
        cookie_analysis.append("No cookies set")

    return cookie_analysis

def main():
    """
    Main function to orchestrate the HTTP header analysis.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if not validate_url(args.url):
        logging.error("Invalid URL provided.")
        print("Error: Invalid URL provided.")
        return

    headers = analyze_headers(args.url, args.user_agent, args.timeout, args.insecure)

    if headers is None:
        print("Failed to retrieve headers.")
        return

    security_assessment = assess_security_headers(headers)
    server_info = analyze_server_version(headers)
    cookie_info = analyze_cookies(headers)

    data = {
        'Header': list(headers.keys()) + ['Server Analysis', 'Cookie Analysis'] + list(security_assessment.keys()),
        'Value': list(headers.values()) + [server_info] + [', '.join(cookie_info)] + list(security_assessment.values())
    }

    df = pd.DataFrame(data)

    if args.output:
        try:
            df.to_csv(args.output, index=False)
            logging.info(f"Results saved to {args.output}")
            print(f"Results saved to {args.output}")
        except Exception as e:
            logging.error(f"Error writing to file: {e}")
            print(f"Error writing to file: {e}")
    else:
        print(df.to_string())

if __name__ == "__main__":
    main()

# Usage Examples:
# python main.py https://example.com
# python main.py https://example.com --output results.csv
# python main.py https://example.com --user-agent "MyCustomAgent"
# python main.py https://example.com --timeout 5
# python main.py https://insecure-website.com --insecure