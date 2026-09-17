from urllib.parse import urlparse
import ipaddress


def analyze_urls(observations):
    indicators = []

    # Get all URLs that observations.py extracted from the email body.
    urls = observations.get("urls", [])

    # Domains commonly used to shorten URLs.
    url_shorteners = {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "buff.ly",
        "is.gd",
        "cutt.ly",
        "rb.gy",
        "rebrand.ly",
    }

    # File types that would be concerning if linked directly from an email.
    suspicious_extensions = {
        ".exe",
        ".com",
        ".scr",
        ".pif",
        ".cpl",
        ".msi",
        ".msp",
        ".ps1",
        ".bat",
        ".cmd",
        ".vbs",
        ".vbe",
        ".js",
        ".jse",
        ".wsf",
        ".hta",
        ".lnk",
        ".jar",
        ".iso",
        ".img",
        ".dmg",
        ".apk",
    }

    # Analyze each URL individually.
    for url in urls:

        # Break the URL into pieces such as:
        # scheme, hostname, path, port, etc.
        parsed_url = urlparse(url)

        scheme = parsed_url.scheme.lower()
        hostname = parsed_url.hostname
        path = parsed_url.path.lower()

        # If Python cannot determine a hostname,
        # there is not much useful domain analysis to do.
        if hostname is None:
            indicators.append({
                "type": "url",
                "subtype": "missing_hostname",
                "value": url,
                "severity": "low",
            })

            continue

        # Normalize the hostname to lowercase
        hostname = hostname.lower()


        # Check 1: HTTP instead of HTTPS

        if scheme == "http":
            indicators.append({
                "type": "url",
                "subtype": "http_url",
                "value": url,
                "severity": "low",
                "domain": hostname,
            })


        # Check 2: IP address instead of a domain

        try:
            ipaddress.ip_address(hostname)

            indicators.append({
                "type": "url",
                "subtype": "ip_address_url",
                "value": url,
                "severity": "medium",
                "domain": hostname,
            })

        except ValueError:
            # Hostname was not an IP address
            pass


        # CHECK 3: Punycode domain

        # Internationalized domains can use "xn--", can be
        # legitimate but also be used in lookalike/phishing domains
        if "xn--" in hostname:
            indicators.append({
                "type": "url",
                "subtype": "punycode_domain",
                "value": url,
                "severity": "medium",
                "domain": hostname,
            })


        # Check 4: Known URL shortener

        if hostname in url_shorteners:
            indicators.append({
                "type": "url",
                "subtype": "url_shortener",
                "value": url,
                "severity": "medium",
                "domain": hostname,
            })


        # Check 5: Suspicious file extension in URL path

        for extension in suspicious_extensions:
            if path.endswith(extension):
                indicators.append({
                    "type": "url",
                    "subtype": "suspicious_file_link",
                    "value": url,
                    "severity": "high",
                    "domain": hostname,
                    "file_extension": extension,
                })

                # Once one matching extension is found,
                # there is no reason to keep checking the others.
                break


        # Check 6: Excessive number of subdomains

        # Example: login.security.account.example.com
        # becomes:
        # ["login", "security", "account", "example", "com"]
    
        domain_parts = hostname.split(".")

        if len(domain_parts) > 4:
            indicators.append({
                "type": "url",
                "subtype": "excessive_subdomains",
                "value": url,
                "severity": "low",
                "domain": hostname,
            })


        # Check 7: Very long URL

        # Not automatically malicious, but phishing/tracking/obfuscation 
        # can make URLs unusually long
        if len(url) > 200:
            indicators.append({
                "type": "url",
                "subtype": "long_url",
                "value": url,
                "severity": "low",
                "domain": hostname,
                "length": len(url),
            })


        # Check 8: Username/password-style userinfo in URL

        # Example:https://google.com@scam.com/login
        # The actual hostname is scam.com.

        if parsed_url.username is not None:
            indicators.append({
                "type": "url",
                "subtype": "userinfo_in_url",
                "value": url,
                "severity": "medium",
                "domain": hostname,
            })


    return indicators