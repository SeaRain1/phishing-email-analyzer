from email.utils import parseaddr


def analyze_context(observations, individual_indicators):
    contextual_indicators = []

    # Check 1: From domain vs Reply-To domain mismatch

    sender = observations.get("from")
    reply_to = observations.get("reply-to")

    # Only compare them if both headers actually exist.
    if sender is not None and reply_to is not None:

        # Extract the email addresses from headers like:
        # "PayPal Support <support@paypal.com>"
        
        # parseaddr() returns:
        # ("PayPal Support", "support@paypal.com")

        sender_name, sender_address = parseaddr(sender)
        reply_name, reply_address = parseaddr(reply_to)

        sender_domain = None
        reply_domain = None

        # Make sure the parsed addresses contain @
        # before trying to extract domains.
        if "@" in sender_address:
            sender_domain = sender_address.split("@")[-1].lower()

        if "@" in reply_address:
            reply_domain = reply_address.split("@")[-1].lower()

        # Only compare domains if both were successfully extracted.
        if (
            sender_domain is not None
            and reply_domain is not None
            and sender_domain != reply_domain
        ):
            contextual_indicators.append({
                "type": "contextual",
                "subtype": "from_reply_to_domain_mismatch",
                "severity": "medium",
                "from_domain": sender_domain,
                "reply_to_domain": reply_domain,
            })


    # Check 2: Multiple authentication failures

    authentication_failures = []

    # Look through the standalone indicators that were already
    # produced by authentication_analysis.py.
    for indicator in individual_indicators:

        if indicator.get("type") != "authentication":
            continue

        subtype = indicator.get("subtype")

        # Looking for definite authentication
        # failures, not temperror, permerror, softfail, etc.
        if subtype in {
            "spf_failure",
            "dkim_failure",
            "dmarc_failure",
        }:
            authentication_failures.append(subtype)

    # If at least two separate authentication mechanisms failed,
    # create an additional contextual indicator.
    if len(authentication_failures) >= 2:
        contextual_indicators.append({
            "type": "contextual",
            "subtype": "multiple_authentication_failures",
            "severity": "high",
            "failures": authentication_failures,
        })


    # Check 3: Suspicious attachment + suspicious URL

    suspicious_attachment = False
    suspicious_url = False

    for indicator in individual_indicators:

        # A high-severity attachment indicator means something
        # like an executable or other risky attachment.
        if (
            indicator.get("type") == "attachment"
            and indicator.get("severity") == "high"
        ):
            suspicious_attachment = True

        # A high-severity URL indicator means something like
        # a direct link to an executable/script.
        if (
            indicator.get("type") == "url"
            and indicator.get("severity") == "high"
        ):
            suspicious_url = True

    # Neither finding necessarily depends on the other,
    # but seeing both in the same email increases concern.
    if suspicious_attachment and suspicious_url:
        contextual_indicators.append({
            "type": "contextual",
            "subtype": "suspicious_attachment_and_url",
            "severity": "high",
        })


    return contextual_indicators