from email.utils import parseaddr


def analyze_metadata(observations):
    indicators = []

    sender = observations.get("from")
    message_id = observations.get("message-id")
    date = observations.get("date")
    subject = observations.get("subject")


    # Check 1: Missing From header

    if sender is None:
        indicators.append({
            "type": "metadata",
            "subtype": "missing_from",
            "value": None,
            "severity": "medium",
        })

    else:
        # parseaddr() separates a display name from the email address
        # Example: "John Smith <john@example.com>"
        # becomes: ("John Smith", "john@example.com")

        sender_name, sender_address = parseaddr(sender)

        # Check that an actual email address appears in the From header

        if not sender_address or "@" not in sender_address:
            indicators.append({
                "type": "metadata",
                "subtype": "malformed_from",
                "value": sender,
                "severity": "medium",
            })


    # Check 2: Missing Message-ID

    if message_id is None:
        indicators.append({
            "type": "metadata",
            "subtype": "missing_message_id",
            "value": None,
            "severity": "low",
        })


    # Check 3: Missing Date header

    if date is None:
        indicators.append({
            "type": "metadata",
            "subtype": "missing_date",
            "value": None,
            "severity": "low",
        })


    # Check 4: Missing or empty subject

    if subject is None or not subject.strip():
        indicators.append({
            "type": "metadata",
            "subtype": "missing_subject",
            "value": subject,
            "severity": "low",
        })


    return indicators