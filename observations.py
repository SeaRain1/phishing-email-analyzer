# This file is responsible for receiving the parsed email object and then creating a dictionary for the observations we care about


# collect subject, from, to, date, memssage-id, 
# reply-to, return-path
# spf, dkim, dmarc, smtp.mailfrom, 

import re
import html
from pathlib import Path

def create_dictionary(msg):

    # Get Authentication Headers
    auth_headers = msg.get_all("Authentication-Results", [])
    dkim_headers = msg.get_all("DKIM-Signature", [])

    # Combine Authentication-Results headers into one string to search
    auth_text = " ; ".join(str(header) for header in auth_headers)

    # Parse SPF from Authentication-Results, SENDING_IP will be parsed later from RECEIVED 
    # DATA to avoid using mailbox specific terms like "designates ... as permitted sender"
    spf_dict = None
    # if auth_text is not empty:
    if auth_text:
        # Find spf_result
        find_spf_result = re.search(r"\bspf=([A-Za-z0-9_-]+)",auth_text,re.IGNORECASE)
        if find_spf_result is not None:
            spf_result = find_spf_result.group(1)

            # Find smtp.mailfrom
            spf_mailfrom = None
            find_spf_mailfrom = re.search(r"smtp\.mailfrom=([^\s;]+)",auth_text,re.IGNORECASE)
            if find_spf_mailfrom is not None:
                spf_mailfrom = find_spf_mailfrom.group(1)

            # Find smtp.helo
            spf_helo = None
            find_spf_helo = re.search(r"smtp\.helo=([^\s;]+)",auth_text,re.IGNORECASE)
            if find_spf_helo is not None:
                spf_helo = find_spf_helo.group(1)

            spf_dict = {
                "result": spf_result,
                "mailfrom": spf_mailfrom,
                "helo": spf_helo,
                "sending_ip": None,
            }

    # Parse DMARC
    dmarc_dict = None

    if auth_text:
        # Capture the DMARC result and the details belonging to it
        find_dmarc = re.search(r"\bdmarc=([A-Za-z0-9_-]+)([^;]*)",auth_text,re.IGNORECASE)
        if find_dmarc is not None:
            dmarc_result = find_dmarc.group(1)
            dmarc_details = find_dmarc.group(2)

            # Find header.from
            dmarc_header_from = None
            find_dmarc_header_from = re.search(r"header\.from=([^\s;]+)",dmarc_details,re.IGNORECASE)
            if find_dmarc_header_from is not None:
                dmarc_header_from = find_dmarc_header_from.group(1)

            # Find p= policy
            dmarc_policy = None
            find_dmarc_policy = re.search(r"\bp=([A-Za-z]+)",dmarc_details,re.IGNORECASE)
            if find_dmarc_policy is not None:
                dmarc_policy = find_dmarc_policy.group(1)

            # Find sp= subdomain policy
            dmarc_subdomain_policy = None
            find_dmarc_subdomain_policy = re.search(r"\bsp=([A-Za-z]+)",dmarc_details,re.IGNORECASE)
            if find_dmarc_subdomain_policy is not None:
                dmarc_subdomain_policy = find_dmarc_subdomain_policy.group(1)

            dmarc_dict = {
                "result": dmarc_result,
                "header_from": dmarc_header_from,
                "policy": dmarc_policy,
                "subdomain_policy": dmarc_subdomain_policy,
            }

    # PARSE DKIM VERIFICATION RESULTS
    # Only Authentication-Results tells us DKIM pass/fail, while DKIM-Signature
    # headers provide DKIM data. 
    # So first parse DKIM results from Authentication-Results and then match 
    # them to their actual DKIM-Signature headers   

    # List that will hold parsed DKIM results
    dkim_results = []

    if auth_text:
        dkim_matches = re.findall(r"\bdkim=([A-Za-z0-9_-]+)([^;]*)",auth_text,re.IGNORECASE)

        # Tuple unpacking of dkim_matches ex: ("pass", " header.s=s1...")
        # result = "pass"
        # details = "header.s=s1..."
        for result, details in dkim_matches:

            # Find selector from header.s=
            auth_selector = None
            find_auth_selector = re.search(r"header\.s=([^\s;]+)",details,re.IGNORECASE)
            if find_auth_selector is not None:
                auth_selector = find_auth_selector.group(1)

            # Find identity from header.i=
            auth_identity = None
            find_auth_identity = re.search(r"header\.i=([^\s;]+)",details,re.IGNORECASE)
            if find_auth_identity is not None:
                auth_identity = find_auth_identity.group(1)

            # Find signing domain from header.d= if supplied
            auth_domain = None
            find_auth_domain = re.search(r"header\.d=([^\s;]+)",details,re.IGNORECASE)
            if find_auth_domain is not None:
                auth_domain = find_auth_domain.group(1)

            # If header.d is absent, derive the domain from header.i
            elif auth_identity is not None and "@" in auth_identity:
                auth_domain = auth_identity.split("@")[-1]

            dkim_results.append({
                "result": result,
                "selector": auth_selector,
                "domain": auth_domain,
            })

    # PARSE DKIM-SIGNATURE HEADERS
    # Each signature can have its own domain, identity, selector, algorithm, 
    # and verification result.
    
    # Final list of parsed DKIM signatures
    dkim_list = []
    # Tracks which results have already been matched to a signature
    used_dkim_results = set()

    for signature in dkim_headers:

        dkim_domain = None
        dkim_identity = None
        dkim_selector = None
        dkim_algorithm = None

        # Find d= signing domain
        find_dkim_domain = re.search(r"\bd=([^;]+)", signature, re.IGNORECASE)
        if find_dkim_domain is not None:
            dkim_domain = find_dkim_domain.group(1).strip()

        # Find i= signing identity
        find_dkim_identity = re.search(r"\bi=([^;]+)", signature, re.IGNORECASE)
        if find_dkim_identity is not None:
            dkim_identity = find_dkim_identity.group(1).strip()

        # Find s= selector
        find_dkim_selector = re.search(r"\bs=([^;]+)", signature, re.IGNORECASE)
        if find_dkim_selector is not None:
            dkim_selector = find_dkim_selector.group(1).strip()

        # Find a= algorithm
        find_dkim_algorithm = re.search(r"\ba=([^;]+)", signature, re.IGNORECASE)
        if find_dkim_algorithm is not None:
            dkim_algorithm = find_dkim_algorithm.group(1).strip()

        # Match this DKIM-Signature to the correct DKIM result
        current_signature_result = None

        for index, result_info in enumerate(dkim_results):

            if index in used_dkim_results:
                continue

            selector_matches = (
                dkim_selector is not None
                and result_info["selector"] is not None
                and dkim_selector.lower() == result_info["selector"].lower()
            )

            domain_matches = (
                dkim_domain is not None
                and result_info["domain"] is not None
                and dkim_domain.lower() == result_info["domain"].lower()
            )

            # Prefer selector matching. If both sides also provide
            # domains, require the domains to agree.
            if selector_matches:
                if (
                    result_info["domain"] is None
                    or dkim_domain is None
                    or domain_matches
                ):
                    current_signature_result = result_info["result"]
                    used_dkim_results.add(index)
                    break

            # If no selector was supplied, use domain as a fallback
            elif result_info["selector"] is None and domain_matches:
                current_signature_result = result_info["result"]
                used_dkim_results.add(index)
                break

        # Save one completed dictionary for this DKIM signature
        dkim_list.append({
            "result": current_signature_result,
            "domain": dkim_domain,
            "identity": dkim_identity,
            "selector": dkim_selector,
            "algorithm": dkim_algorithm,
        })

    # Fallback: Authentication-Results reports DKIM,
    # but the message contains no DKIM-Signature header.
    if not dkim_headers:

        dkim_auth_matches = re.findall(
            r"\bdkim=([A-Za-z0-9_-]+)(.*?)(?=\b(?:spf|dkim|dmarc|arc|compauth|bimi)=|$)",
            auth_text,
            re.IGNORECASE
        )

        for result, details in dkim_auth_matches:

            domain_match = re.search(r"header\.d=([^\s;]+)",details,
                re.IGNORECASE
            )

            identity_match = re.search(r"header\.i=([^\s;]+)",details,
                re.IGNORECASE
            )

            selector_match = re.search(r"header\.s=([^\s;]+)",details,
                re.IGNORECASE
            )

            algorithm_match = re.search(r"header\.a=([^\s;]+)",details,
                re.IGNORECASE
            )

            dkim_list.append({
                "result": result.lower(),
                "domain": domain_match.group(1) if domain_match else None,
                "identity": identity_match.group(1) if identity_match else None,
                "selector": selector_match.group(1) if selector_match else None,
                "algorithm": algorithm_match.group(1) if algorithm_match else None,
            })  


    # Build Authentication Dictionary

    auth_dict = {
        "spf": spf_dict,
        "dkim": dkim_list,
        "dmarc": dmarc_dict,
    }

   
    # Store Received / Routing Headers
    # Later analysis will inspect the
    # route and extract sending IP information more reliably.

    received_headers = [
        str(header)
        for header in msg.get_all("Received", [])
    ]

    # MIME /Body Structure and raw URL extraction

    content_types = []
    urls = []

    for part in msg.walk():

        # multipart/* parts are containers, not actual content
        if part.is_multipart():
            continue

        content_type = part.get_content_type()
        content_types.append(content_type)

        # Search normal text/HTML body parts for URLs
        if (
            content_type in ("text/plain", "text/html")
            and part.get_content_disposition() != "attachment"
        ):
            content = part.get_content()

            # Plain-text email:
            # Find URLs written directly in the text.
            if content_type == "text/plain":
                found_urls = re.findall(r"https?://[^\s<>'\")]+",content)

            # HTML email:
            # Only collect URLs that are actual href links.
            else:
                found_urls = re.findall(r'''href=["'](https?://[^"']+)["']''',
                content,re.IGNORECASE)

                found_urls = [
                    html.unescape(url)
                    for url in found_urls
                ]

            urls.extend(found_urls)

    # Remove duplicate URLs while preserving their order
    urls = list(dict.fromkeys(urls))

    # Attachments
    attachments = []

    for attachment in msg.iter_attachments():

        filename = attachment.get_filename()

        # Extract extension if a filename exists
        extension = None
        if filename is not None:
            extension = Path(filename).suffix.lower()

        # Decode attachment bytes so its size can be measured
        payload = attachment.get_payload(decode=True)

        size = None
        if payload is not None:
            size = len(payload)

        attachments.append({
            "filename": filename,
            "content_type": attachment.get_content_type(),
            "extension": extension,
            "size_bytes": size,
        })


    # Build final observations dictionary
    observations_dict = {
        "subject": msg.get("subject"),
        "from": msg.get("from"),
        "to": msg.get("to"),
        "date": msg.get("date"),
        "message-id": msg.get("message-id"),
        "reply-to": msg.get("reply-to"),
        "return-path": msg.get("return-path"),
        "authentication": auth_dict,
        "received": received_headers,

        "body_structure": {
            "content_types": content_types,
            "has_plain_text": "text/plain" in content_types,
            "has_html": "text/html" in content_types,
        },

        "urls": urls,
        "attachments": attachments,
        "user-agent": msg.get("user-agent"),
        "x-mailer": msg.get("x-mailer"),
    }

    return observations_dict