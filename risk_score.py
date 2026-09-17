
individual_weights = {
    # SPF
    "spf_failure": 8,
    "spf_softfail": 6,
    "spf_permerror": 6,
    "spf_temperror": 4,
    "spf_none": 3,
    "spf_not_present": 3,
    "spf_could_not_determine": 3,

    # DKIM
    # dkim_failure is handled separately because additional
    # failed signatures are only worth +2 each.
    "dkim_permerror": 6,
    "dkim_temperror": 4,
    "dkim_none": 3,
    "dkim_not_present": 3,
    "dkim_could_not_determine": 3,

    # DMARC
    "dmarc_failure": 15,
    "dmarc_permerror": 6,
    "dmarc_temperror": 4,
    "dmarc_none": 3,
    "dmarc_not_present": 3,
    "dmarc_could_not_determine": 3,

    # Attachments
    "high_risk_extension": 10,
    "macro_enabled_document": 8,
    "archive_attachment": 8,
    "disk_image_attachment": 8,
    "potentially_risky_extension": 8,
    "missing_filename": 2,

    # URLs
    "http_url": 2,
    "ip_address_url": 5,
    "punycode_domain": 5,
    "url_shortener": 4,
    "suspicious_file_link": 12,
    "excessive_subdomains": 3,
    "long_url": 3,
    "userinfo_in_url": 8,
    "missing_hostname": 2,

    # Metadata
    "missing_from": 6,
    "malformed_from": 6,
    "missing_message_id": 3,
    "missing_date": 2,
    "missing_subject": 2,
}


contextual_weights = {
    "from_reply_to_domain_mismatch": 15,
    "multiple_authentication_failures": 10,
    "suspicious_attachment_and_url": 10,
}


def calculate_risk_score(individual_indicators, contextual_indicators):

    total_score = 0
    breakdown = []

    # Prevent the same subtype from being scored repeatedly.
    seen_subtypes = set()

    # DKIM failures are special because multiple failed
    # signatures are allowed to stack.
    dkim_failure_count = 0

    for indicator in individual_indicators:

        subtype = indicator.get("subtype")

        # Handle DKIM failures separately.
        if subtype == "dkim_failure":
            dkim_failure_count += 1
            continue

        # Same subtype only counts once per email.
        if subtype in seen_subtypes:
            continue

        points = individual_weights.get(subtype)

        # Ignore indicators that do not have a scoring rule.
        if points is None:
            continue

        total_score += points

        breakdown.append({
            "subtype": subtype,
            "points": points,
        })

        seen_subtypes.add(subtype)

    # Score definite DKIM failures.
    if dkim_failure_count > 0:

        dkim_points = 8

        if dkim_failure_count > 1:
            dkim_points += (dkim_failure_count - 1) * 2

        total_score += dkim_points

        breakdown.append({
            "subtype": "dkim_failure",
            "count": dkim_failure_count,
            "points": dkim_points,
        })

    seen_contextual_subtypes = set()

    for indicator in contextual_indicators:

        subtype = indicator.get("subtype")

        if subtype in seen_contextual_subtypes:
            continue

        points = contextual_weights.get(subtype)

        if points is None:
            continue

        total_score += points

        breakdown.append({
            "subtype": subtype,
            "points": points,
        })

        seen_contextual_subtypes.add(subtype)

    # Final displayed score cannot exceed 100.
    final_score = min(total_score, 40)

    if final_score <= 10:
        risk_level = "Low"

    elif final_score <= 19:
        risk_level = "Medium"

    elif final_score <= 29:
        risk_level = "High"

    else:
        risk_level = "Critical"

    return {
        "score": final_score,
        "raw_score": total_score,
        "risk_level": risk_level,
        "breakdown": breakdown,
    }