
def generate_risk_report(
    observations,
    individual_indicators,
    contextual_indicators,
    risk_result
):
    lines = []

    lines.append("=" * 60)
    lines.append("PHISHING EMAIL ANALYSIS REPORT")
    lines.append("=" * 60)

    # Basic email information
    lines.append("")
    lines.append("EMAIL INFORMATION")
    lines.append("-" * 60)
    lines.append(f"From: {observations.get('from') or 'Not available'}")
    lines.append(f"To: {observations.get('to') or 'Not available'}")
    lines.append(f"Subject: {observations.get('subject') or 'Not available'}")
    lines.append(f"Date: {observations.get('date') or 'Not available'}")

    # Risk score
    lines.append("")
    lines.append("RISK ASSESSMENT")
    lines.append("-" * 60)
    lines.append(f"Risk Score: {risk_result['score']}/40")
    lines.append(f"Risk Level: {risk_result['risk_level'].upper()}")

    # Score breakdown
    lines.append("")
    lines.append("SCORING BREAKDOWN")
    lines.append("-" * 60)

    breakdown = risk_result.get("breakdown", [])

    if not breakdown:
        lines.append("No scored risk indicators detected.")

    else:
        for item in breakdown:
            subtype = item.get("subtype", "unknown")
            points = item.get("points", 0)
            count = item.get("count")

            readable_name = subtype.replace("_", " ").title()

            if count is not None:
                lines.append(
                    f"- {readable_name} "
                    f"(count: {count}) (+{points})"
                )
            else:
                lines.append(
                    f"- {readable_name} (+{points})"
                )

    # Individual indicators
    lines.append("")
    lines.append("INDIVIDUAL INDICATORS")
    lines.append("-" * 60)

    if not individual_indicators:
        lines.append("None detected.")

    else:
        for indicator in individual_indicators:
            subtype = indicator.get("subtype", "unknown")
            severity = indicator.get("severity", "unknown")

            readable_name = subtype.replace("_", " ").title()

            lines.append(
                f"- {readable_name} "
                f"[Severity: {severity.upper()}]"
            )

    # Contextual indicators
    lines.append("")
    lines.append("CONTEXTUAL INDICATORS")
    lines.append("-" * 60)

    if not contextual_indicators:
        lines.append("None detected.")

    else:
        for indicator in contextual_indicators:
            subtype = indicator.get("subtype", "unknown")
            severity = indicator.get("severity", "unknown")

            readable_name = subtype.replace("_", " ").title()

            lines.append(
                f"- {readable_name} "
                f"[Severity: {severity.upper()}]"
            )

    # Additional observations
    lines.append("")
    lines.append("EMAIL CONTENT SUMMARY")
    lines.append("-" * 60)

    urls = observations.get("urls", [])
    attachments = observations.get("attachments", [])

    lines.append(f"URLs Found: {len(urls)}")
    lines.append(f"Attachments Found: {len(attachments)}")

    lines.append("")
    lines.append("=" * 60)
    lines.append(
        "This score represents detected risk indicators and does not "
        "constitute a definitive determination that an email is malicious."
    )
    lines.append("=" * 60)

    return "\n".join(lines)