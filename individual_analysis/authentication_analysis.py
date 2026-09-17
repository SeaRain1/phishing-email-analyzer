# This file is responsible for storing and tracking the invividual indicators found from the attachment, authentication, and URL analysis files. 
# This file delivers individual indicators to the contextual analysis file to be further analyzed for specific patterns.

def analyze_authentication(observations):

    indicators = []

    authentication = observations.get("authentication", {})

    # Check SPF

    spf = authentication.get("spf")

    if spf is None:
        indicators.append({
            "type": "authentication",
            "subtype": "spf_not_present",
            "value": None,
            "severity": "low",
        })

    else:
        spf_result = spf.get("result")

        if spf_result is None:
            indicators.append({
                "type": "authentication",
                "subtype": "spf_could_not_determine",
                "value": None,
                "severity": "low",
            })

        elif spf_result.lower() == "none":
            indicators.append({
                "type": "authentication",
                "subtype": "spf_none",
                "value": spf_result,
                "severity": "low",
            })

        elif spf_result.lower() == "fail":
            indicators.append({
                "type": "authentication",
                "subtype": "spf_failure",
                "value": spf_result,
                "severity": "high",
            })

        elif spf_result.lower() == "softfail":
            indicators.append({
                "type": "authentication",
                "subtype": "spf_softfail",
                "value": spf_result,
                "severity": "medium",
            })

        elif spf_result.lower() == "temperror":
            indicators.append({
                "type": "authentication",
                "subtype": "spf_temperror",
                "value": spf_result,
                "severity": "low",
            })

        elif spf_result.lower() == "permerror":
            indicators.append({
                "type": "authentication",
                "subtype": "spf_permerror",
                "value": spf_result,
                "severity": "medium",
            })

    # Check DKIM

    dkim = authentication.get("dkim")

    if not dkim:
        indicators.append({
            "type": "authentication",
            "subtype": "dkim_not_present",
            "value": None,
            "severity": "low",
        })

    else:
        for signature in dkim:

            dkim_result = signature.get("result")

            if dkim_result is None:
                indicators.append({
                    "type": "authentication",
                    "subtype": "dkim_could_not_determine",
                    "value": None,
                    "severity": "low",
                    "domain": signature.get("domain"),
                    "selector": signature.get("selector"),
                })

            elif dkim_result.lower() == "none":
                indicators.append({
                    "type": "authentication",
                    "subtype": "dkim_none",
                    "value": dkim_result,
                    "severity": "low",
                    "domain": signature.get("domain"),
                    "selector": signature.get("selector"),
                })
            
            elif dkim_result.lower() == "fail":
                indicators.append({
                    "type": "authentication",
                    "subtype": "dkim_failure",
                    "value": dkim_result,
                    "severity": "high",
                    "domain": signature.get("domain"),
                    "selector": signature.get("selector"),
                })

            elif dkim_result.lower() == "temperror":
                indicators.append({
                    "type": "authentication",
                    "subtype": "dkim_temperror",
                    "value": dkim_result,
                    "severity": "low",
                    "domain": signature.get("domain"),
                    "selector": signature.get("selector"),
                })

            elif dkim_result.lower() == "permerror":
                indicators.append({
                    "type": "authentication",
                    "subtype": "dkim_permerror",
                    "value": dkim_result,
                    "severity": "medium",
                    "domain": signature.get("domain"),
                    "selector": signature.get("selector"),
                })

    # DMARC

    dmarc = authentication.get("dmarc")

    if dmarc is None:
        indicators.append({
            "type": "authentication",
            "subtype": "dmarc_not_present",
            "value": None,
            "severity": "low",
        })

    else:
        dmarc_result = dmarc.get("result")

        if dmarc_result is None:
            indicators.append({
                "type": "authentication",
                "subtype": "dmarc_could_not_determine",
                "value": None,
                "severity": "low",
            })

        elif dmarc_result.lower() == "none":
            indicators.append({
                "type": "authentication",
                "subtype": "dmarc_none",
                "value": dmarc_result,
                "severity": "low",
            })

        elif dmarc_result.lower() == "fail":
            indicators.append({
                "type": "authentication",
                "subtype": "dmarc_failure",
                "value": dmarc_result,
                "severity": "high",
            })

        elif dmarc_result.lower() == "temperror":
            indicators.append({
                "type": "authentication",
                "subtype": "dmarc_temperror",
                "value": dmarc_result,
                "severity": "low",
            })

        elif dmarc_result.lower() == "permerror":
            indicators.append({
                "type": "authentication",
                "subtype": "dmarc_permerror",
                "value": dmarc_result,
                "severity": "medium",
            })

    return indicators