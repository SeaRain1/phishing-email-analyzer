from individual_analysis.authentication_analysis import analyze_authentication
from individual_analysis.attachment_analysis import analyze_attachments
from individual_analysis.url_analysis import analyze_urls
from individual_analysis.metadata_analysis import analyze_metadata


def collect_individual_indicators(observations):
    # This will become the master list containing
    # every standalone indicator found in the email
    indicators = []

    # Run authentication analysis.
    # extend() adds each returned indicator dictionary
    # individually into the master indicators list.
    indicators.extend(analyze_authentication(observations))

    # Run attachment analysis.
    indicators.extend(analyze_attachments(observations))

    # Run URL analysis.
    indicators.extend(analyze_urls(observations))

    # Run metadata analysis.
    indicators.extend(analyze_metadata(observations))

    # Return one combined list containing indicators
    # from all four individual-analysis modules.
    return indicators