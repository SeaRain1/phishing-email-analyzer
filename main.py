import sys
if len(sys.argv) < 2:
    print("Usage: python main.py <email.eml>")
    sys.exit(1)
from read_email import read_email
from observations import create_dictionary
from individual_analysis.individual_indicators import collect_individual_indicators
from contextual_analysis import analyze_context
from risk_score import calculate_risk_score
from risk_report import generate_risk_report


try:
    email = read_email(sys.argv[1])

except FileNotFoundError as error:
    print(f"Error: {error}")
    sys.exit(1)

except ValueError as error:
    print(f"Error: {error}")
    sys.exit(1)
    

observations = create_dictionary(email)

individual_indicators = collect_individual_indicators(observations)

contextual_indicators = analyze_context(
    observations,
    individual_indicators
)

risk_result = calculate_risk_score(
    individual_indicators,
    contextual_indicators
)

report = generate_risk_report(
    observations,
    individual_indicators,
    contextual_indicators,
    risk_result
)

print(report)


