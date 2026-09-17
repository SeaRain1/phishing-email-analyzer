from pathlib import Path
from email.parser import BytesParser
from email import policy

def read_email(file_path):

    email_path = Path(file_path)

    if not email_path.exists():
        raise FileNotFoundError("Email was not found")
    
    if not email_path.is_file():
        raise ValueError("Expected a file")
    
    if email_path.suffix.lower() != ".eml":
        raise ValueError("Expected a .eml file")
    
    with email_path.open("rb") as file:
        parsed_email = BytesParser(policy=policy.default).parse(file)


    return parsed_email