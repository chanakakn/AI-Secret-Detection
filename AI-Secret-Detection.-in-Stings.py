import re
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB

# Known secret patterns
patterns = [
    r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",  # Email addresses
    r"\b\d{3}-\d{2}-\d{4}\b",  # Social Security numbers
    r"\b\d{16}\b",  # Credit card numbers
    r"\b[A-Fa-f0-9]{32}\b",  # MD5 hashes
    r"\b[^\s]{30,}\b",  # API Keys
    r"\b[^\s]{8,}\b",  # Passwords
    r"\b[^\s]{40,}\b",  # Access Tockens
    r"\b-----BEGIN\s(.*\s)?PRIVATE\sKEY-----\b",  # SSH private keys
    r"\bAKIA[0-9A-Z]{16}\b",  # AWS access keys
    r"\b[0-9a-zA-Z/+]{40}\b",  # AWS secret access keys
    r"\bAIza[0-9A-Za-z_-]{35}\b",  # Google API keys
    r"\b[xoxa|xoxt]-\d{12}-\d{12}-[a-z0-9]{32}\b",  # Slack tokens
    r"\b-----BEGIN\sRSA\sPRIVATE\sKEY-----\b",  # RSA private keys
    r"\b[A-Za-z0-9/+]{342}\b",  # AWS session tokens
    r"^(ssh-[dr]s[as]\s.*|[a-z]+-[a-z0-9]+)\s+[a-zA-Z0-9+/]+[=]{0,2}(\s+\S+)?$",  # SSH public keys
    r"\b[0-9a-f]{32}\b",  # OAuth access tokens
    r"\b[A-Za-z0-9]{32,}\b",  # Private API keys
    r"\b[0-9a-zA-Z_-]{24}\b",  # Bitbucket access tokens
    r"\b[0-9a-zA-Z_]{39}-[0-9a-zA-Z_]{8}\b",  # Google Cloud Platform (GCP) API keys
    r"\bAC[a-z0-9]{32}\b",  # Twilio account SID and auth tokens
    r"\b[a-z0-9]{32}\b",  # Twilio account SID and auth tokens
    r"\bxoxb-\d{12}-\d{12}-[a-z0-9]{24}\b",  # Slack bot user OAuth tokens
    r"\beyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b",  # JWT tokens
    r"\b[A-Za-z0-9+/]{88}==\b",  # Microsoft Azure Storage account keys
    r"\b[0-9a-zA-Z]{40}\b",  # GitHub personal access tokens
    r"\bhttps://hooks.slack.com/services/[A-Z0-9]{10}/[A-Z0-9]{10}/[A-Za-z0-9]+\b",  # Slack webhook URLs
    r"\bEAACEdEose0cBA[0-9A-Za-z]+[=]*\b",  # Facebook Access Tokens
    r"\b-----BEGIN\sPGP\sPRIVATE\sKEY\sBLOCK-----\n(?:[a-zA-Z0-9+/=\n]+)+\n-----END\sPGP\sPRIVATE\sKEY\sBLOCK-----\b",  # PGP private keys
    r"\bsq0atp-[0-9A-Za-z_-]{22}\b",  # Square OAuth tokens
    r"\b[0-9a-f]{64}\b",  # Docker Registry authentication tokens
    # Add more secret patterns here
]

# Train the model on known secret patterns
vectorizer = CountVectorizer(token_pattern=r'\b\w+\b', lowercase=False)
X = vectorizer.fit_transform(patterns)
y = ['secret'] * len(patterns)
clf = MultinomialNB().fit(X, y)

# Detect potential secrets in code
def detect_secrets(code):
    matches = []
    for pattern in patterns:
        regex = re.compile(pattern, re.IGNORECASE)
        for match in regex.findall(code):
            matches.append(match)
    if matches:
        X_test = vectorizer.transform(matches)
        y_pred = clf.predict(X_test)
        return [match for match, label in zip(matches, y_pred) if label == 'secret']
    else:
        return []

# Example usage
code = '''
password = "abc@1234"
api_key = "ils-GAF1vxxxxxxxxxxx43xx3hghffhgxcccccccfhfFJxBg1cxxxxxxxLTFvwOKCxxxT3xxxxxxBlbk1I5xxxac8"
password = "xxxxxxxxxx@gmail.com
'''
secrets = detect_secrets(code)
print(secrets)  
