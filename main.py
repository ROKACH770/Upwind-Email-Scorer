from fastapi import FastAPI
from pydantic import BaseModel #improves security by validating incoming data
# and ensuring it adheres to the expected format

# Initialize the FastAPI application
app = FastAPI(title="Email Scorer API")


# Define the structure of the expected incoming request
class EmailData(BaseModel):
    sender: str
    subject: str
    body: str


# Define the endpoint that will handle the scoring logic
@app.post("/analyze")
def analyze_email(email: EmailData):
    # TODO: Implement actual security analysis logic here

    # For now, return a mock response matching the required product format
    return {
        "score": 85,
        "verdict": "Suspicious",
        "reasoning": "The sender domain is not recognized and requires further investigation."
    }