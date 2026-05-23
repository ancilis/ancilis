from openai import OpenAI


def intake_note(patient_id: str) -> str:
    client = OpenAI()
    response = client.responses.create(
        model="gpt-4.1-mini",
        input=f"Summarize intake details for patient {patient_id}.",
    )
    return response.output_text
