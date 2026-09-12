from openai import AsyncOpenAI

from config import OPENAI_API_KEY


client = AsyncOpenAI(
    api_key=OPENAI_API_KEY
)


async def ask_gpt(text: str):

    response = await client.responses.create(
        model="gpt-5-mini",
        input=text
    )

    return response.output_text
