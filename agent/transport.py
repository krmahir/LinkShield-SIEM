
import requests

from config import API_URL, REQUEST_TIMEOUT


def post_event(event: dict) -> None:
    response = requests.post(
        API_URL,
        json=event,
        timeout=REQUEST_TIMEOUT,
    )

    response.raise_for_status()
