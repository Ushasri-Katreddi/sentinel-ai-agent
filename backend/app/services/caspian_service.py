from caspian_sdk import CommClient

from app.config.settings import settings


class CaspianService:

    def __init__(self):
        self.client = CommClient(
            api_key=settings.CASPIAN_API_KEY,
            base_url=settings.CASPIAN_BASE_URL,
        )

    def send_email_alert(
        self,
        recipient: str,
        subject: str,
        message: str,
    ) -> dict:
        """
        Send a Sentinel AI security alert to a recipient through
        the connected Caspian email channel.
        """

        text = f"{subject}\n\n{message}"

        response = self.client.initiate(
            connection_id=settings.CASPIAN_CONNECTION_ID,
            recipient=recipient,
            text=text,
        )

        return response


caspian_service = CaspianService()