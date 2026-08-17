from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.services.caspian_service import caspian_service


router = APIRouter(
    prefix="/caspian",
    tags=["Caspian"],
)


class EmailRequest(BaseModel):
    recipient: str
    message: str
    subject: str = "Sentinel AI Security Alert"


@router.post("/send-email")
def send_email_message(request: EmailRequest):

    try:
        response = caspian_service.send_email_alert(
            recipient=request.recipient,
            subject=request.subject,
            message=request.message,
        )

        return {
            "success": True,
            "message": "Security alert initiated successfully",
            "caspian_response": response,
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=str(e),
        )