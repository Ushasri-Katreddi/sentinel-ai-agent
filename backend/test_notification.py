from app.services.notification_service import NotificationService


notification_service = NotificationService()

result = notification_service.send_test_email()

print("Email sent successfully!")
print(result)