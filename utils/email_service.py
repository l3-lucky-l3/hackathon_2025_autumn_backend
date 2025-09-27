import os
from dotenv import load_dotenv
import smtplib
from email.mime.text import MIMEText
from email.utils import formataddr
import asyncio

load_dotenv()


class EmailService:
    def __init__(self):
        self.smtp_host = os.getenv("SMTP_HOST", "smtp.mail.ru")
        self.smtp_port = int(os.getenv("SMTP_PORT", 465))
        self.smtp_user = os.getenv("SMTP_USER")
        self.smtp_password = os.getenv("SMTP_PASSWORD")
        self.from_email = os.getenv("FROM_EMAIL")
        self.from_name = os.getenv("FROM_NAME", "Хакатон Осень 2025")
        self.verification_code_expire_minutes = os.getenv("VERIFICATION_CODE_EXPIRE_MINUTES", 5)

    def send_email_sync(self, to_email: str, subject: str, message: str, is_html: bool = False):
        """Синхронная отправка email"""
        if not all([self.smtp_host, self.smtp_user, self.smtp_password]):
            print(f"SMTP not configured. Would send email to {to_email}: {subject}")
            return True

        try:
            # Создание сообщения
            if is_html:
                msg = MIMEText(message, 'html', 'utf-8')
            else:
                msg = MIMEText(message, 'plain', 'utf-8')

            # Правильное форматирование отправителя
            msg['From'] = formataddr((self.from_name, self.from_email or self.smtp_user))
            msg['To'] = to_email
            msg['Subject'] = subject

            # Отправка через SMTP_SSL
            with smtplib.SMTP_SSL(self.smtp_host, self.smtp_port) as server:
                server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)

            return True

        except Exception as e:
            print(f"Ошибка при отправке письма: {e}")
            return False

    async def send_verification_email(self, to_email: str, code: str):
        """Отправка email для подтверждения адреса"""
        html_content = f"""
        <html>
        <body>
            <h2>Подтверждение email адреса</h2>
            <p>Ваш код подтверждения: <strong>{code}</strong></p>
            <p>Введите этот код в приложении для завершения регистрации.</p>
            <p>Код действителен в течение {self.verification_code_expire_minutes} минут.</p>
        </body>
        </html>
        """

        # Используем синхронную версию в отдельном потоке
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            self.send_email_sync,
            to_email,
            "Подтверждение email адреса",
            html_content,
            True  # is_html=True
        )

    async def send_password_reset_email(self, to_email: str, code: str):
        """Отправка email для сброса пароля"""
        html_content = f"""
        <html>
        <body>
            <h2>Сброс пароля</h2>
            <p>Ваш код для сброса пароля: <strong>{code}</strong></p>
            <p>Введите этот код в приложении для установки нового пароля.</p>
            <p>Код действителен в течение {self.verification_code_expire_minutes} минут.</p>
        </body>
        </html>
        """

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            self.send_email_sync,
            to_email,
            "Сброс пароля",
            html_content,
            True  # is_html=True
        )

    async def send_text_email(self, to_email: str, subject: str, message: str):
        """Отправка простого текстового письма"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            self.send_email_sync,
            to_email,
            subject,
            message,
            False  # is_html=False
        )
