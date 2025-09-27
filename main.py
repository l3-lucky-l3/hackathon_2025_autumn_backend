import os
from fastapi import FastAPI, Depends, HTTPException, status, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr, validator
from datetime import datetime, timedelta
from database import get_db
from models import User, EmailVerificationCode, PasswordResetCode, BlacklistedToken
from auth import (
    get_password_hash, verify_password, create_access_token,
    create_refresh_token, verify_token, generate_verification_code,
    get_current_user
)
from utils.email_service import EmailService
from dotenv import load_dotenv

load_dotenv()

VERIFICATION_CODE_EXPIRE_MINUTES = int(os.getenv("VERIFICATION_CODE_EXPIRE_MINUTES", 5))

app = FastAPI(
    title="Flutter App API",
    description="Backend API для мобильного приложения, хакатон Осень 2025",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()
email_service = EmailService()


# Pydantic модели
class UserBase(BaseModel):
    email: EmailStr


class UserCreate(UserBase):
    password: str

    @validator('password')
    def password_strength(cls, v):
        if len(v) < 6:
            raise ValueError('Пароль должен содержать минимум 6 символов')
        return v


class UserResponse(UserBase):
    id: int
    email_verified: bool

    class Config:
        from_attributes = True


class Token(BaseModel):
    access: str
    refresh: str
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class EmailVerificationRequest(BaseModel):
    email: EmailStr
    code: str


class EmailVerificationAndLoginRequest(BaseModel):
    email: EmailStr
    code: str
    password: str


class PasswordResetRequest(BaseModel):
    email: EmailStr
    code: str
    password: str


class PasswordResetConfirm(BaseModel):
    email: EmailStr


class MessageResponse(BaseModel):
    message: str


# Роуты
@app.post("/api/users/register/", response_model=UserResponse)
async def register(
        user_data: UserCreate,
        background_tasks: BackgroundTasks,
        db: Session = Depends(get_db)
):
    # Проверяем, существует ли пользователь
    existing_user = db.query(User).filter(
        User.email == user_data.email
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Пользователь с таким email уже существует"
        )

    # Генерируем код подтверждения
    code = generate_verification_code()
    expires_at = datetime.utcnow() + timedelta(minutes=VERIFICATION_CODE_EXPIRE_MINUTES)

    # Пытаемся отправить письмо СИНХРОННО (не в фоне)
    try:
        # Синхронная отправка для проверки
        await email_service.send_verification_email(user_data.email, code)
    except Exception as e:
        # Логируем ошибку для отладки
        print(f"Ошибка отправки email: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Не удалось отправить письмо подтверждения. Проверьте email адрес."
        )

    # Если письмо отправлено успешно, создаем пользователя
    try:
        hashed_password = get_password_hash(user_data.password)
        db_user = User(
            email=user_data.email,
            password_hash=hashed_password,
            email_verified=False
        )

        db.add(db_user)

        # Создаем запись с кодом подтверждения
        verification_code = EmailVerificationCode(
            email=user_data.email,
            code=code,
            expires_at=expires_at
        )
        db.add(verification_code)

        db.commit()
        db.refresh(db_user)

        return UserResponse(
            id=db_user.id,
            email=db_user.email,
            email_verified=db_user.email_verified
        )

    except Exception as e:
        # Если произошла ошибка при создании пользователя после успешной отправки письма
        db.rollback()
        print(f"Ошибка при создании пользователя после отправки письма: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Произошла ошибка при создании пользователя"
        )


@app.post("/api/users/verify-and-login/", response_model=Token)
async def verify_and_login(
        request_data: EmailVerificationAndLoginRequest,
        db: Session = Depends(get_db)
):
    # Верификация email
    verification_code = db.query(EmailVerificationCode).filter(
        EmailVerificationCode.email == request_data.email,
        EmailVerificationCode.code == request_data.code,
        EmailVerificationCode.used == False,
        EmailVerificationCode.expires_at > datetime.utcnow()
    ).first()

    if not verification_code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Неверный или просроченный код подтверждения"
        )

    user = db.query(User).filter(User.email == request_data.email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Пользователь не найден"
        )

    # Проверяем пароль
    if not verify_password(request_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверный пароль"
        )

    # Обновляем статус подтверждения
    user.email_verified = True
    verification_code.used = True
    db.commit()
    db.refresh(user)

    # Создаем токены
    access_token = create_access_token(data={"sub": str(user.id)})
    refresh_token = create_refresh_token(data={"sub": str(user.id)})

    return Token(access=access_token, refresh=refresh_token)


@app.post("/api/users/resend-verification/", response_model=MessageResponse)
async def resend_verification(
        email_data: PasswordResetConfirm,
        background_tasks: BackgroundTasks,
        db: Session = Depends(get_db)
):
    user = db.query(User).filter(
        User.email == email_data.email
    ).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Пользователь не найден"
        )

    if user.email_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email уже подтвержден"
        )

    # Генерируем новый код
    code = generate_verification_code()
    expires_at = datetime.utcnow() + timedelta(minutes=VERIFICATION_CODE_EXPIRE_MINUTES)

    verification_code = EmailVerificationCode(
        email=email_data.email,
        code=code,
        expires_at=expires_at
    )

    db.add(verification_code)
    db.commit()

    # Отправляем email
    background_tasks.add_task(
        email_service.send_verification_email,
        email_data.email,
        code
    )

    return MessageResponse(message="Код подтверждения отправлен")


@app.post("/api/users/token/", response_model=Token)
async def login(login_data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(
        User.email == login_data.email
    ).first()

    if not user or not verify_password(login_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверный email или пароль"
        )

    if not user.email_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Требуется подтверждение email",
            headers={"requires_verification": "true"}
        )

    access_token = create_access_token(data={"sub": str(user.id)})
    refresh_token = create_refresh_token(data={"sub": str(user.id)})

    return Token(access=access_token, refresh=refresh_token)


@app.post("/api/users/token/refresh/", response_model=Token)
async def refresh_token(
        refresh_data: dict,
        db: Session = Depends(get_db)
):
    refresh_token = refresh_data.get("refresh")
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Refresh token обязателен"
        )

    payload = verify_token(refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверный refresh token"
        )

    user_id = payload.get("sub")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Пользователь не найден"
        )

    # Проверяем, не в черном списке ли токен
    blacklisted = db.query(BlacklistedToken).filter(
        BlacklistedToken.token == refresh_token
    ).first()
    if blacklisted:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token revoked"
        )

    new_access_token = create_access_token(data={"sub": str(user.id)})
    new_refresh_token = create_refresh_token(data={"sub": str(user.id)})

    return Token(access=new_access_token, refresh=new_refresh_token)


@app.post("/api/users/token/blacklist/", response_model=MessageResponse)
async def blacklist_token(
        token_data: dict,
        db: Session = Depends(get_db)
):
    refresh_token = token_data.get("refresh")
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Refresh token обязателен"
        )

    # Добавляем токен в черный список
    blacklisted_token = BlacklistedToken(token=refresh_token)
    db.add(blacklisted_token)
    db.commit()

    return MessageResponse(message="Token успешно отозван")


@app.post("/api/users/reset-password/request/", response_model=MessageResponse)
async def reset_password_request(
        email_data: PasswordResetConfirm,
        background_tasks: BackgroundTasks,
        db: Session = Depends(get_db)
):
    user = db.query(User).filter(
        User.email == email_data.email
    ).first()

    if user:
        # Генерируем код сброса
        code = generate_verification_code()
        expires_at = datetime.utcnow() + timedelta(minutes=VERIFICATION_CODE_EXPIRE_MINUTES)

        reset_code = PasswordResetCode(
            email=email_data.email,
            code=code,
            expires_at=expires_at
        )

        db.add(reset_code)
        db.commit()

        # Отправляем email
        background_tasks.add_task(
            email_service.send_password_reset_email,
            email_data.email,
            code
        )

    # Всегда возвращаем успех для безопасности
    return MessageResponse(
        message="Если email зарегистрирован, код сброса пароля будет отправлен"
    )


@app.post("/api/users/reset-password/confirm/", response_model=MessageResponse)
async def reset_password_confirm(
        reset_data: PasswordResetRequest,
        db: Session = Depends(get_db)
):
    # Находим код сброса
    reset_code = db.query(PasswordResetCode).filter(
        PasswordResetCode.email == reset_data.email,
        PasswordResetCode.code == reset_data.code,
        PasswordResetCode.used == False,
        PasswordResetCode.expires_at > datetime.utcnow()
    ).first()

    if not reset_code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Неверный или просроченный код сброса"
        )

    # Находим пользователя
    user = db.query(User).filter(
        User.email == reset_data.email
    ).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Пользователь не найден"
        )

    # Обновляем пароль
    user.password_hash = get_password_hash(reset_data.password)
    reset_code.used = True
    db.commit()

    return MessageResponse(message="Пароль успешно изменен")


@app.get("/api/users/profile/", response_model=UserResponse)
async def get_user_profile(current_user: User = Depends(get_current_user)):
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        email_verified=current_user.email_verified
    )


@app.put("/api/users/profile/", response_model=UserResponse)
async def update_user_profile(
        user_data: UserBase,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    # Проверяем уникальность email
    if user_data.email != current_user.email:
        existing_user = db.query(User).filter(
            User.email == user_data.email
        ).first()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Пользователь с таким email уже существует"
            )

    # Обновляем данные
    current_user.email = user_data.email
    current_user.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(current_user)

    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        email_verified=current_user.email_verified
    )


# Health check
@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
