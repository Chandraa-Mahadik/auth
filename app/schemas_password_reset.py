from pydantic import BaseModel, EmailStr, Field

class PasswordForgotIn(BaseModel):
    email: EmailStr
    app_base_url: str | None = None  # so you can build correct frontend URL

class PasswordResetIn(BaseModel):
    token: str = Field(min_length=10)
    new_password: str = Field(min_length=8, max_length=256)

class PasswordChangeIn(BaseModel):
    current_password: str = Field(min_length=1)
    new_password: str = Field(min_length=8, max_length=256)
