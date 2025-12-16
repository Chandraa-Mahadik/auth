from pydantic import BaseModel, EmailStr, HttpUrl

class LoginIn(BaseModel):
    email: EmailStr
    password: str
    app_base_url: HttpUrl | None = None

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
