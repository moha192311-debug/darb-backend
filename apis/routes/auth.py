# api/routes/auth.py
"""
Routes للمصادقة: تسجيل، دخول، خروج، نسيت كلمة المرور
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, EmailStr
from typing import Optional

from data.supabase_client import get_supabase
from apis.dependencies.auth import get_current_user

router = APIRouter(prefix="/auth", tags=["Authentication"])


# =========================
# Models
# =========================
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    username: str
    phone: Optional[str] = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    new_password: str


# =========================
# Register
# =========================
@router.post("/register")
async def register(user_data: RegisterRequest):
    try:
        supabase = get_supabase()

        response = supabase.auth.sign_up({
            "email": user_data.email,
            "password": user_data.password,
            "options": {
                "data": {
                    "username": user_data.username,
                    "phone": user_data.phone or ""
                }
            }
        })

        if not response.user:
            raise HTTPException(status_code=400, detail="Registration failed")

        return {
            "success": True,
            "user_id": response.user.id,
            "email": response.user.email
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# =========================
# Login
# =========================
@router.post("/login")
async def login(credentials: LoginRequest):
    try:
        supabase = get_supabase()

        result = supabase.auth.sign_in_with_password({
            "email": credentials.email,
            "password": credentials.password
        })

        if not result.user or not result.session:
            raise HTTPException(status_code=401, detail="Invalid credentials")

        return {
            "success": True,
            "access_token": result.session.access_token,
            "refresh_token": result.session.refresh_token,
            "user": {
                "id": result.user.id,
                "email": result.user.email,
                "username": result.user.user_metadata.get("username", ""),
                "phone": result.user.user_metadata.get("phone", "")
            }
        }

    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))


# =========================
# Logout
# =========================
@router.post("/logout")
async def logout(current_user=Depends(get_current_user)):
    try:
        supabase = get_supabase()
        supabase.auth.sign_out()

        return {
            "success": True,
            "message": "Logged out successfully"
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# =========================
# Forgot Password
# =========================
@router.post("/forgot-password")
async def forgot_password(request: ForgotPasswordRequest):
    try:
        supabase = get_supabase()
        supabase.auth.reset_password_email(request.email)

        return {
            "success": True,
            "message": "Reset email sent"
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# =========================
# Reset Password
# =========================
@router.post("/reset-password")
async def reset_password(
    request: ResetPasswordRequest,
    current_user=Depends(get_current_user)
):
    try:
        supabase = get_supabase()

        supabase.auth.update_user({
            "password": request.new_password
        })

        return {
            "success": True,
            "message": "Password updated successfully"
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# =========================
# Get current user
# =========================
@router.get("/me")
async def get_me(current_user=Depends(get_current_user)):
    return {
        "id": current_user.id,
        "email": current_user.email,
        "username": current_user.user_metadata.get("username", ""),
        "phone": current_user.user_metadata.get("phone", "")
    }


# =========================
# Google OAuth
# =========================
@router.get("/google")
async def google_login():
    try:
        supabase = get_supabase()
        result = supabase.auth.sign_in_with_oauth({
            "provider": "google"
        })

        return {"url": result.url}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))