# Authentication Guide

## Overview

The Threat Intel Dashboard now includes a client-side authentication system for the React frontend. This is a **demo implementation** using localStorage and should be replaced with proper backend authentication in production.

---

## Features

✅ **Login/Signup Pages**: Beautiful, modern authentication UI  
✅ **Protected Routes**: Dashboard requires authentication  
✅ **User Session**: Persistent login across page refreshes  
✅ **Logout Functionality**: Secure session termination  
✅ **Error Handling**: User-friendly error messages  

---

## How to Use

### 1. Access the Login Page

Navigate to: **http://localhost:3000/login**

### 2. Create an Account

1. Click "Sign Up" at the bottom of the login form
2. Enter your email address
3. Create a password (minimum 6 characters)
4. Click "Sign Up"
5. You'll be prompted to sign in with your new credentials

### 3. Sign In

1. Enter your email and password
2. Click "Sign In"
3. You'll be redirected to the main dashboard

### 4. Using the Dashboard

Once logged in, you'll see:
- Your email address in the top-right corner
- A "Logout" button to end your session
- Full access to all threat intelligence features

### 5. Logout

Click the "Logout" button in the top-right corner to end your session.

---

## Security Notes

### ⚠️ Current Implementation (Demo Only)

The current authentication system uses:
- **localStorage** for storing user credentials and session state
- **Plain text passwords** (NOT hashed)
- **Client-side only** validation

### 🔒 Production Recommendations

For a production deployment, you should implement:

1. **Backend Authentication**:
   ```python
   # FastAPI example with JWT
   from fastapi import FastAPI, Depends, HTTPException
   from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
   from passlib.context import CryptContext
   import jwt
   
   security = HTTPBearer()
   pwd_context = CryptContext(schemes=["bcrypt"])
   
   @app.post("/auth/login")
   async def login(credentials: LoginRequest):
       # Verify user credentials
       user = verify_user(credentials.email, credentials.password)
       if not user:
           raise HTTPException(status_code=401, detail="Invalid credentials")
       
       # Generate JWT token
       token = jwt.encode({"sub": user.email}, SECRET_KEY)
       return {"access_token": token, "token_type": "bearer"}
   ```

2. **Password Hashing**:
   - Use bcrypt, Argon2, or PBKDF2
   - Never store plain text passwords
   - Salt passwords before hashing

3. **Secure Token Storage**:
   - Use httpOnly cookies for tokens
   - Implement CSRF protection
   - Set appropriate cookie SameSite policies

4. **Session Management**:
   - Implement token expiration (15-60 minutes)
   - Use refresh tokens for extended sessions
   - Implement token blacklisting for logout

5. **HTTPS Only**:
   - Always use HTTPS in production
   - Set Secure flag on cookies
   - Implement HSTS headers

---

## Integration with Backend

To integrate with the FastAPI backend:

### Backend Setup

1. **Install dependencies**:
   ```bash
   pip install python-jose[cryptography] passlib[bcrypt] python-multipart
   ```

2. **Create auth endpoints**:
   ```python
   # infosecwriteups/auth.py
   from fastapi import APIRouter, HTTPException
   from pydantic import BaseModel
   from passlib.context import CryptContext
   
   router = APIRouter()
   pwd_context = CryptContext(schemes=["bcrypt"])
   
   class SignupRequest(BaseModel):
       email: str
       password: str
   
   class LoginRequest(BaseModel):
       email: str
       password: str
   
   @router.post("/auth/signup")
   async def signup(request: SignupRequest):
       # Check if user exists
       # Hash password
       # Store in database
       # Return success
       pass
   
   @router.post("/auth/login")
   async def login(request: LoginRequest):
       # Verify credentials
       # Generate JWT token
       # Return token
       pass
   ```

3. **Update frontend** to call backend API:
   ```typescript
   // frontend/src/app/login/page.tsx
   async function handleLogin() {
       const response = await axios.post('http://127.0.0.1:8000/auth/login', {
           email,
           password
       })
       
       // Store JWT token
       localStorage.setItem('token', response.data.access_token)
       
       // Redirect to dashboard
       router.push('/')
   }
   ```

---

## File Structure

```
frontend/
├── src/
│   ├── app/
│   │   ├── login/
│   │   │   └── page.tsx          # Login/Signup page
│   │   └── page.tsx               # Protected dashboard
│   └── contexts/
│       └── AuthContext.tsx        # (Optional) Auth state management
```

---

## API Endpoints (To Implement)

### POST /auth/signup
Create a new user account

**Request**:
```json
{
  "email": "user@example.com",
  "password": "securepassword123"
}
```

**Response**:
```json
{
  "message": "User created successfully",
  "email": "user@example.com"
}
```

### POST /auth/login
Authenticate a user

**Request**:
```json
{
  "email": "user@example.com",
  "password": "securepassword123"
}
```

**Response**:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "user": {
    "email": "user@example.com"
  }
}
```

### POST /auth/logout
Invalidate user session

**Headers**:
```
Authorization: Bearer <token>
```

**Response**:
```json
{
  "message": "Logged out successfully"
}
```

---

## Testing

### Test Accounts (Demo Mode)

You can create any test account with the signup form. Examples:

- Email: `admin@example.com`, Password: `admin123`
- Email: `analyst@soc.com`, Password: `threat123`
- Email: `test@test.com`, Password: `test1234`

### Clear Authentication Data

To reset authentication:

1. Open browser DevTools (F12)
2. Go to "Application" → "Local Storage"
3. Delete all items starting with `user_`, `currentUser`, `isAuthenticated`

Or run in browser console:
```javascript
localStorage.clear()
```

---

## Troubleshooting

### Can't Login After Signup

**Issue**: "User not found" error  
**Solution**: Make sure you clicked "Sign Up" first, not "Sign In"

### Stuck on Loading Screen

**Issue**: Dashboard shows "Loading..." indefinitely  
**Solution**: Clear localStorage and try again

### Redirected to Login Immediately

**Issue**: Can't access dashboard  
**Solution**: Your session may have expired. Login again

### Password Requirements

**Minimum Length**: 6 characters  
**Recommended**: Use a strong password with letters, numbers, and symbols

---

## Next Steps

1. ✅ Implement backend authentication endpoints
2. ✅ Add password hashing with bcrypt/Argon2
3. ✅ Implement JWT token generation and validation
4. ✅ Add refresh token mechanism
5. ✅ Implement proper session management
6. ✅ Add password reset functionality
7. ✅ Implement 2FA (Two-Factor Authentication)
8. ✅ Add rate limiting to prevent brute force
9. ✅ Log authentication events for security audit

---

**For production deployment, consult with a security professional and follow OWASP authentication best practices.**
