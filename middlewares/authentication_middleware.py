from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.middleware import Middleware
from jwt import PyJWTError
from config.db import connect_DB
from bson.objectid import ObjectId
import jwt
import os

# Function to extract the bearer token from Authorization header
def extract_bearer_token(authorization_header: str)-> str:
    if not authorization_header.startswith('Bearer '):
        return None

    return authorization_header.split(' ')[1]


# Custom Middleware function
async def token_validation_dependency(request: Request):
    try:
        # Extract the Authorization header
        authorization: str = request.headers.get('Authorization')

        # If no Authorization header is present, skip the validation
        if not authorization:
            return JSONResponse(status_code = 400, content={"status": "error", "message": "Authorization header not found!"})
        
        # Extract the Bearer token
        token = extract_bearer_token(authorization)
        if not token:
            return JSONResponse(status_code = 400, content={"status": "error", "message": "Invalid token format!"})
        
        
        # Decode JWT Token and extract payload-
        try:
            payload = jwt.decode(token, os.getenv("JWT_SECRET_KEY"), algorithms=["HS256"])
        except PyJWTError:
            return JSONResponse(status_code=401, content={"status": "error", "message": "Invalid or expired token!"})
        
        # Extract the "sub" claim (email)
        email = payload.get("sub")
        if not email:
            return JSONResponse(status_code=401, content={"status": "error", "message": "Token payload missing 'sub' claim!"})
        
        mongodb_client, mongodb = await connect_DB()

        # Get the token collection from the MongoDB
        token_collection = mongodb.get_collection("token")

        # Check if the collection is present in the collection
        is_token_present = await token_collection.find_one({"token": token})

        if is_token_present:
            return JSONResponse(status_code=404, content={"status": "error", "message": "Token is not allowed!"})
        
        # Check if the email exists in the user collection
        user_collection = mongodb.get_collection("user")
        user_exists = await user_collection.find_one({"email": email})
        if not user_exists:
            return JSONResponse(status_code=404, content={"status": "error", "message": "User not found for the provided email!"})
        
        # Proceed without error if everything is fine
        return token
    
    except PyJWTError as e:
        return JSONResponse(status_code=401, content={"status": "error", "message": "Invalid token!"})

    except Exception as e:
        # Handle unexpected errors
        print(e)
        return JSONResponse(status_code=500, content={"status": "error", "message": "An error occurred during token validation!"})



async def token_validation_dependency_for_admin(request: Request):
    try:
        # Extract the Authorization header
        authorization: str = request.headers.get('Authorization')

        # If no Authorization header is present, skip the validation
        if not authorization:
            return JSONResponse(status_code = 400, content={"status": "error", "message": "Authorization header not found!"})
        
        # Extract the Bearer token
        token = extract_bearer_token(authorization)
        if not token:
            return JSONResponse(status_code = 400, content={"status": "error", "message": "Invalid token format!"})
        
        
        # Decode JWT Token and extract payload-
        try:
            payload = jwt.decode(token, os.getenv("JWT_SECRET_KEY"), algorithms=["HS256"])
        except PyJWTError:
            return JSONResponse(status_code=401, content={"status": "error", "message": "Invalid or expired token!"})
        
        # Extract the "sub" claim (email)
        email = payload.get("sub")
        if not email:
            return JSONResponse(status_code=401, content={"status": "error", "message": "Token payload missing 'sub' claim!"})
        
        mongodb_client, mongodb = await connect_DB()

        # Get the token collection from the MongoDB
        token_collection = mongodb.get_collection("token")

        # Check if the collection is present in the collection
        is_token_present = await token_collection.find_one({"token": token})

        if is_token_present:
            return JSONResponse(status_code=404, content={"status": "error", "message": "Token is not allowed!"})
        
        # Check if the email exists in the user collection
        user_collection = mongodb.get_collection("admin")
        user_exists = await user_collection.find_one({"admin_email": email})
        if not user_exists:
            return JSONResponse(status_code=404, content={"status": "error", "message": "Admin not found for the provided email!"})
        
        # Proceed without error if everything is fine
        return token
    
    except PyJWTError as e:
        return JSONResponse(status_code=401, content={"status": "error", "message": "Invalid token!"})

    except Exception as e:
        # Handle unexpected errors
        print(e)
        return JSONResponse(status_code=500, content={"status": "error", "message": "An error occurred during token validation!"})