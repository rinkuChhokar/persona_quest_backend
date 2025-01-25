from fastapi import FastAPI, Depends, Request, Query
from fastapi.responses import JSONResponse
from config.db import connect_DB
from models.user_model import UserModel
from models.user_login_model import UserLoginModel
from models.admin_login_model import AdminLoginModel
from fastapi.middleware.cors import CORSMiddleware
import bcrypt
import jwt
import os
from datetime import datetime, timedelta
from middlewares.authentication_middleware import token_validation_dependency
from middlewares.authentication_middleware import token_validation_dependency_for_admin
from dotenv import load_dotenv
load_dotenv()
import cloudinary
from cloudinary import CloudinaryImage
import cloudinary.uploader
import cloudinary.api
import json
from bson import ObjectId
import time
import traceback

config = cloudinary.config(secure=True)

app = FastAPI(debug=True)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins (can specify specific origins)
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods (GET, POST, etc.)
    allow_headers=["*"],  # Allow all headers
)



@app.on_event("startup")
async def db_init():
    app.mongodb_client, app.mongodb = await connect_DB()
    print("Database connected!")

@app.on_event("shutdown")
async def shutdown_db_client():
    app.mongodb_client.close()
    print("Database connection closed!")

# Function to return the collection from mongodb
def get_collection(collection_name: str):
    return app.mongodb.get_collection(collection_name)

# Function to generate hash password
def hash_password(password: str):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    return hashed

# Function to verify password using bcrypt
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))


# Function to create JWT token of user
def generate_jwt_token(email: str)-> str:
    secret_key = os.getenv("JWT_SECRET_KEY")
    expiration = datetime.utcnow() + timedelta(days=365)
    token = jwt.encode({"sub":email, "exp":expiration}, secret_key, algorithm="HS256")
    return token

@app.get("/")
def read_root():
    return {"message": "Welcome to FastAPI!"}

# Endpoint for registering new users
@app.post("/api/v1/user/user-register")
async def register_user(user: UserModel):
    try:
        print("user->",user)     
        user_collection = get_collection("user")   
        email = user.email
        is_user_already_present = await user_collection.find_one({"email":email})

        # Check if user already exists
        if is_user_already_present is not None:
            return JSONResponse(status_code=200, content={"status": "error", "message": "This email is already present!"})

        else:
            hashed_password = hash_password(user.password)

            user_data = user.dict()
            user_data['password'] = hashed_password

            # Insert the new user into database
            result = await user_collection.insert_one(user_data)

            # # Create JWT token for newly created user
            # token = generate_jwt_token(user.email)

            return JSONResponse(status_code=200, content={"status": "success", "message": "User added successfully!", "user_id": str(result.inserted_id)})
        
    except Exception as e:
        print(e)
        return JSONResponse(status_code=400, content={"status": "error"})

# Endpoint for lpgin users
@app.post("/api/v1/user/user-login")
async def login_user(user: UserLoginModel):
    try:
        print("user->",user)     
        user_collection = get_collection("user")   
        email = user.email
        is_user_already_present = await user_collection.find_one({"email":email})

        # Check if user already exists
        if is_user_already_present is None:
            return JSONResponse(status_code=200, content={"status": "error", "message": "User not found!"})

        else:
            # Verify the password using bcrypt
            stored_password = is_user_already_present.get("password")
            if not verify_password(user.password, stored_password):
                return JSONResponse(status_code=401, content={"status": "error", "message": "Incorrect password!"})

            # Create JWT token for newly created user
            token = generate_jwt_token(is_user_already_present.get("email"))

            return JSONResponse(status_code=200, content={"status": "success", "message": "User logged in successfully!", "token": token})
        
    except Exception as e:
        print(e)
        return JSONResponse(status_code=400, content={"status": "error"})


@app.post("/api/v1/user/user-logout", dependencies=[Depends(token_validation_dependency)])
async def user_logout(request: Request):
    try:
        data = await request.json()
        token = data["token"]
        print(token)
        if token is None or token == "":
            return JSONResponse(status_code=200, content={"status": "error", "message": "Token not found!"})
        
        token_collection = get_collection("token")
        is_token_present = await token_collection.find_one({"token": token})  
        if is_token_present:
            return JSONResponse(status_code=200, content={"status": "error", "message": "Token is not allowed!"})
        
        await token_collection.insert_one({"token": token})
        return JSONResponse(status_code=200, content={"status": "success", "message": "User logged out successfully!"})
    
    except Exception as e:
        print(e)
        return JSONResponse(status_code=400, content={"status": "errro", "message": "Error occured!"})


@app.get("/api/v1/admin/admin-register")
async def register_admin(
    admin_name: str = Query(..., description="Admin's name"),
    admin_email: str = Query(..., description="Admin's email"),
    admin_password: str = Query(..., description="Admin's password")):
    try:
        # http://127.0.0.1:8000/api/v1/admin-register?admin_name=admin&admin_email=admin@personaquest.com&admin_password=admin123
        admin_collection = get_collection("admin")   
        email = admin_email
        is_user_already_present = await admin_collection.find_one({"admin_email":email})

        # Check if user already exists
        if is_user_already_present is not None:
            return JSONResponse(status_code=200, content={"status": "error", "message": "This email is already present!"})

        else:
            hashed_password = hash_password(admin_password)

            user_data = {"admin_name":admin_name, "admin_email":admin_email, "admin_password":admin_password}
            user_data['admin_password'] = hashed_password

            # Insert the new user into database
            result = await admin_collection.insert_one(user_data)

            # # Create JWT token for newly created user
            # token = generate_jwt_token(user.email)

            return JSONResponse(status_code=200, content={"status": "success", "message": "Admin added successfully!", "admin_id": str(result.inserted_id)})
        
    except Exception as e:
        print(e)
        return JSONResponse(status_code=400, content={"status": "error"})


# Endpoint for admin login
@app.post("/api/v1/admin/admin-login")
async def admin_login(user: AdminLoginModel):
    try:
        print("user->",user)   
        admin_collection = get_collection("admin")   
        email = user.admin_email
        is_user_already_present = await admin_collection.find_one({"admin_email":email})

        # Check if user already exists
        if is_user_already_present is None:
            return JSONResponse(status_code=200, content={"status": "error", "message": "Admin not found!"})

        else:
            # Verify the password using bcrypt
            stored_password = is_user_already_present.get("admin_password")
            if not verify_password(user.admin_password, stored_password):
                return JSONResponse(status_code=401, content={"status": "error", "message": "Incorrect password!"})

            # Create JWT token for newly created user
            token = generate_jwt_token(is_user_already_present.get("admin_email"))

            return JSONResponse(status_code=200, content={"status": "success", "message": "Admin logged in successfully!", "token": token})
        
    except Exception as e:
        print(e)
        return JSONResponse(status_code=400, content={"status": "error"})


@app.post("/api/v1/admin/admin-logout", dependencies=[Depends(token_validation_dependency_for_admin)])
async def admin_logout(request: Request):
    try:
        data = await request.json()
        token = data["token"]
        print(token)
        if token is None or token == "":
            return JSONResponse(status_code=200, content={"status": "error", "message": "Token not found!"})
        
        token_collection = get_collection("token")
        is_token_present = await token_collection.find_one({"token": token})  
        if is_token_present:
            return JSONResponse(status_code=200, content={"status": "error", "message": "Token is not allowed!"})
        
        await token_collection.insert_one({"token": token})
        return JSONResponse(status_code=200, content={"status": "success", "message": "Admin logged out successfully!"})
    
    except Exception as e:
        print(e)
        return JSONResponse(status_code=400, content={"status": "errro", "message": "Error occured!"})


# Endpoint for adding new test-
@app.post("/api/v1/admin/add-new-test", dependencies=[Depends(token_validation_dependency_for_admin)])
async def add_new_test(request: Request):
    try:
        data = await request.json()
        print("data->",data["test_slug"].split(" "))
        slug_name_of_test = data["test_slug"].split(" ")
        updated_slug_name = ""
        if(len(slug_name_of_test) > 1):
            updated_slug_name = "-".join(slug_name_of_test)
        else:
            updated_slug_name = data["test_slug"]

        personality_test_collection = get_collection("personality_test")
        all_personality_tests = await personality_test_collection.find({}).to_list(length=None)
        if(len(all_personality_tests) > 0):
            for test in all_personality_tests:
                if(test["test_slug"] == updated_slug_name):
                    return JSONResponse(status_code=400, content={"status": "errro", "message": "Slug name already exist!"})


        # Upload the image to Cloudinary
        upload_response = cloudinary.uploader.upload(data["image"], unique_filename=True, overwrite=True)

        # Extract the URL from the upload response
        srcURL = upload_response.get("secure_url")
        print(srcURL)

        
        user_data = {
            "test_name": data["test_name"],
            "test_slug": updated_slug_name,
            "image": srcURL,
            "questions": data["questions"],
            "added_at": time.time(),
            "updated_at": None,
            "deleted_at": None
        }

        await personality_test_collection.insert_one(user_data)
        # Fetch all personality tests as a list
        all_personality_tests = await personality_test_collection.find({}).to_list(length=None)
        for test in all_personality_tests:
            test["_id"] = str(test["_id"])  # Convert ObjectId to string

        return JSONResponse(status_code=200, content={"status": "success", "message": "Personality test added successfully!!", "all_personality_tests": all_personality_tests})

    except Exception as e:
        print(e)
        return JSONResponse(status_code=400, content={"status": "errro", "message": "Error occured!"})


@app.get("/api/v1/admin/fetch-all-tests", dependencies=[Depends(token_validation_dependency_for_admin)])
async def fetch_all_tests(request: Request):
    try:
        personality_test_collection = get_collection("personality_test")

        # Fetch all personality tests as a list
        all_personality_tests = await personality_test_collection.find({}).to_list(length=None)
        for test in all_personality_tests:
            test["_id"] = str(test["_id"])  # Convert ObjectId to string

        return JSONResponse(status_code=200, content={"status": "success", "message": "Personality tests fetched successfully!!", "all_personality_tests": all_personality_tests})

    except Exception as e:
        print(e)
        return JSONResponse(status_code=400, content={"status": "errro", "message": "Error occured!"})


@app.post("/api/v1/admin/edit-test", dependencies=[Depends(token_validation_dependency_for_admin)])
async def edit_test(request: Request):
    try:
        data = await request.json()
        slug_name_of_test = data["test_slug"].split(" ")
        updated_slug_name = ""
        if(len(slug_name_of_test) > 1):
            updated_slug_name = "-".join(slug_name_of_test)
        else:
            updated_slug_name = data["test_slug"]

        personality_test_collection = get_collection("personality_test")
        all_personality_tests = await personality_test_collection.find({}).to_list(length=None)
        if(len(all_personality_tests) > 0):
            for test in all_personality_tests:
                if(test["test_slug"] == updated_slug_name and test["_id"]!=ObjectId(data["id"])):
                    return JSONResponse(status_code=400, content={"status": "errro", "message": "Slug name already exist!"})

        # Find the test to be edited
        test_to_edit = await personality_test_collection.find_one({"_id": ObjectId(data["id"])})
        if not test_to_edit:
            return JSONResponse(status_code=404, content={"status": "error", "message": "Test not found!"})

        srcURL = test_to_edit["image"]
        
        # If the image is updated, upload the new image
        if test_to_edit["image"] != data["image"]:
            upload_response = cloudinary.uploader.upload(data["image"], unique_filename=True, overwrite=True)
            srcURL = upload_response.get("secure_url")

        # Prepare updated data
        updated_data = {
            "test_name": data.get("test_name", test_to_edit["test_name"]),
            "test_slug": data.get("test_slug", test_to_edit["test_slug"]),
            "image": srcURL,
            "questions": data.get("questions", test_to_edit["questions"]),
            "updated_at": time.time()
        }

        # Update the document
        update_result = await personality_test_collection.update_one(
            {"_id": ObjectId(data["id"])},  # Filter by _id
            {"$set": updated_data}  # Set the new values
        )

        if update_result.matched_count == 0:
            return JSONResponse(status_code=404, content={"status": "error", "message": "No matching test found to update."})

        # Fetch all personality tests as a list
        all_personality_tests = await personality_test_collection.find({}).to_list(length=None)
        for test in all_personality_tests:
            test["_id"] = str(test["_id"])  # Convert ObjectId to string

        return JSONResponse(
            status_code=200,
            content={
                "status": "success",
                "message": "Personality test updated successfully!",
                "all_personality_tests": all_personality_tests,
            },
        )

    except Exception as e:
        print("Error",e)
        traceback.print_exc()
        return JSONResponse(status_code=400, content={"status": "error", "message": "An error occurred!"})


@app.post("/api/v1/admin/delete-test", dependencies=[Depends(token_validation_dependency_for_admin)])
async def delete_test(request: Request):
    try:
        data = await request.json()
        personality_test_collection = get_collection("personality_test")

        # Find the test to be deleted
        test_to_delete = await personality_test_collection.find_one({"_id": ObjectId(data["id"])})
        if not test_to_delete:
            return JSONResponse(status_code=404, content={"status": "error", "message": "Test not found!"})

        # Delete the test
        delete_result = await personality_test_collection.delete_one({"_id": ObjectId(data["id"])})

        if delete_result.deleted_count == 0:
            return JSONResponse(status_code=404, content={"status": "error", "message": "Failed to delete the test."})

        # Fetch all remaining personality tests as a list
        all_personality_tests = await personality_test_collection.find({}).to_list(length=None)
        for test in all_personality_tests:
            test["_id"] = str(test["_id"])  # Convert ObjectId to string

        return JSONResponse(
            status_code=200,
            content={
                "status": "success",
                "message": "Personality test deleted successfully!",
                "all_personality_tests": all_personality_tests,
            },
        )

    except Exception as e:
        print(e)
        return JSONResponse(status_code=400, content={"status": "error", "message": "An error occurred!"})


# Endpoint for fetching all personality tests
@app.get("/api/v1/user/fetch-all-tests", dependencies=[Depends(token_validation_dependency)])
async def fetch_all_tests(request: Request):
    try:
        personality_test_collection = get_collection("personality_test")

        # Fetch all personality tests as a list
        all_personality_tests = await personality_test_collection.find({}).to_list(length=None)
        for test in all_personality_tests:
            test["_id"] = str(test["_id"])  # Convert ObjectId to string

        return JSONResponse(status_code=200, content={"status": "success", "message": "Personality tests fetched successfully!!", "all_personality_tests": all_personality_tests})

    except Exception as e:
        print(e)
        return JSONResponse(status_code=400, content={"status": "errro", "message": "Error occured!"})

# Endpoint for fetching test info from slug
@app.post("/api/v1/user/fetch-test-info-from-slug", dependencies=[Depends(token_validation_dependency)])
async def fetch_test_info_from_slug(request: Request):
    try:
        data = await request.json()
        personality_test_collection = get_collection("personality_test")

        # Fetch all personality tests as a list
        personality_test = await personality_test_collection.find_one({"test_slug": data["test_slug"]})
        personality_test["_id"] = str(personality_test["_id"])  # Convert ObjectId to string

        return JSONResponse(status_code=200, content={"status": "success", "message": "Personality test fetched successfully!!", "personality_test": personality_test})

    except Exception as e:
        print(e)
        return JSONResponse(status_code=400, content={"status": "errro", "message": "Error occured!"})



# Calculate the MBTI Type->
@app.post("/api/v1/user/calculate-mbti", dependencies=[Depends(token_validation_dependency)])
async def calculate_mbti(request: Request):
    try:
        """
        Calculate MBTI type based on user responses.
        Each response is scored from -2 to +2.
        """
        data = await request.json()
        # Mapping questions to MBTI dimensions
        dimension_map = {
            "E/I": [1, 2, 3],  # Questions related to E/I
            "S/N": [4, 5, 6],
            "T/F": [7, 8, 9],
            "J/P": [10, 11, 12],
        }
        
        reverse_questions = {2, 5, 8, 11}  # Questions with reverse scoring

        # Initialize dimension scores
        scores = {"E": 0, "I": 0, "S": 0, "N": 0, "T": 0, "F": 0, "J": 0, "P": 0}

        # Scoring
        for qid, response in data["finalAnswers"].items():
            # Get the score from the response
            score = 0
            if response == "Strongly Agree":
                score = 2
            elif response == "Agree":
                score = 1
            elif response == "Neutral":
                score = 0
            elif response == "Disagree":
                score = -1
            elif response == "Strongly Disagree":
                score = -2
            
            # Reverse scoring for specific questions
            if qid in reverse_questions:
                score = -score

            # Add score to the appropriate dimension
            for dimension, questions in dimension_map.items():
                if qid in questions:
                    trait_1, trait_2 = dimension.split("/")  # E/I, S/N, etc.
                    scores[trait_1] += score
                    scores[trait_2] -= score
        
        # Determine final MBTI type
        mbti = ""
        mbti += "E" if scores["E"] >= scores["I"] else "I"
        mbti += "S" if scores["S"] >= scores["N"] else "N"
        mbti += "T" if scores["T"] >= scores["F"] else "F"
        mbti += "J" if scores["J"] >= scores["P"] else "P"

        return JSONResponse(status_code=200, content={"status": "success", "message": "Personality calculated successfully!!", "result": mbti})
    except Exception as e:
        print(e)
        return JSONResponse(status_code=400, content={"status": "errro", "message": "Error occured!"})

# if __name__ == "__main__":
#     asyncio.run(db_init()) 