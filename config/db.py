from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv
import os

load_dotenv()  # take environment variables from .env.

async def connect_DB():
    try:

        # MongoDB URI
        MONGO_DETAILS = f"{os.getenv("MONGODB_URL")}"  # Replace with your MongoDB connection string

        # Initialize the MongoDB client
        client = AsyncIOMotorClient(MONGO_DETAILS)

        # Specify the database you want to use
        database = client.persona_quest  # Replace 'my_database' with your database name

        # Specify the collection (equivalent to table in SQL databases)
        return client, database


    except Exception as e:
        print(e)