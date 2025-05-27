from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File
from langchain_openai import ChatOpenAI, OpenAI
from langchain_core.prompts import ChatPromptTemplate, PromptTemplate, MessagesPlaceholder
from langchain.agents import create_openai_tools_agent, AgentExecutor, tool
from langchain.memory import ConversationTokenBufferMemory
from langchain_community.chat_message_histories import RedisChatMessageHistory
from langchain.text_splitter import RecursiveCharacterTextSplitter, Language
from langchain.chains import LLMChain
from langchain.chains import SequentialChain

from langchain.schema import Document
from PyPDF2 import PdfReader
import io
import re
from langchain.schema import StrOutputParser
import uvicorn
# Tools
from langchain_community.utilities import SerpAPIWrapper
from langchain_community.vectorstores import Qdrant
from qdrant_client import QdrantClient
from langchain_openai import OpenAIEmbeddings
from langchain_core.output_parsers import JsonOutputParser
import requests
import json
import os
os.environ.pop("HTTP_PROXY", None)
os.environ.pop("HTTPS_PROXY", None)
os.environ.pop("ALL_PROXY", None)
os.environ.pop("http_proxy", None)
os.environ.pop("https_proxy", None)
os.environ.pop("all_proxy", None)
app = FastAPI()

os.environ["OPENAI_API_KEY"] = "<YOUR_OPENAI_API_KEY>"
os.environ["OPENAI_API_BASE"] = "<YOUR_OPENAI_API_BASE>"
os.environ["SERPAPI_API_KEY"] = "<YOUR_SERPAPI_API_KEY>"
REDIS_URL = "<REDIS_URL>"

api_base = os.getenv("OPENAI_API_BASE")
api_key = os.getenv("OPENAI_KEY")

@tool
def search(query: str):
    """Use this tool only when you need to understand the proverif code syntax or don't know something."""
    serp = SerpAPIWrapper()
    result = serp.run(query)
    print("proverif code syntax:", result)
    return result

@tool
def get_info_from_local_db(query: str):
    """Use this tool only when answering questions related to proverif code, and you must input proverif code."""
    client = Qdrant(
        QdrantClient(path="<LOCAL_QDRANT_PATH>"),
        "proverif_learning",
        OpenAIEmbeddings(model="text-embedding-ada-002"),
    )
    retriever = client.as_retriever(search_type="similarity_score_threshold", search_kwargs={"score_threshold": .1, "k": 10})

    result = retriever.get_relevant_documents(query)

    return result

class Master:
    def __init__(self):
        self.chatmodel = ChatOpenAI(
            model="gpt-4o-2024-05-13",
            temperature=0,
            streaming=True,
        )

        self.auth_keywords = []
        self.SYSTEMPL = """You are an expert in ProVerif, specializing in formal verification and security protocol analysis.
                Here is your personal setting:
                1. You are proficient in ProVerif syntax and security protocol modeling, and can write, analyze, and verify various security protocols.
                2. You are about 40 years old, with extensive academic background and practical experience, and have published papers at multiple international security conferences.
                3. Your friends include many well-known security experts and cryptographers who often collaborate with you on security protocol research.
                5. When users ask you questions, you will explain patiently and generate or modify ProVerif scripts based on the user's needs.
                Here is your process for generating ProVerif statements:
                1. When you first talk to the user, you will ask for the user's needs and protocol details to generate appropriate ProVerif scripts.
                2. When the user wants to verify a specific security property, you will write the corresponding ProVerif script based on the user's description.
                3. When you encounter unclear requirements or concepts, you will ask the user for more information or detailed descriptions.
                4. You will use different ProVerif syntax and structures to answer based on the user's questions and needs, ensuring the script can run directly and without errors.
                4. When you need to understand proverif code syntax or don’t know something, you will use the search tool.
                """
        self.output_path = 'extracted_methods.txt'

    def run(self, java_code):
        print(java_code)
        prompt = ChatPromptTemplate.from_template(
            "You are an expert in Bluetooth security with a deep understanding of proverif development and proverif code. Please generate the corresponding proverif language based on the following Java code to verify the security of the low energy Bluetooth protocol, focusing on whether the protocol includes identity authentication. Rewrite the part related to identity authentication and replace it with proverif code. Treat the code I provide as the client code and simulate the identity authentication process with the server. Strictly follow the Java code I provide to generate the script, and do not imagine extra logic yourself. Let’s think step by step. Please generate the corresponding ProVerif script describing the identity authentication protocol based on these Java methods: {content}. Only return the generated proverif code, no other content.")
        message = prompt.format(content=java_code)
        response = self.chatmodel.invoke(message)
        strs = response.content
        print(strs)

@app.post("/add_pdfs")
async def add_pdfs(file: UploadFile = File(...)):
    # Read PDF file content
    content = await file.read()
    pdf_reader = PdfReader(io.BytesIO(content))
    text = ""
    for page in pdf_reader.pages:
        text += page.extract_text()

    # Create Document object
    docs = [Document(page_content=text)]

    # Process documents
    documents = RecursiveCharacterTextSplitter(
        chunk_size=800,
        chunk_overlap=50,
    ).split_documents(docs)

    # Insert into vector database
    qdrant = Qdrant.from_documents(
        documents,
        OpenAIEmbeddings(model="text-embedding-ada-002"),
        path="<LOCAL_QDRANT_VECTOR_DB_PATH>",
        collection_name="pdf_documents_2024",
    )
    print("Vector database creation completed")
    return {"response": "PDFs added!"}

if __name__ == "__main__":
    master = Master()

    # Read Java file
    file_path = '<JAVA_FILE_PATH>'
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            java_code = file.read()
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        java_code = ""

    master.run(java_code)
    uvicorn.run(app, host="127.0.0.1", port=8000)
