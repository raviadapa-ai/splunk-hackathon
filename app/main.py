from fastapi import FastAPI
import random
import logging
app = FastAPI()
logging.basicConfig(filename="app.log", level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

@app.get("/")
def home():
    logging.info("Request received")
    return {"status" : "ok"}

@app.get("/error")
def error():
    logging.error("Database timeout")
    return {"status" : "error"}

@app.get("/test")
def test():
    if random.randint(1,10) > 7:
        logging.error("Database timeout")
    else:
        logging.info("Request Successful")
    return {"status" : "ok"}