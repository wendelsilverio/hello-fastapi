import importlib.metadata
from importlib.metadata import metadata

import uvicorn
from fastapi import FastAPI
from importlib import metadata

app = FastAPI(
    title='Hello API',
    summary='Hello world with the resources needed to build a real REST service',
    version=metadata.version('hello-fastapi')
)


@app.get('/')
async def root():
    return {'message': 'Hello World'}


if __name__ == "__main__":
    uvicorn.run(app)
