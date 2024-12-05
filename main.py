import uvicorn
from fastapi import FastAPI
from importlib import metadata

from fastapi.openapi.docs import get_swagger_ui_html
from starlette.responses import FileResponse
from starlette.staticfiles import StaticFiles

app = FastAPI(
    title='Hello API',
    summary='Hello world with the resources needed to build a real REST service',
    version=metadata.version('hello-fastapi'),
)

app.mount('/static', StaticFiles(directory='static'), name='static')

@app.get('/')
async def root():
    return {'message': 'Hello World'}


if __name__ == "__main__":
    uvicorn.run(app)
