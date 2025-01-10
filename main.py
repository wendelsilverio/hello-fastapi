from importlib import metadata
from typing import Annotated, Callable

import uvicorn
from fastapi import FastAPI, HTTPException, status, Request
from fastapi.staticfiles import StaticFiles
from fastapi.params import Depends
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response, JSONResponse

from auth.routers import auth_router
from auth.security import oauth2_scheme, verify_token

app = FastAPI(
    title='Hello API',
    summary='Hello world with the resources needed to build a real REST service',
    root_path='/api/v1',
    version=metadata.version('hello-fastapi'),
)

# Static assets ----------------------------------------------------------------
app.mount('/assets', StaticFiles(directory='assets'), name='assets')


# Routes -----------------------------------------------------------------------
@app.get('/')
async def root():
    return {'message': 'Hello World'}


@app.get('/protected-route')
async def get_protected_route(token: Annotated[str, Depends(oauth2_scheme)]):
    return {'token': token}


app.include_router(auth_router)


@app.middleware('http')
async def token_revocation_check(request: Request, call_next):
    # response: Response = await call_next(request)
    authorization = request.headers.get('Authorization')
    if authorization and authorization.startswith('Bearer'):
        token = authorization[7:]
        try:
            verify_token(token)
        except HTTPException as error:
            return JSONResponse(content={'detail': error.detail}, status_code=error.status_code)
    response = await call_next(request)
    return response


# Server -----------------------------------------------------------------------
if __name__ == "__main__":
    uvicorn.run(app)
