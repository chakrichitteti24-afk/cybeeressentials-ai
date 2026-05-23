from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routers import logs as logs_router, threats as threats_router, analyze as analyze_router

app = FastAPI(title='CyberSentinel AI - Backend')

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*']
)

app.include_router(logs_router.router)
app.include_router(threats_router.router)
app.include_router(analyze_router.router)


@app.get('/')
async def root():
    return {'status': 'CyberSentinel AI backend running'}


if __name__ == '__main__':
    import uvicorn
    uvicorn.run('main:app', host='0.0.0.0', port=8000, reload=True)
