import logging
import time
import uvicorn
from fastapi import FastAPI, WebSocket, Request
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.websockets import WebSocketDisconnect

from urllib.parse import urlparse, urlunparse

import external_methods
import python_methods

logger = logging.getLogger('uvicorn.error')
logger.setLevel(logging.DEBUG)

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory='templates')


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()

    try:
        while True:
            data = await websocket.receive_json()
            url = data['url']
            method = data['method']
            scan_type = data['scanType']

            parsed_url = urlparse(url)
            if not parsed_url.scheme:
                parsed_url = urlparse('http://' + url)

            # TODO: add xss and injection protection

            url = str(urlunparse(parsed_url))

            result = None
            start_time = time.time()

            if not parsed_url.netloc:
                logger.error('Invalid URL: Missing host')
                await websocket.send_json({'type': 'error', 'data': 'Invalid URL'})
                continue

            if method == 'python':
                if scan_type == 'availability':
                    result = await python_methods.check_available(url)
                elif scan_type == 'directories':
                    url = parsed_url.scheme + '://' + parsed_url.netloc + parsed_url.path
                    result_list = await python_methods.directory_bruteforce(url, 'wordlist.txt')
                    result = [status for status in result_list if status]
                    if not result:
                        result = "Directories aren't found"
                elif scan_type == 'subdomains':
                    url = parsed_url.scheme + '://' + parsed_url.netloc
                    result_list = await python_methods.subdomains_bruteforce(url, 'wordlist.txt')
                    result = [status for status in result_list if status and 'Error' not in status]
                    if not result:
                        result = "Subdomains aren't found"
            else:  # method == 'external'
                if scan_type == 'availability':
                    result = await external_methods.check_available(url, logger)
                elif scan_type == 'version':
                    result = await external_methods.check_version(parsed_url.netloc, '80,443', logger)
                elif scan_type == 'screenshot':
                    screenshot = await external_methods.get_screenshot(url, logger)
                    await websocket.send_json({'type': 'screenshot', 'data': screenshot})
                    continue
                elif scan_type == 'nuclei':
                    result = await external_methods.run_nuclei(url, logger)
                elif scan_type == 'subdomains':
                    url = parsed_url.scheme + '://FUZZ.' + parsed_url.netloc
                    result = await external_methods.get_subdomains(url, logger)
                elif scan_type == 'directories':
                    url = parsed_url.scheme + '://' + parsed_url.netloc + '/FUZZ'
                    result = await external_methods.directory_bruteforce(url, logger)
                elif scan_type == 'sqlmap':
                    result = await external_methods.run_sqlmap(url, logger)

            end_time = time.time()
            duration = end_time - start_time

            if result:
                await websocket.send_json({'type': 'result',
                                           'data': result,
                                           'duration': duration,
                                           })
            else:
                await websocket.send_json({'type': 'result',
                                           'data': 'Empty result',
                                           'duration': duration})

    except WebSocketDisconnect:
        print("Client disconnected")


@app.get("/")
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


if __name__ == '__main__':
    uvicorn.run(app=app, host="127.0.0.1", port=8000, reload=True, log_level="trace")
