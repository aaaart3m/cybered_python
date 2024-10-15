# Pentest multitool  

This project is homework for python classes on CyberEd.  
[![Demonstartion](https://img.youtube.com/vi/sEAz_K_ZFvg/0.jpg)](https://www.youtube.com/watch?v=sEAz_K_ZFvg) to the video with demonstration
Web application runs on fastapi and uvicorn. Scanner based on python libs adn some utilities:  

- httpx;
- ffuf;  
- nmap;  
- nuclei;  
- gowitness;  
- sqlmap;  
- asyncio;  
- aiohttp;  

In addition, the application displays the time spent on scanning.  

## Install  

To install this tool you need to install Python 3.8+  

```bash
pip install -r requirements.txt
```

## Start

To start you have to run uvicorn:  

```bash
uvicorn app:app --host 0.0.0.0 --reload
```

Then you have to go <http://127.0.0.1:8000> on your browser!  
