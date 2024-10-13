import asyncio
import logging
import subprocess


async def check_available(url: str, logger: logging.Logger):
    httpx = ['httpx', '-sc', '-silent', '-u', url]
    logger.debug('starting httpx ...')
    # curl = ['curl', '-o', '/dev/null', '-w', '\"%{http_code}\"', '-s', url]
    # For unknown reasons utilities by ProjectDiscovery require something to stdin
    echo = subprocess.Popen(['echo', '1'], stdout=subprocess.PIPE)
    process = await asyncio.create_subprocess_exec(*httpx,
                                                   stdin=echo.stdout,
                                                   stdout=asyncio.subprocess.PIPE,
                                                   stderr=asyncio.subprocess.PIPE)
    # process = subprocess.run(httpx, stdin=echo.stdout, check=True, capture_output=True, text=True)
    # process = subprocess.Popen(httpx, stdin=echo.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    logger.debug('ending httpx ...')
    stdout, stderr = await process.communicate()
    if stdout:
        logger.debug(stdout.decode())
    if stderr:
        logger.debug(stderr.decode())

    if stdout.decode():
        return stdout.decode()
    else:
        return "Something went wrong"


async def check_version(url: str, port: str, logger: logging.Logger):
    nmap = ["nmap",
            "-sV",
            f'-p{port}',
            url]
    logger.debug(f'starting nmap ...')
    process = await asyncio.create_subprocess_exec(*nmap,
                                                   stdout=asyncio.subprocess.PIPE,
                                                   stderr=asyncio.subprocess.PIPE)
    logger.debug(f'ending nmap ...')
    stdout, stderr = await process.communicate()

    if stdout:
        logger.debug(stdout.decode())
    if stderr:
        logger.debug(stderr.decode())

    if stdout.decode():
        return stdout.decode()
    else:
        return "Something went wrong"


async def get_screenshot(url: str, logger: logging.Logger):
    gowitness = ['gowitness', 'scan', 'single', '-u', url, '-s', './static/screenshots/']
    logger.debug(f'starting gowitness ...')
    process = await asyncio.create_subprocess_exec(*gowitness,
                                                   stdout=asyncio.subprocess.PIPE,
                                                   stderr=asyncio.subprocess.PIPE)
    logger.debug(f'ending gowitness ...')
    stdout, stderr = await process.communicate()

    if stdout:
        logger.debug(stdout.decode())
    if stderr:
        logger.debug(stderr.decode())

    return f'{url.replace(":", "-").replace("/", "-")}.jpeg'


async def run_nuclei(url: str, logger: logging.Logger):
    nuclei = ['nuclei', '-u', url]
    logger.debug(f'starting nuclei ...')
    # For unknown reasons utilities by ProjectDiscovery require something to stdin
    echo = subprocess.Popen(['echo', '1'], stdout=subprocess.PIPE)
    process = await asyncio.create_subprocess_exec(*nuclei,
                                                   stdin=echo.stdout,
                                                   stdout=asyncio.subprocess.PIPE,
                                                   stderr=asyncio.subprocess.PIPE)
    logger.debug(f'ending nuclei ...')
    stdout, stderr = await process.communicate()

    if stdout.decode():
        return stdout.decode()
    else:
        return "Vulnerabilities aren't found"


async def get_subdomains(url: str, logger: logging.Logger):
    ffuf_subdomain = ['ffuf', '-u', url, '-w', 'wordlist.txt']
    logger.debug('starting ffuf fuzzing subdomains...')
    process = await asyncio.create_subprocess_exec(*ffuf_subdomain,
                                                   stdout=asyncio.subprocess.PIPE,
                                                   stderr=asyncio.subprocess.PIPE)
    logger.debug('ending ffuf fuzzing subdomains...')
    stdout, stderr = await process.communicate()
    if stdout.decode():
        return stdout.decode()
    else:
        return "Subdomains aren't found"


async def directory_bruteforce(url: str, logger: logging.Logger):
    ffuf_dir = ['ffuf', '-u', url, '-w', 'wordlist.txt']
    logger.debug('starting ffuf fuzzing directories ...')
    process = await asyncio.create_subprocess_exec(*ffuf_dir,
                                                   stdout=asyncio.subprocess.PIPE,
                                                   stderr=asyncio.subprocess.PIPE)
    logger.debug('ending ffuf fuzzing directories ...')
    stdout, stderr = await process.communicate()

    if stdout.decode():
        return stdout.decode()
    else:
        return "Directories aren't found"


async def run_sqlmap(url: str, logger: logging.Logger):
    pass


if __name__ == '__main__':
    pass
    # asyncio.run(check_version('http://188.64.151.65/', '6875'))
    # asyncio.run(run_nuclei('http://188.64.151.65:6875/'))
    # asyncio.run(check_available('http://188.64.151.65:6875/'))
    # get_screenshot_sync('http://188.64.151.65:6875/')
    # asyncio.run(get_screenshot('http://188.64.151.65:6875/'))
    # asyncio.run(directory_bruteforce('http://188.64.151.65:6875'))
