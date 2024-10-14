import asyncio
import logging
import subprocess


async def check_available(url: str, logger: logging.Logger):
    httpx = ['httpx', '-sc', '-silent', '-u', url]
    logger.debug('starting httpx ...')

    # For unknown reasons utilities by ProjectDiscovery require something to stdin
    echo = subprocess.Popen(['echo', '1'], stdout=subprocess.PIPE)
    process = await asyncio.create_subprocess_exec(*httpx,
                                                   stdin=echo.stdout,
                                                   stdout=asyncio.subprocess.PIPE,
                                                   stderr=asyncio.subprocess.PIPE)

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
            '--scripts',
            'vulners',
            url]
    logger.debug(f'starting nmap ...')
    process = await asyncio.create_subprocess_exec(*nmap,
                                                   stdout=asyncio.subprocess.PIPE,
                                                   stderr=asyncio.subprocess.PIPE)

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

    stdout, stderr = await process.communicate()

    if stdout:
        logger.debug(stdout.decode())
    if stderr:
        logger.debug(stderr.decode())

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

    stdout, stderr = await process.communicate()

    if stdout.decode():
        return stdout.decode()
    else:
        return "Directories aren't found"


async def run_sqlmap(url: str, logger: logging.Logger):
    sqlmap = ['sqlmap', '-u', url, '--batch', '--risk=3', '--level=5']
    print(sqlmap)
    logger.debug('starting sqlmap...')
    process = await asyncio.create_subprocess_exec(*sqlmap,
                                                   stdout=asyncio.subprocess.PIPE,
                                                   stderr=asyncio.subprocess.PIPE)
    stdout, stderr = await process.communicate()
    if stdout.decode():
        return stdout.decode()
    else:
        return "Something went wrong"

if __name__ == '__main__':
    pass

