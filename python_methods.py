import aiohttp
import asyncio
import logging
import ssl
from urllib.parse import urlparse
from ipaddress import ip_address


def is_ipaddress(hostname: str):
    try:
        ip_address(hostname)
        return True
    except ValueError:
        return False


async def check_available(url: str, logger: logging.Logger):
    try:
        parsed_url = urlparse(url)

        async with aiohttp.ClientSession() as session:
            async with session.get(url=url) as response:
                if is_ipaddress(parsed_url.hostname):
                    logger.debug('URL is IP')
                    return (f"{url}: Status {response.status}, Length {len(await response.text())}."
                            f"To get domain status set URL as domain name")
                elif len(parsed_url.hostname.split('.')) > 2:
                    url_domain = parsed_url.scheme + '://' + '.'.join(parsed_url.hostname.split('.')[-2:])
                    async with session.get(url=url_domain) as response_dom:
                        return (f"{url}: Status {response.status}, Length {len(await response.text())}\n"
                                f"{url_domain}: Status {response_dom.status} Length {len(await response_dom.text())}\n")
                else:
                    return f"{url}: Status {response.status}, Length {len(await response.text())}\n"
    except aiohttp.ClientSSLError as ssl_err:
        logger.error(f"{url}: Error {ssl_err}")
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        async with aiohttp.ClientSession() as session:
            async with session.get(url=url, ssl=ssl_context) as response:
                return f"{url}: Status {response.status}, Length {len(await response.text())}"
    except aiohttp.ClientConnectorError as client_connect_err:
        return f"{url}: Error {client_connect_err}"
    except aiohttp.ServerDisconnectedError as server_connect_err:
        return f"{url}: Error {server_connect_err}"


async def check_directory(session: aiohttp.ClientSession, url: str, logger: logging.Logger):
    try:
        async with session.get(url) as response:
            if response.status in list(range(200, 300)) + [301, 302, 403, 500, 501, 502]:
                # print(f"{url.strip()}: Status {response.status}, Length {len(await response.text())}")
                return f"{url.strip()}: Status {response.status}, Length {len(await response.text())}\n"
            # else:
            #     print(f"{url.strip()} unavailable status {response.status}")
    except aiohttp.ClientSSLError as ssl_err:
        logger.error(f"{url}: Error {ssl_err}")
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        async with session.get(url=url, ssl=ssl_context) as response:
            return f"{url.strip()}: Status {response.status}, Length {len(await response.text())}\n"
    except aiohttp.ClientConnectorError as client_connect_err:
        return f"{url}: Error {client_connect_err}"
    except aiohttp.ServerDisconnectedError as server_connect_err:
        return f"{url}: Error {server_connect_err}"


async def directory_bruteforce(url: str, wordlist: str, logger: logging.Logger):
    async with aiohttp.ClientSession() as session:
        logger.debug('starting directory bruteforce...')
        with open(wordlist, 'r') as wl:
            tasks = []
            for directory in wl:
                if url[-1] == '/':
                    url_dir = url + directory
                else:
                    url_dir = f'{url}/{directory}'
                url_status = check_directory(session=session, url=url_dir, logger=logger)
                if url_status is not None:
                    tasks.append(url_status)
            result = await asyncio.gather(*tasks)
            return result


async def subdomains_bruteforce(url: str, wordlist: str, logger: logging.Logger):
    parsed_url = urlparse(url)
    if is_ipaddress(parsed_url.hostname):
        logger.error('URL is IP')
        return 'URL in IP format. To search subdomains set URL in domain name format'
    else:
        async with aiohttp.ClientSession() as session:
            with open(wordlist, 'r') as wl:
                tasks = []
                for subdomain in wl:
                    url_sub = f'{parsed_url.scheme}://{subdomain.strip()}.{parsed_url.netloc}'
                    url_status = check_directory(session=session, url=url_sub, logger=logger)
                    if url_status is not None:
                        tasks.append(url_status)
                result = await asyncio.gather(*tasks)
                return result


# async def main():
#     result_list = await directory_bruteforce('http://vulnweb.com', 'wordlist.txt')
#     result = [status for status in result_list if status and 'Error' not in status]
#     return result


# if __name__ == '__main__':
#     print(asyncio.run(main()))
