import aiohttp
import asyncio
from urllib.parse import urlparse


# async def check_available(url: str, websocket):
#     await websocket.send_text(f"Check {url}")
#     try:
#         async with aiohttp.ClientSession() as session:
#             async with session.get(url) as response:
#                 await websocket.send_text(f"{url}: Status {response.status}, {response.headers}")
#     except aiohttp.ClientSSLError as ssl_err:
#         await websocket.send_text(f"{url}: Error {ssl_err}")
#     except aiohttp.ClientConnectorError as connect_err:
#         await websocket.send_text(f"{url}: Error {connect_err}")


async def check_available(url: str):
    try:

        async with aiohttp.ClientSession() as session:
            async with session.get(url=url) as response:
                return f"{url}: Status {response.status}, Length {len(await response.text())}"
    except aiohttp.ClientSSLError as ssl_err:
        return f"{url}: Error {ssl_err}"
    except aiohttp.ClientConnectorError as connect_err:
        return f"{url}: Error {connect_err}"


async def check_directory(session: aiohttp.ClientSession, url: str):
    try:
        async with session.get(url) as response:
            if response.status in list(range(200, 300)) + [301, 302, 403, 500, 501, 502]:
                # print(f"{url.strip()}: Status {response.status}, Length {len(await response.text())}")
                return f"{url.strip()}: Status {response.status}, Length {len(await response.text())}"
            # else:
            #     print(f"{url.strip()} unavailable status {response.status}")
    except aiohttp.ClientSSLError as ssl_err:
        return f"{url}: Error {ssl_err}"
    except aiohttp.ClientConnectorError as client_connect_err:
        return f"{url}: Error {client_connect_err}"
    except aiohttp.ServerDisconnectedError as server_connect_err:
        return f"{url}: Error {server_connect_err}"


async def directory_bruteforce(url: str, wordlist: str):
    async with aiohttp.ClientSession() as session:
        with open(wordlist, 'r') as wl:
            tasks = []
            for directory in wl:
                if url[-1] == '/':
                    url_dir = url + directory
                else:
                    url_dir = f'{url}/{directory}'
                print(url_dir)
                url_status = check_directory(session=session, url=url_dir)
                if url_status is not None:
                    tasks.append(url_status)
            result = await asyncio.gather(*tasks)
            return result


async def subdomains_bruteforce(url: str, wordlist: str):
    parsed_url = urlparse(url)
    async with aiohttp.ClientSession() as session:
        with open(wordlist, 'r') as wl:
            tasks = []
            for subdomain in wl:
                url_sub = f'{parsed_url.scheme}://{subdomain.strip()}.{parsed_url.netloc}'
                url_status = check_directory(session=session, url=url_sub)
                if url_status is not None:
                    tasks.append(url_status)
            result = await asyncio.gather(*tasks)
            return result


async def main():
    result_list = await directory_bruteforce('http://vulnweb.com', 'wordlist.txt')
    # result_list = await subdomains_bruteforce('http://vulnweb.com', 'wordlist.txt')
    result = [status for status in result_list if status and 'Error' not in status]
    return result
    # for stat in result:
    #     if stat:
    #         print(stat)

if __name__ == '__main__':
    # asyncio.run(check_version('http://188.64.151.65/', '6875'))
    # print(asyncio.run(check_available_direct('http://188.64.151.65:6875/')))
    print(asyncio.run(main()))
