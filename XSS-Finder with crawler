import asyncio
from playwright.async_api import async_playwright
from urllib.parse import urlparse, urljoin, parse_qs, urlencode

# ANSI color codes for red and purple
RED = "\033[31m"
PURPLE = "\033[35m"
RESET = "\033[0m"

def print_logo():
    logo_lines = [
        " _   _ _____ ____  __  __ ",
        "| \\ | |_   _|  _ \\|  \\/  |",
        "|  \\| | | | | |_) | |\\/| |",
        "| |\\  | | | |  _ <| |  | |",
        "|_| \\_| |_| |_| \\_\\_|  |_|",
        "                          ",
        "        by ox033"
    ]
    # Color lines alternating red and purple to create mix
    colored_logo = ""
    for i, line in enumerate(logo_lines):
        color = RED if i % 2 == 0 else PURPLE
        colored_logo += f"{color}{line}{RESET}\n"
    print(colored_logo)

class XSSScanner:
    def __init__(self, base_url, payloads, max_depth=2):
        self.base_url = base_url
        self.base_domain = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.visited_urls = set()
        self.payloads = payloads
        self.vulnerabilities = []

    async def crawl(self, page, url, depth=0):
        if depth > self.max_depth or url in self.visited_urls:
            return
        print(f"Crawling: {url} (depth {depth})")
        self.visited_urls.add(url)
        try:
            await page.goto(url, wait_until="load", timeout=15000)
        except Exception as e:
            print(f"Failed to load {url}: {e}")
            return
        links = await page.eval_on_selector_all("a[href]", "elements => elements.map(el => el.href)")
        links = [l for l in links if urlparse(l).netloc == self.base_domain]
        await self.test_xss(page, url)
        for link in links:
            if link not in self.visited_urls:
                await self.crawl(page, link, depth + 1)

    async def test_xss(self, page, url):
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        if qs:
            for param in qs:
                for payload in self.payloads:
                    injected_params = {k: (payload if k == param else v[0]) for k,v in qs.items()}
                    new_query = urlencode(injected_params)
                    injected_url = parsed._replace(query=new_query).geturl()
                    print(f"Testing {injected_url} with payload in param '{param}'")
                    vulnerable = await self.check_xss(injected_url, param, payload)
                    if vulnerable:
                        self.report(injected_url, param, payload)
        try:
            await page.goto(url, wait_until="load", timeout=15000)
            forms = await page.query_selector_all("form")
            for form in forms:
                form_info = await self.get_form_details(form)
                for param in form_info.get("inputs", []):
                    name = param.get("name")
                    if not name:
                        continue
                    for payload in self.payloads:
                        print(f"Testing form {form_info.get('action')} param '{name}' with payload")
                        vulnerable = await self.test_form(field_name=name, payload=payload, form_info=form_info, page=page, base_url=url)
                        if vulnerable:
                            self.report(form_info.get('action', url), name, payload)
        except Exception as e:
            print(f"Error scanning forms on {url}: {e}")

    async def check_xss(self, test_url, param, payload):
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()
            triggered = False

            def dialog_handler(dialog):
                nonlocal triggered
                triggered = True
                asyncio.create_task(dialog.dismiss())

            page.on("dialog", dialog_handler)

            try:
                await page.goto(test_url, wait_until="load", timeout=15000)
                await page.wait_for_timeout(3000)
            except Exception:
                pass

            await browser.close()
            return triggered

    async def get_form_details(self, form):
        action = await form.get_attribute("action") or ""
        method = (await form.get_attribute("method") or "get").lower()
        inputs = []
        input_elements = await form.query_selector_all("input,textarea,select")
        for inp in input_elements:
            name = await inp.get_attribute("name")
            if name:
                inputs.append({"name": name})
        return {"action": action, "method": method, "inputs": inputs}

    async def test_form(self, field_name, payload, form_info, page, base_url):
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page2 = await context.new_page()
            triggered = False

            def dialog_handler(dialog):
                nonlocal triggered
                triggered = True
                asyncio.create_task(dialog.dismiss())

            page2.on("dialog", dialog_handler)

            form_data = {}
            for inp in form_info["inputs"]:
                if inp["name"] == field_name:
                    form_data[inp["name"]] = payload
                else:
                    form_data[inp["name"]] = "test"

            form_action = urljoin(base_url, form_info["action"])

            try:
                if form_info["method"] == "post":
                    await page2.goto(base_url, wait_until="load", timeout=15000)
                    for key, value in form_data.items():
                        try:
                            await page2.fill(f'input[name="{key}"],textarea[name="{key}"],select[name="{key}"]', value)
                        except Exception:
                            pass
                    await page2.evaluate("() => document.forms[0].submit()")
                    await page2.wait_for_timeout(3000)
                else:
                    parsed = urlparse(form_action)
                    qs = parse_qs(parsed.query)
                    for k in form_data:
                        qs[k] = [form_data[k]]
                    new_query = urlencode(qs, doseq=True)
                    injected_url = parsed._replace(query=new_query).geturl()
                    await page2.goto(injected_url, wait_until="load", timeout=15000)
                    await page2.wait_for_timeout(3000)
            except Exception:
                pass

            await browser.close()
            return triggered

    def report(self, url, param, payload):
        finding = {
            "url": url,
            "parameter": param,
            "payload": payload
        }
        self.vulnerabilities.append(finding)
        print(f"[VULN FOUND] XSS via parameter '{param}' on {url} with payload: {payload}")

    async def start(self):
        print_logo()
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            await self.crawl(page, self.base_url)
            await browser.close()
        print("\nScan complete! Vulnerabilities found:")
        for vuln in self.vulnerabilities:
            print(vuln)

def main():
    base_url = input("Enter base URL to scan: ").strip()
    payload_file = input("Enter path to payload file (one payload per line): ").strip()

    try:
        with open(payload_file, 'r') as f:
            payloads = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Failed to load payload file: {e}")
        return

    max_depth_input = input("Enter max crawl depth (default 2): ").strip()
    max_depth = int(max_depth_input) if max_depth_input.isdigit() else 2

    scanner = XSSScanner(base_url, payloads, max_depth)
    asyncio.run(scanner.start())

if __name__ == "__main__":
    main()
