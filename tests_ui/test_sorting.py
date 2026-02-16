import sys
import time
from playwright.sync_api import sync_playwright

def test_sorting():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()

        try:
            # Navigate to the app
            print("Navigating to http://127.0.0.1:8000/login...")
            page.goto("http://127.0.0.1:8000/login")

            print("Logging in as admin...")
            page.fill("#username", "admin")
            page.fill("#password", "admin")
            page.click("button[type='submit']")
            page.wait_for_load_state("networkidle")

            # Add some tasks to ensure we have something to sort
            uid = str(int(time.time()))
            name_a = f"Alpha {uid}"
            name_z = f"Zeta {uid}"

            print(f"Adding task: {name_a}")
            page.fill("#name", name_a)
            page.fill("#date", "2023-01-01")
            page.press("#date", "Enter")
            page.wait_for_load_state("networkidle")

            print(f"Adding task: {name_z}")
            page.fill("#name", name_z)
            page.fill("#date", "2023-01-02")
            page.press("#date", "Enter")
            page.wait_for_load_state("networkidle")

            # 1. Sort by Name ASC
            print("Clicking 'Task Name' for ASC sort...")
            page.click("a:has-text('Task Name')")
            page.wait_for_load_state("networkidle")

            # Verify order
            rows = page.query_selector_all("tbody tr:not(:has-text('No tasks found'))")
            names = [row.query_selector("th").inner_text() for row in rows]
            # Filter for our added tasks to avoid interference from existing data
            filtered_names = [n for n in names if uid in n]
            print(f"Filtered names (ASC): {filtered_names}")
            if filtered_names != [name_a, name_z]:
                print(f"Error: Expected {[name_a, name_z]}, got {filtered_names}")
                sys.exit(1)

            # 2. Sort by Name DESC
            print("Clicking 'Task Name' for DESC sort...")
            page.click("a:has-text('Task Name')")
            page.wait_for_load_state("networkidle")

            rows = page.query_selector_all("tbody tr:not(:has-text('No tasks found'))")
            names = [row.query_selector("th").inner_text() for row in rows]
            filtered_names = [n for n in names if uid in n]
            print(f"Filtered names (DESC): {filtered_names}")
            if filtered_names != [name_z, name_a]:
                print(f"Error: Expected {[name_z, name_a]}, got {filtered_names}")
                sys.exit(1)

            print("UI Sorting Test Passed!")

        except Exception as e:
            print(f"Test failed with exception: {e}")
            sys.exit(1)
        finally:
            browser.close()

if __name__ == "__main__":
    test_sorting()
