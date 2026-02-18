import sys
import time
from datetime import datetime, timedelta
from playwright.sync_api import sync_playwright

def test_expired():
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

            # Create a unique user
            uid = str(int(time.time()))
            test_username = f"user_expired_{uid}"
            print(f"Creating test user: {test_username}")
            page.goto("http://127.0.0.1:8000/user_admin/new")
            page.fill("#username", test_username)
            page.fill("#password", "password")
            page.click("button[type='submit']")
            page.wait_for_load_state("networkidle")

            print("Logging out...")
            page.click("button:has-text('Logout')")
            page.wait_for_load_state("networkidle")

            print(f"Logging in as {test_username}...")
            page.fill("#username", test_username)
            page.fill("#password", "password")
            page.click("button[type='submit']")
            page.wait_for_load_state("networkidle")

            # Dates
            yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
            future = (datetime.now() + timedelta(days=7)).strftime("%Y-%m-%d")

            print(f"Adding expired task for yesterday: {yesterday}")
            page.fill("#name", "Expired Task")
            page.fill("#date", yesterday)
            page.press("#date", "Enter")
            page.wait_for_load_state("networkidle")

            print(f"Adding future task for future: {future}")
            page.fill("#name", "Future Task")
            page.fill("#date", future)
            page.press("#date", "Enter")
            page.wait_for_load_state("networkidle")

            # Verify Expired Task has gray background
            print("Verifying background colors and status...")
            expired_row = page.query_selector("tr:has-text('Expired Task')")

            if not expired_row:
                print("Error: Expired Task row not found")
                sys.exit(1)

            expired_class = expired_row.get_attribute("class")
            print(f"Expired row class: {expired_class}")
            if "bg-gray-300" not in expired_class:
                print("Error: Expired task row does not have 'bg-gray-300' class")
                sys.exit(1)

            expired_status = expired_row.query_selector("td").inner_text()
            print(f"Expired status text: {expired_status}")
            if "Expired" not in expired_status:
                print("Error: Expired task does not show 'Expired' status")
                sys.exit(1)

            # Verify sorting: Expired Task should be FIRST even if sorting by date DESC (which would normally put it last)
            # Default sort is Date DESC
            rows = page.query_selector_all("tbody tr")
            first_row_text = rows[0].inner_text()
            print(f"First row text: {first_row_text}")
            if "Expired Task" not in first_row_text:
                print("Error: Expired task is not at the top of the list")
                sys.exit(1)

            print("UI Expired Test Passed!")

        except Exception as e:
            print(f"Test failed with exception: {e}")
            sys.exit(1)
        finally:
            browser.close()

if __name__ == "__main__":
    test_expired()
