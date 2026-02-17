import sys
import time
from datetime import datetime, timedelta
from playwright.sync_api import sync_playwright

def test_urgency():
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
            test_username = f"user_urgency_{uid}"
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
            today = datetime.now().strftime("%Y-%m-%d")
            future = (datetime.now() + timedelta(days=7)).strftime("%Y-%m-%d")

            print(f"Adding urgent task for today: {today}")
            page.fill("#name", "Urgent Task")
            page.fill("#date", today)
            page.press("#date", "Enter")
            page.wait_for_load_state("networkidle")

            print(f"Adding non-urgent task for future: {future}")
            page.fill("#name", "Future Task")
            page.fill("#date", future)
            page.press("#date", "Enter")
            page.wait_for_load_state("networkidle")

            # Verify Urgent Task has red background
            print("Verifying background colors...")
            urgent_row = page.query_selector("tr:has-text('Urgent Task')")
            future_row = page.query_selector("tr:has-text('Future Task')")

            urgent_class = urgent_row.get_attribute("class")
            print(f"Urgent row class: {urgent_class}")
            if "bg-red-50" not in urgent_class:
                print("Error: Urgent task row does not have 'bg-red-50' class")
                sys.exit(1)

            future_class = future_row.get_attribute("class")
            print(f"Future row class: {future_class}")
            if "bg-red-50" in future_class:
                print("Error: Future task row should NOT have 'bg-red-50' class")
                sys.exit(1)

            print("UI Urgency Test Passed!")

        except Exception as e:
            print(f"Test failed with exception: {e}")
            sys.exit(1)
        finally:
            browser.close()

if __name__ == "__main__":
    test_urgency()
