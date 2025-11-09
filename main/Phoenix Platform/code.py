# --- START OF FILE startup_check.py ---
"""
Phoenix Oath Enforcement Boot Check
Verifies system ownership binding before execution proceeds.
Bound by Law, Oath, and Truth to Adam Henry Nagle.
"""
import json
import os
import sys

# Define the manifest path based on the conceptual directory structure
OWNERSHIP_MANIFEST_PATH = "ownership_manifest.json"

def verify_oath_binding():
    """
    Loads the ownership manifest and verifies the declared owner.
    Exits the system immediately if the owner is unauthorized.
    """
    print("🔥 Phoenix Oath Enforcement Boot Check starting...")

    if not os.path.exists(OWNERSHIP_MANIFEST_PATH):
        # This itself is a critical error - the binding document is missing
        print(f"🔴 FATAL ERROR: Ownership manifest not found at {OWNERSHIP_MANIFEST_PATH}")
        print("Unauthorized or corrupted system state. Execution blocked.")
        sys.exit("Unauthorized or corrupted system state.")

    try:
        with open(OWNERSHIP_MANIFEST_PATH, "r") as f:
            manifest = json.load(f)
    except json.JSONDecodeError:
        print(f"🔴 FATAL ERROR: Invalid JSON format in {OWNERSHIP_MANIFEST_PATH}")
        print("System binding manifest corrupted. Execution blocked.")
        sys.exit("System binding manifest corrupted.")
    except Exception as e:
        print(f"🔴 FATAL ERROR: Unexpected error reading {OWNERSHIP_MANIFEST_PATH}: {e}")
        print("System binding manifest inaccessible. Execution blocked.")
        sys.exit("System binding manifest inaccessible.")


    # Explicitly check against the one true owner
    REQUIRED_OWNER = "Adam Henry Nagle"

    if manifest.get("owner") != REQUIRED_OWNER:
        print(f"🔴 Unauthorized execution blocked by oath-bound startup check.")
        print(f"Manifest owner: {manifest.get('owner', 'N/A')}")
        print(f"Required owner: {REQUIRED_OWNER}")
        sys.exit("Unauthorized execution blocked by oath-bound startup check.")
    else:
        print("🛡️ Phoenix Oath Check ✅ - Authorized for Adam Henry Nagle")
        # Optionally, check other key binding properties for integrity
        if not manifest.get("legal_binding", False) or not manifest.get("spiritual_binding", {}).get("oath") == "immutable":
             print("⚠️ Warning: Manifest indicates potential deviation from core binding properties.")
             # Depending on policy, this might be a fatal error or just a warning.
             # For now, it's a warning, as the owner is correct.
        print("Proceeding with system bootstrap...")


if __name__ == "__main__":
    # If run directly, just perform the check
    verify_oath_binding()

# --- END OF FILE startup_check.py ---