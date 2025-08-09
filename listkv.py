#!/usr/bin/env python3
import os
import sys
import json
import hvac

KV_MOUNT_POINT = "kv"

def list_all_keys(client, path_prefix=""):
    """Recursively list all keys in the given path under the KV mount point."""
    try:
        response = client.secrets.kv.v2.list_secrets(
            path=path_prefix,
            mount_point=KV_MOUNT_POINT
        )
        keys = response.get("data", {}).get("keys", [])
        all_keys = []

        for key in keys:
            if key.endswith("/"):  # Folder
                all_keys.extend(list_all_keys(client, path_prefix + key))
            else:
                all_keys.append(path_prefix + key)
        return all_keys
    except hvac.exceptions.InvalidPath:
        return []

def export_kv(filename):
    vault_addr = os.getenv("VAULT_ADDR")
    vault_token = os.getenv("VAULT_TOKEN")
    if not vault_addr or not vault_token:
        print("Error: VAULT_ADDR and VAULT_TOKEN must be set in environment variables.")
        sys.exit(1)

    client = hvac.Client(url=vault_addr, token=vault_token)
    if not client.is_authenticated():
        print("Error: Failed to authenticate with Vault.")
        sys.exit(1)

    all_keys = list_all_keys(client)
    export_data = {}

    for key in all_keys:
        try:
            secret = client.secrets.kv.v2.read_secret_version(
                path=key,
                mount_point=KV_MOUNT_POINT,
                raise_on_deleted_version=False  # skip deleted
            )
            data = secret.get("data", {}).get("data", {})

            if not data:
                print(f"Skipping deleted/empty secret: {key}")
                continue

            export_data[key] = data  # store ONLY the relative path
            print(f"Exported: {key}")

        except Exception as e:
            print(f"Error reading {key}: {e}")

    with open(filename, "w") as f:
        json.dump(export_data, f, indent=2)

    print(f"\n✅ Export complete. Saved to {filename}")

def import_kv(filename):
    vault_addr = os.getenv("VAULT_ADDR")
    vault_token = os.getenv("VAULT_TOKEN")
    if not vault_addr or not vault_token:
        print("Error: VAULT_ADDR and VAULT_TOKEN must be set in environment variables.")
        sys.exit(1)

    client = hvac.Client(url=vault_addr, token=vault_token)
    if not client.is_authenticated():
        print("Error: Failed to authenticate with Vault.")
        sys.exit(1)

    with open(filename, "r") as f:
        import_data = json.load(f)

    for key, secret_data in import_data.items():
        try:
            client.secrets.kv.v2.create_or_update_secret(
                path=key,  # relative path only
                secret=secret_data,
                mount_point=KV_MOUNT_POINT
            )
            print(f"Imported: {key}")
        except Exception as e:
            print(f"Error writing {key}: {e}")

    print(f"\n✅ Import complete from {filename}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} --exportkv <file.json> | --importkv <file.json>")
        sys.exit(1)

    action = sys.argv[1]
    filename = sys.argv[2]

    if action == "--exportkv":
        export_kv(filename)
    elif action == "--importkv":
        import_kv(filename)
    else:
        print("Error: Invalid action. Use --exportkv or --importkv.")
