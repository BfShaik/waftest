import json
import os
import time
import oci
import sys

from oci.waf.models import UpdateNetworkAddressListAddressesDetails

NETWORK_ADDRESS_LIST_OCID = "ocid1.webappfirewallnetworkaddresslist.oc1.iad.amaaaaaa2j5jslyalmryayb6hfbk6em2wkia7bts5iydnaceutjvell2ckkq"


def get_blacklisted_ips(compartment_ocid: str, min_confidence: int = 50, max_limit: int = 1000) -> list[str]:
    """
    Retrieves blacklisted IP addresses from OCI Threat Intelligence.

    Args:
        compartment_ocid (str): The OCID of the compartment.
        min_confidence (int): Minimum confidence level for indicators (default: 50).

    Returns:
        list[str]: List of deduplicated IP addresses.
    """
    config = oci.config.from_file(os.path.expanduser("~/.oci/config"), "DEFAULT")
    ti_client = oci.threat_intelligence.ThreatintelClient(config)

    resp = ti_client.list_indicators(
        compartment_id=compartment_ocid,
        type="IP_ADDRESS",
        confidence_greater_than_or_equal_to=min_confidence,
        limit=max_limit
    )

    ip_addresses = [item.value for item in resp.data.items if item.value]
    return list(set(ip_addresses))


def update_network_address_list(ips: list[str]) -> object:
    """
    Updates the hardcoded Network Address List with new IP addresses.

    Args:
        ips (list[str]): List of IP addresses to block.

    Returns:
        object: The updated Network Address List object.
    """
    config = oci.config.from_file(os.path.expanduser("~/.oci/config"), "DEFAULT")
    waf_client = oci.waf.WafClient(config)

    try:
        addr_list = waf_client.get_network_address_list(NETWORK_ADDRESS_LIST_OCID).data
    except oci.exceptions.ServiceError as e:
        print(f"ERROR: Failed to get Network Address List with OCID {NETWORK_ADDRESS_LIST_OCID}.")
        print(f"Exception details: {e}")
        raise

    print(f"Updating Network Address List '{addr_list.display_name}'...")

    update_details = UpdateNetworkAddressListAddressesDetails(addresses=ips)

    try:
        waf_client.update_network_address_list(addr_list.id, update_details)

        print("Waiting for update to complete...")
        for i in range(12):
            addr_list_resp = waf_client.get_network_address_list(addr_list.id)
            addr_list = addr_list_resp.data

            if addr_list.lifecycle_state == 'ACTIVE':
                print("Network Address List updated successfully.")
                break
            elif addr_list.lifecycle_state == 'FAILED':
                raise Exception("Network Address List update failed. Check OCI Console for details.")

            time.sleep(5)
        else:
            raise Exception("Network Address List did not update within timeout.")

    except oci.exceptions.ServiceError as e:
        print(f"ERROR: Failed to update Network Address List.")
        print(f"Exception details: {e}")
        raise

    return addr_list


if __name__ == "__main__":
    compartment_ocid = "ocid1.compartment.oc1..aaaaaaaatyqrz5n2tdxc554iktvqwwtnoe5ck4gvaxpf6hjcvg6g7k3g3opq"

    try:
        print("Getting blacklisted IPs from Threat Intelligence...")
        ips = get_blacklisted_ips(compartment_ocid, min_confidence=50)
        print(f"Found {len(ips)} blacklisted IPs: {json.dumps(ips)}")

        if ips:
            print("Updating Network Address List...")
            update_network_address_list(ips)
            print("Update complete.")
        else:
            print("No blacklisted IPs found.")

    except oci.exceptions.ServiceError as e:
        print(f"OCI Service Error - {e.code}: {e.message}")
        print("Ensure correct OCID values, API key config (~/.oci/config), and permissions.")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)
