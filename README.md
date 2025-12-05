# WAF Threat Intelligence IP Updater

This Python script automatically updates a predefined Oracle Cloud Infrastructure (OCI) Web Application Firewall (WAF) Network Address List with blacklisted IP addresses retrieved from OCI Threat Intelligence.

## Features

- Fetches IP addresses from OCI Threat Intelligence with a confidence score of 50 or higher.
- Deduplicates IPs before updating.
- Updates the existing Network Address List (hardcoded OCID) by replacing its addresses.
- Waits for the update to complete asynchronously.
- Provides clear error handling and logging.

## Prerequisites

- Oracle Cloud Infrastructure (OCI) CLI installed and configured.
- OCI config file at `~/.oci/config` with appropriate permissions.
- OCI Python SDK installed.

## Usage

1. Clone the repository.
2. Ensure your OCI setup is correct.
3. Run the script: `python WafTest.py`
4. The hardcoded Network Address List will be updated with fresh blacklisted IPs.

## Configuration

- Update `NETWORK_ADDRESS_LIST_OCID` with your WAF Network Address List OCID.
- Adjust `compartment_ocid` if needed.
- Modify `min_confidence` (default: 50) to change the threat detection threshold.

## Functions

- `get_blacklisted_ips(compartment_ocid, min_confidence=50)`: Retrieves and deduplicates blacklisted IPs.
- `update_network_address_list(ips)`: Updates the network address list with new IPs.

Note: The code is hardcoded for simplicity and assumes the network address list exists.
