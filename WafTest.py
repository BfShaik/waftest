import os
import json
import oci

def get_blacklisted_ips(compartment_ocid: str, min_confidence: int = 50):
    # Instance Principals signer
    # signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()

    # Create Threat Intelligence client; region comes from the signer context
    # ti_client = oci.threat_intelligence.ThreatintelClient(config={}, signer=signer)
    
    config = oci.config.from_file(".oci/config", "DEFAULT")
    ti_client = oci.threat_intelligence.ThreatintelClient(config)

    #signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
    #ti_client = oci.threat_intelligence.ThreatintelClient(config={}, signer=signer)
    
    
    
    # Collect all IP indicators with confidence >= min_confidence
    ip_addresses = []

    list_kwargs = {
        "compartment_id": compartment_ocid,
        "type": "IP_ADDRESS",
        "confidence_greater_than_or_equal_to": min_confidence,
        "limit": 100
    }

    resp = ti_client.list_indicators(
        compartment_id=compartment_ocid,
        type="IP_ADDRESS",
        confidence_greater_than_or_equal_to=min_confidence,
        limit=10 # single call max
    )

    #print(resp.data)
    
    for item in resp.data.items:
        if item.value:
            ip_addresses.append(item.value)

    # Deduplicate while preserving order
    seen = set()
    deduped_ips = []
    for ip in ip_addresses:
        if ip not in seen:
            seen.add(ip)
            deduped_ips.append(ip)

    return deduped_ips 

if __name__ == "__main__":
    # The original code had `if name == "main":` which should be `if __name__ == "__main__":`
    compartment_ocid = "ocid1.compartment.oc1..aaaaaaaatyqrz5n2tdxc554iktvqwwtnoe5ck4gvaxpf6hjcvg6g7k3g3opq"

    if not compartment_ocid or compartment_ocid.startswith("<"):
        raise ValueError("Please set COMPARTMENT_OCID environment variable or replace the placeholder.")

    ips = get_blacklisted_ips(compartment_ocid, min_confidence=50)

    # Print as a JSON array of strings
    print(json.dumps(ips))
