# tools/otx_lookup.py
"""
AlienVault OTX Threat Intelligence Tool.

Used by: Analysis agent (agents/analysis.py)
Job: Given a source IP, return structured threat intel.
     Tells the LLM whether this IP is a known bad actor before it reasons.
"""
import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config 
from OTXv2 import OTXv2, IndicatorTypes


def lookup_ip(ip: str) -> dict:
    """
    Query OTX for threat intel on an IP address.

    Returns a clean summary dict — not the raw OTX response (which is massive).

    Verdict logic:
      5+ pulses  → "malicious"   (well-known bad actor)
      1-4 pulses → "suspicious"  (appears in some threat reports)
      0 pulses   → "clean"       (not in OTX database)
      error      → "unknown"     (couldn't reach OTX)
    """
    result = {
        "ip"              : ip,
        "found"           : False,
        "pulse_count"     : 0,
        "threat_types"    : [],
        "malware_families": [],
        "country"         : "unknown",
        "verdict"         : "unknown",
        "error"           : None,
    }

    try:
        otx  = OTXv2(config.OTX_API_KEY)
        data = otx.get_indicator_details_full(IndicatorTypes.IPv4, ip)

        # ── Pull pulse data ────────────────────────────────────────────────────
        general    = data.get("general", {})
        pulse_info = general.get("pulse_info", {})
        pulse_count = pulse_info.get("count", 0)
        pulses      = pulse_info.get("pulses", [])

        # ── Extract threat types + malware families from pulse tags ────────────
        # Cap at 10 pulses — enough signal without slowing the pipeline
        threat_types     = set()
        malware_families = set()

        for pulse in pulses[:10]:
            for tag in pulse.get("tags", []):
                threat_types.add(tag)
            for mw in pulse.get("malware_families", []):
                name = mw.get("display_name") or mw.get("id", "")
                if name:
                    malware_families.add(name)

        # ── Verdict ────────────────────────────────────────────────────────────
        if pulse_count >= 5:
            verdict = "malicious"
        elif pulse_count >= 1:
            verdict = "suspicious"
        else:
            verdict = "clean"

        result.update({
            "found"           : pulse_count > 0,
            "pulse_count"     : pulse_count,
            "threat_types"    : list(threat_types)[:10],
            "malware_families": list(malware_families)[:5],
            "country"         : general.get("country_code", "unknown"),
            "verdict"         : verdict,
        })

        print(f"  🌐 OTX → {ip} | {verdict.upper()} | {pulse_count} pulses | {general.get('country_code', '??')}")

    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
        result["verdict"] = "unknown"
        print(f"  ⚠️  OTX lookup failed for {ip}: {e}")

    return result


# ── Standalone test ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # 185.220.101.55 = known Tor exit node — should return multiple pulses
    TEST_IP = "185.220.101.55"
    print(f"Looking up {TEST_IP}...\n")

    result = lookup_ip(TEST_IP)

    for k, v in result.items():
        print(f"  {k}: {v}")

    print(f"\nVerdict: {result['verdict'].upper()}")