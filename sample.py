import requests



INTELLINA_SERVER_IP = "127.0.0.1"
INTELLINA_SERVER_PORT = 51034

# 1. Query Ipv4 and port
RequestUri = "/network/ipv4port"
Output = requests.get(
    f"http://{INTELLINA_SERVER_IP}:{INTELLINA_SERVER_PORT}{RequestUri}",
    params={
        "Ipv4": "158.94.208.219",
        "Port": 54982
    }
).json()

'''
{
  "is_success": true,
  "result": {
    "threatfox": [
      {
        "Primaryid": "16304612025-10-3119:40:03UTC",
        "id": "1630461",
        "ioc_value": "157.20.182.47:7707",
        "ioc_type": "ip:port",
        "ioc_desc": "ip:port combination that is used for botnet Command&control (C&C)",
        "threat_type": "botnet_cc",
        "malware": "win.asyncrat",
        "malware_alias": "None",
        "malware_printable": "AsyncRAT",
        "first_seen_utc": "2025-10-31 19:40:03 UTC",
        "last_seen_utc": "2025-11-04 12:44:32 UTC",
        "confidence_level": 100,
        "refer": "None",
        "tags": "asyncrat,RAT",
        "reporter": "abuse_ch"
      }
    ]
  }
}
'''
print(Output)



###############################################################################################
"""
# 2. Query only Ipv4
RequestUri = "/network/ipv4"
Output = requests.get(
    f"http://{INTELLINA_SERVER_IP}:{INTELLINA_SERVER_PORT}{RequestUri}",
    params={
        "Ipv4": "99.44.61.231"
    }
).json()

'''
{
  "is_success": true,
  "result": {
    "otx": [
      {
        "Primaryid": "68f42b89569812429dbf6b924136541480",
        "id": "68f42b89569812429dbf6b92",
        "name": "Malware Filter - Botnet List - 18-10-2025",
        "description": "",
        "author_name": "CyberHunterAutoFeed",
        "modified": "2025-10-19T00:06:32.678000",
        "created": "2025-10-19T00:06:32.678000",
        "revision": 1,
        "tlp": "green",
        "public": 1,
        "adversary": "",
        "indicators_id": 4136541480,
        "indicators_indicator": "99.44.61.231",
        "indicators_type": "IPv4",
        "indicators_created": "2025-10-19T00:06:34",
        "indicators_content": "",
        "indicators_title": "",
        "indicators_description": "",
        "indicators_expiration": "2025-11-18T00:00:00",
        "indicators_is_active": 1,
        "indicators_role": null,
        "tags": "",
        "targeted_countries": "",
        "malware_families": "",
        "attack_ids": "",
        "reference_list": "https://malware-filter.gitlab.io/malware-filter/botnet-filter.txt",
        "industries": "",
        "extract_source": ""
      }
    ]
  }
}
'''
print(Output)



###############################################################################################



# 2. Query only Ipv4
RequestUri = "/file/sha256"
Output = requests.get(
    f"http://{INTELLINA_SERVER_IP}:{INTELLINA_SERVER_PORT}{RequestUri}",
    params={
        "Sha256": "08a25e1e926752f15b0e2fc79ce07ec41656b6fb55a3da4c0b579a8dc3face0e"
    }
).json()

print(Output)"""