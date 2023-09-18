import requests
import logging
import urllib3
import sys

from time import sleep
from dotenv import dotenv_values

config = dotenv_values(".env")
adguard_host = config.get("ADGUARD_HOST")
adguard_username = config.get("ADGUARD_USERNAME")
adguard_password = config.get("ADGUARD_PASSWORD")
pve_domain = config.get("PVE_DOMAIN")
pve_node_ips = config.get("PVE_NODE_IPS").split(",")

base_url = f"http://{adguard_host}/control"
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

urllib3.disable_warnings()

class AdGuardException(Exception):
    pass

class AdGuardLoginException(AdGuardException):
    pass

class AdGuard:
    cookie = None

    def __init__(self, base_url, username, password) -> None:
        self.base_url = base_url
        self.username = username
        self.password = password
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "MaoMaoBot/1.0"
        }
        self.cookie = self.login()
        
    def login(self) -> dict:
        r = requests.post(
            f"{self.base_url}/login",
            json={"name": self.username, "password": self.password},
            headers=self.headers
        )
        if r.status_code != 200:
            raise AdGuardLoginException(f"Login failed: {r.status_code} {r.content.decode('utf-8')}")
        return r.cookies.get_dict()

    def status(self) -> str:
        response = requests.get(f"{self.base_url}/status", cookies=self.cookie, headers=self.headers)
        if response.status_code != 200:
            raise AdGuardException(f"Status failed: {response.status_code} {response.content.decode('utf-8')}")
        return response.content.decode("utf-8")

    def get_rewrite_list(self) -> list:
        response = requests.get(f"{self.base_url}/rewrite/list", cookies=self.cookie, headers=self.headers)
        if response.status_code != 200:
            raise AdGuardException(f"Get rewrite list failed: {response.status_code} {response.content.decode('utf-8')}")
        return response.json()
    
    def set_rewrite(self, domain, answer) -> bool:
        response = requests.post(
            f"{self.base_url}/rewrite/add",
            json={"domain": domain, "answer": answer},
            cookies=self.cookie,
            headers=self.headers
        )
        return response.status_code == 200
    
    def delete_rewrite(self, domain, answer) -> bool:
        response = requests.post(
            f"{self.base_url}/rewrite/delete",
            json={"domain": domain, "answer": answer},
            cookies=self.cookie,
            headers=self.headers
        )
        return response.status_code == 200


def get_current_pve():
    for domain in adguard.get_rewrite_list():
        if domain["domain"] == pve_domain:
            return domain["answer"]
    return None

def check_pve_node(ip):
    try:
        r = requests.get(f"https://{ip}:8006/api2/json/access/ticket", timeout=5, verify=False)
        logger.debug(f"Check {ip}: {r.status_code}")
        return r.status_code == 200
    except:
        return False

adguard = AdGuard(base_url, adguard_username, adguard_password)
while True:
    current_master_pve = get_current_pve()
    logger.info(f"Current master PVE: {current_master_pve}")

    if not current_master_pve or current_master_pve not in pve_node_ips:
        if current_master_pve:
            adguard.delete_rewrite(pve_domain, current_master_pve)
        adguard.set_rewrite(pve_domain, pve_node_ips[0])
        logger.info(f"Switched to {pve_node_ips[0]}")
        current_master_pve = pve_node_ips[0]
    
    if check_pve_node(current_master_pve) is False:
        for ip in pve_node_ips:
            if check_pve_node(ip) is True:
                adguard.delete_rewrite(pve_domain, current_master_pve)
                adguard.set_rewrite(pve_domain, ip)
                logger.info(f"Switched to {ip}")
                break
    sleep(60)