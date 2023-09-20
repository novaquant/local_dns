"""
生成本地的DNS文件，供平台使用：
1. 定时从scan server拉取本机所需的local dns
2. 指定专线IP
3. 将以上内容合并输出到DNS文件中
4. 在某些case情况下，检查IP的存活性

输出的DNS文件中存在两类DNS结果，一类是无使用代价的，比如ws-api.binance.com，另一类是有代价的，比如使用专线访问 api.bybit.com 。
对于无使用代价的场景，应该尽量多使用DNS文件中的IP，对于有使用代价的场景，则应该给DNS name添加特殊后缀，只有主动启用才使用。
DNS name的特殊后缀以组件命名，比如：
* `:trader`: 供trader使用的DNS
* `:counter`: 供counter使用的DNS
* 其他后缀见`dns.h`

DNS格式参考：https://bitbucket.pinghu.tech/projects/CRYPTO/repos/crypto-scan-ip/browse
除上面文件中说明的DNS格式之外，还支持alias:
```
{
    "name": "xxxxx",
    "alias": "yyyyyy"
}
```
"""
from __future__ import annotations
import json
import time
import traceback
import requests
from pathlib import Path
import dns.resolver
import socket
import functools
from typing import Callable
import copy
from crypto.ipc import Logger

hostname = socket.gethostname()
LOCAL_DNS_FILEPATH = "/var/tmp/local_dns.json"

working_directory = Path(__file__).resolve().parent.absolute()
log_directory = working_directory / "logs"
logger = Logger((log_directory / "local_dns").__str__(), verbose=False, rotate=False)


class DNSTask:
    """
    表示一个获取DNS的任务，会被定期执行，并且会检查其DNS结果和之前的DNS结果是否相同。
    如果DNS有更新，则会自动将其和其他DNS合并输出成一个DNS文件，以便平台使用。
    """

    def __init__(self, func: Callable[[], dict], generate_interval: float) -> None:
        self.func = func  # 生成DNS时被调用的函数
        self.generate_interval = generate_interval  # 间隔多久调用一次生成函数，单位：秒

        # 保存DNS状态
        self.dns: dict = None  # 生成的DNS
        self.last_call_timestamp: float = 0  # 上次生成DNS的时间


# 所有获取DNS的任务列表
dns_tasks: dict[str, DNSTask] = {}


def gen_dns_from_dns_resolver(domain: str,rename: str = None):
    """
    解析DNS从而生成DNS结果
    """
    resolver = dns.resolver.Resolver()
    ips = []
    for i in resolver.resolve(domain):
        r = str(i.to_text())
        ips.append({"domain": domain, "ip": r})
    ips = sorted(ips, key=lambda item: item["ip"])
    d = {}
    d = {"update_time": int(time.time()), "ips": ips}
    if rename is not None:
        d["name"] = rename
    return d


# 币安的VIP域名
if hostname.startswith("jp"):
    for i in [3, 6, 7, 8, 9, 13]:
        dns_tasks[f"fapi{i}.binance.com"] = DNSTask(functools.partial(gen_dns_from_dns_resolver, f"fapi{i}.binance.com"), 60 * 60)
        dns_tasks[f"dapi{i}.binance.com"] = DNSTask(functools.partial(gen_dns_from_dns_resolver, f"dapi{i}.binance.com"), 60 * 60)


def gen_dns_from_scan_server(server: str, name: str, *, rename: str = None):
    """
    向scan server请求DNS
    """
    r = requests.get(f"http://{server}:10053/dns", params={"name": name}, timeout=10)
    dns = json.loads(r.text)
    if rename is not None:
        dns["name"] = rename
    return dns


# SCAN_SERVER_TOKYO_A = "172.31.39.154"  # jp96，位于东京A区的扫描服务器
# 币安现货websocket下单
dns_tasks["ws-api.binance.com"] = DNSTask(functools.partial(gen_dns_from_dns_resolver, "ws-api.binance.com"), 60)
# 币安合约REST接口
dns_tasks["fapi.binance.com"] = DNSTask(functools.partial(gen_dns_from_dns_resolver, "fapi.binance.com"), 60)
# 币安行情接口
for mode in ["stream", "fstream", "dstream"]:
    dns_tasks[f"{mode}.binance.com"] = DNSTask(functools.partial(gen_dns_from_dns_resolver, f"{mode}.binance.com", rename=f"{mode}.binance.com:marketdata"), 60)


def gen_dns_from_static_ips(ips: list, *, always_valid = True):
    """
    指定静态IP地址
    """
    return {"update_time": int(time.time()), "always_valid": always_valid, "ips": ips}



dns_tasks["ws.okx.com"] = DNSTask(functools.partial(gen_dns_from_dns_resolver, "ws.okx.com"), 60)
# 币安合约REST接口
dns_tasks["www.okx.com"] = DNSTask(functools.partial(gen_dns_from_dns_resolver, "www.okx.com"), 60)

# # Bybit的下单专线
# if hostname in ["jp06", "jp13", "jp16"] or hostname == "jp08":
#     bybit_swap_proxy_ip = ["172.15.8.238", "172.15.6.155", "172.15.10.251", "172.15.4.202", "172.15.6.215", "172.15.14.169"]
#     # 只允许trader使用
#     dns_tasks["api.bybit.com:trader"] = DNSTask(
#         functools.partial(gen_dns_from_static_ips, [{
#             "domain": "api.bybit.com",
#             "ip": ip
#         } for ip in bybit_swap_proxy_ip], always_valid=False),
#         60 * 60 * 24 * 365,
#     )

# # OKEx的回报专线
# if hostname in ["jp06", "jp13", "jp16"] or hostname == "jp08":
#     # TODO: counter现在还没有使用本DNS
#     dns_tasks["ws.okx.com:counter"] = DNSTask(
#         functools.partial(gen_dns_from_static_ips, [{
#             "domain": "ws.okx.com",
#             "ip": ip
#         } for ip in ["192.168.14.1"]]),
#         60 * 60 * 24 * 365,
#     )

# # OKEx的colo
# if hostname.startswith("hk") or hostname == "jp08":
#     dns_tasks["ws.okx.com"] = DNSTask(
#         functools.partial(gen_dns_from_static_ips, ["192.168.2.28"]),
#         60 * 60 * 24 * 365,
#     )


def run_once():
    """
    运行一次
    """
    updated = False  # 本轮是否有更新
    for name, task in dns_tasks.items():
        try:
            if time.time() - task.last_call_timestamp > task.generate_interval:
                dns = task.func()
                assert isinstance(dns, dict), f"{dns=} is not a dict"
                if "name" not in dns:
                    dns["name"] = name
                task.last_call_timestamp = time.time()

                old_dns = copy.deepcopy(task.dns) if task.dns else {}
                new_dns = copy.deepcopy(dns)
                if "update_time" in old_dns:
                    del old_dns["update_time"]
                if "update_time" in new_dns:
                    del new_dns["update_time"]

                if new_dns != old_dns:  # 有更新
                    # print(f"DNS for {name} is updated as {dns}")
                    task.dns = dns
                    updated = True
        except Exception as e:
            print(traceback.format_exc())

    if updated:
        with open(LOCAL_DNS_FILEPATH, "w") as fd:
            json.dump([task.dns for task in dns_tasks.values() if task.dns is not None], fd, indent=4)



if __name__ == "__main__":
    print("=========================================")
    print(f"start local_dns on {hostname}")
    while True:
        run_once()
        time.sleep(10)
