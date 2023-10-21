import threading, argparse, os
from urllib.parse import urlparse

import requests
from tqdm import tqdm

parser = argparse.ArgumentParser(
    description="A Naive Speed Tester",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter
)
parser.add_argument("-H", "--host", help="override hostname in SNI (e.g., a.speedtest.com)", type=str, default=None)
parser.add_argument("-i", "--ip", help="override ip address (e.g., 222.28.152.253)", type=str, default=None)
parser.add_argument("-n", "--num-threads", help="number of threads to use", type=int, default=1)
parser.add_argument("-u", "--url", help="url to test", type=str, default="https://changeme/client_app/download/pc_zip/20230916101725_v2XCKuuvzCVh3BdI/GenshinImpact_4.1.0.zip.001")
args = parser.parse_args()

dns_map = {}
def patch_dns():
    import urllib3
    from urllib3.util import connection
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    _orig_create_connection = connection.create_connection
    def patched_create_connection(address, *args, **kwargs):
        host, port = address
        host = dns_map.get(host, host)
        return _orig_create_connection((host, port), *args, **kwargs)
    connection.create_connection = patched_create_connection

url = args.url
resp = requests.get(url, stream=True)
size = int(resp.headers["Content-Length"])
remote_addr = resp.raw._connection.sock.getpeername()
if args.ip:
    remote_addr = (args.ip, remote_addr[1])
print("Testing {}".format(remote_addr))
resp.close()
factor = 8
sem = threading.Semaphore(value=args.num_threads)

bar = tqdm(total=size * factor, unit="B", unit_scale=True, unit_divisor=1024, smoothing=0)

parsed = urlparse(url)
dns_map[parsed.netloc] = remote_addr[0]
custom_domain = args.host
if custom_domain:
    replaced = parsed._replace(netloc=parsed.netloc.replace(parsed.hostname, custom_domain))
    dns_map[custom_domain] = remote_addr[0]
    url = replaced.geturl()

def worker():
    with sem:
        try:
            resp = requests.get(url, headers={
                "host": parsed.hostname
            }, stream=True, verify=False)
        except requests.exceptions.SSLError:
            print("\nSSL Error, please also try overriding the ip address")
            os._exit(1)
        for chunk in resp.iter_content(chunk_size=8192):
            bar.update(len(chunk))

patch_dns()
T = [threading.Thread(target=worker, daemon=True) for i in range(factor)]
for t in T:
    t.start()

try:
    for t in T:
        while t.is_alive():
            t.join(0.1)
except KeyboardInterrupt:
    pass
