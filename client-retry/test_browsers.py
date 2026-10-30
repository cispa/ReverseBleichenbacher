#!/usr/bin/env python3
'''Automated browser retry testing using Selenium.'''

import argparse
import json
import os
import subprocess
import sys
import time

from selenium import webdriver
from selenium.webdriver.firefox.options import Options as FirefoxOptions

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def test_firefox(url, wait=35):
    opts = FirefoxOptions()
    opts.add_argument('--headless')
    opts.accept_insecure_certs = True

    driver = webdriver.Firefox(options=opts)
    try:
        print(f'Firefox navigating to {url}')
        driver.get(url)
        print(f'Waiting {wait}s for retries to complete...')
        time.sleep(wait)
    finally:
        driver.quit()


def run_test(fail_mode, domain='lvh.me', frontend_port=8080, backend_port=8443,
             quiet_period=30, wait=35):
    results_file = os.path.join(SCRIPT_DIR, f'results_{fail_mode}.jsonl')
    server = subprocess.Popen(
        [sys.executable, os.path.join(SCRIPT_DIR, 'server.py'),
         '--domain', domain,
         '--frontend-port', str(frontend_port),
         '--backend-port', str(backend_port),
         '-q', str(quiet_period),
         '--fail-mode', fail_mode,
         '-o', results_file],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    time.sleep(2)

    url = f'http://localhost:{frontend_port}/'
    try:
        test_firefox(url, wait=wait)
    except Exception as e:
        print(f'  Error: {e}')
    finally:
        time.sleep(quiet_period + 5)
        server.terminate()
        stdout, _ = server.communicate(timeout=5)
        print(stdout)

    try:
        with open(results_file) as f:
            lines = [json.loads(l) for l in f if l.strip()]
        conns = [l for l in lines if l.get('ciphertext_hash')]
        return {
            'fail_mode': fail_mode,
            'total_connections': len(conns),
            'unique_pms': len(set(l['ciphertext_hash'] for l in conns)),
            'has_pms': any(l.get('ciphertext_hash') for l in conns),
        }
    except FileNotFoundError:
        return {'fail_mode': fail_mode, 'total_connections': 0, 'unique_pms': 0, 'has_pms': False}


def main():
    p = argparse.ArgumentParser(description='Automated browser retry test')
    p.add_argument('--modes', nargs='+',
                   default=['reset', 'close', 'alert', 'bad_mac',
                            'decode_error', 'internal_error', 'close_notify', 'garbage'],
                   help='Fail modes to test')
    p.add_argument('--domain', default='lvh.me')
    p.add_argument('--wait', type=int, default=35,
                   help='Seconds to wait for retries per test')
    args = p.parse_args()

    results = []
    for mode in args.modes:
        print(f'\n{"="*60}')
        print(f'Testing fail_mode={mode}')
        print(f'{"="*60}')
        r = run_test(mode, domain=args.domain, wait=args.wait)
        results.append(r)
        print(f'  -> {r["total_connections"]} connections, {r["unique_pms"]} unique PMS')
        time.sleep(2)  # let ports free up

    print(f'\n{"="*60}')
    print('SUMMARY')
    print(f'{"="*60}')
    print(f'{"Mode":<20} {"Connections":<15} {"Unique PMS":<15}')
    print('-' * 50)
    for r in results:
        print(f'{r["fail_mode"]:<20} {r["total_connections"]:<15} {r["unique_pms"]:<15}')


if __name__ == '__main__':
    main()
