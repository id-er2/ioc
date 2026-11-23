import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import ioc


class Extraction(unittest.TestCase):
    def test_urls(self):
        r=ioc.extract('See https://example.com/path?a=1 and http://other.example/.')
        self.assertEqual(r['counts']['url'],2)
        self.assertIn('hxxps://example[.]com/path?a=1',r['indicators']['url'])
        self.assertIn('example[.]com',r['indicators']['domain'])

    def test_domains_punctuation(self):
        r=ioc.extract('example.com. (sub.example.org), other.example;')
        self.assertEqual(r['indicators']['domain'],['example[.]com','other[.]example','sub[.]example[.]org'])

    def test_domains_case(self):
        r=ioc.extract('Example.COM example.com EXAMPLE.COM')
        self.assertEqual(r['counts']['domain'],1)

    def test_email(self):
        r=ioc.extract('Person+tag@EXAMPLE.com. test@example.org')
        self.assertIn('Person+tag[@]example[.]com',r['indicators']['email'])
        self.assertEqual(r['counts']['domain'],2)

    def test_ipv4(self):
        r=ioc.extract('192.0.2.1 127.0.0.1 999.0.0.1 1.2.3 192.0.2.1')
        self.assertEqual(r['indicators']['ipv4'],['127[.]0[.]0[.]1','192[.]0[.]2[.]1'])

    def test_ipv4_trailing_period(self):
        r=ioc.extract('From 192.0.2.1. Also 10.0.0.1, end')
        self.assertEqual(r['indicators']['ipv4'],['10[.]0[.]0[.]1','192[.]0[.]2[.]1'])

    def test_ipv4_trailing_period_not_longer_token(self):
        for value in ['1.2.3.4.5','192.0.2.1.com','192.0.2.1.','x192.0.2.1']:
            with self.subTest(value=value):
                self.assertEqual(ioc.extract(value)['counts']['ipv4'],1 if value=='192.0.2.1.' else 0)

    def test_ipv6(self):
        r=ioc.extract('[2001:db8::1] ::1 2001:0db8:0:0:0:0:0:1')
        self.assertEqual(r['counts']['ipv6'],2)
        self.assertIn('2001[:]db8[:][:]1',r['indicators']['ipv6'])

    def test_ipv6_url(self):
        r=ioc.extract('http://[2001:db8::1]/')
        self.assertEqual(r['counts']['url'],1)
        self.assertIn('hxxp://[2001:db8::1]/',r['indicators']['url'])

    def test_hash_lengths(self):
        for length in [32,40,64,96,128]:
            r=ioc.extract('A'*length)
            self.assertEqual(r['indicators']['hash'],['a'*length])
        for length in [31,33,39,41,63,65,95,97,127,129]:
            with self.subTest(length=length):self.assertEqual(ioc.extract('a'*length)['counts']['hash'],0)

    def test_refanged_input(self):
        r=ioc.extract('hxxps://example[.]com/path a[@]mail(.)example 192[.]0[.]2[.]1')
        self.assertEqual(r['counts']['url'],1);self.assertEqual(r['counts']['email'],1)
        self.assertEqual(r['counts']['ipv4'],1)

    def test_raw(self):
        r=ioc.extract('hxxp://example[.]com',raw=True)
        self.assertFalse(r['defanged']);self.assertEqual(r['indicators']['url'],['http://example.com'])

    def test_bad_urls(self):
        for value in ['https://user:pass@example.com/','http://[bad]/','https://example.com:bad/']:
            with self.subTest(value=value):self.assertEqual(ioc.extract(value)['counts']['url'],0)

    def test_no_network(self):
        with patch('socket.getaddrinfo',side_effect=AssertionError('network called')):
            self.assertGreater(ioc.extract('https://example.com')['total'],0)

    def test_empty(self):
        self.assertEqual(ioc.extract('just words')['total'],0)

    def test_input_limit(self):
        with self.assertRaises(ioc.IOCError):ioc.extract('a'*(ioc.MAX_BYTES+1))
        with self.assertRaises(ioc.IOCError):ioc.extract('م'*ioc.MAX_BYTES)

    def test_item_limit(self):
        with self.assertRaises(ioc.IOCError):
            ioc.extract(' '.join(f'host{i}.example' for i in range(5001)))

    def test_defang_ipv6(self):
        self.assertEqual(ioc.defang('::1','ipv6'),'[:][:]1')

    def test_terminal(self):
        self.assertEqual(ioc.safe_text('x\x1b[31m'),r'x\x1b[31m')


class CLI(unittest.TestCase):
    def run_cli(self,args,text=b''):
        return subprocess.run([sys.executable,os.path.join(os.path.dirname(__file__),'ioc.py')]+args,input=text,stdout=subprocess.PIPE,stderr=subprocess.PIPE)

    def test_json(self):
        p=self.run_cli(['--json'],b'example.com')
        self.assertEqual(p.returncode,0);self.assertTrue(json.loads(p.stdout)['defanged'])

    def test_empty(self):
        self.assertEqual(self.run_cli([],b'words').returncode,1)

    def test_invalid_utf8(self):
        p=self.run_cli(['--json'],b'\xff');self.assertEqual(p.returncode,2);self.assertIn('error',json.loads(p.stdout))

    def test_missing_file(self):
        self.assertEqual(self.run_cli(['/no/such/input']).returncode,2)

    def test_file(self):
        with tempfile.NamedTemporaryFile() as f:
            f.write(b'test@example.com');f.flush()
            p=self.run_cli([f.name,'--json']);self.assertEqual(p.returncode,0)
            self.assertEqual(json.loads(p.stdout)['counts']['email'],1)


if __name__=='__main__':unittest.main()
