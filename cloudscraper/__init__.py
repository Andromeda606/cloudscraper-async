import logging
import sys
from requests_toolbelt.utils import dump
from urllib.parse import urlparse

import aiohttp
import brotli
from aiohttp import ClientSession

from cloudscraper.cloudflare import Cloudflare
from cloudscraper.exceptions import CloudflareLoopProtection, CloudflareIUAMError
from cloudscraper.user_agent import User_Agent


class CloudScraper:
    def __init__(self, *args, **kwargs):
        self.debug = kwargs.pop('debug', False)
        self.disableCloudflareV1 = kwargs.pop('disableCloudflareV1', False)
        self.delay = kwargs.pop('delay', None)
        self.captcha = kwargs.pop('captcha', {})
        self.doubleDown = kwargs.pop('doubleDown', True)
        self.interpreter = kwargs.pop('interpreter', 'native')
        self.requestPreHook = kwargs.pop('requestPreHook', None)
        self.requestPostHook = kwargs.pop('requestPostHook', None)
        self.cipherSuite = kwargs.pop('cipherSuite', None)
        self.ecdhCurve = kwargs.pop('ecdhCurve', 'prime256v1')
        self.source_address = kwargs.pop('source_address', None)
        self.server_hostname = kwargs.pop('server_hostname', None)
        self.ssl_context = kwargs.pop('ssl_context', None)
        self.allow_brotli = kwargs.pop('allow_brotli', True)
        self.user_agent = User_Agent(
            allow_brotli=self.allow_brotli,
            browser=kwargs.pop('browser', None)
        )
        self._solveDepthCnt = 0
        self.solveDepth = kwargs.pop('solveDepth', 3)

        self.session = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.session.close()

    async def perform_request(self, method, url, *args, **kwargs):
        return await self.session.request(method, url, *args, **kwargs)

    async def decode_brotli(self, resp):
        if aiohttp.__version__ < '3.7.0' and resp.headers.get('Content-Encoding') == 'br':
            if self.allow_brotli and resp.content:
                resp.content = brotli.decompress(await resp.read())
            else:
                logging.warning(
                    f'You\'re running aiohttp {aiohttp.__version__}, Brotli content detected, '
                    'which requires manual decompression, '
                    'but option allow_brotli is set to False, '
                    'we will not continue to decompress.'
                )

        return resp

    async def request(self, method, url, *args, **kwargs):
        if kwargs.get('proxy') and kwargs.get('proxy') != self.session.connector.proxy:
            self.session.connector.proxy = kwargs.get('proxy')

        if self.requestPreHook:
            (method, url, args, kwargs) = await self.requestPreHook(
                self,
                method,
                url,
                *args,
                **kwargs
            )

        response = await self.decode_brotli(
            await self.perform_request(method, url, *args, **kwargs)
        )

        if self.debug:
            self.debug_request(response)

        if self.requestPostHook:
            new_response = await self.requestPostHook(self, response)

            if response != new_response:
                response = new_response
                if self.debug:
                    print('==== requestPostHook Debug ====')
                    self.debug_request(response)

        if not self.disableCloudflareV1:
            cloudflareV1 = Cloudflare(self)

            if cloudflareV1.is_Challenge_Request(response):
                if self._solveDepthCnt >= self.solveDepth:
                    _ = self._solveDepthCnt
                    self.simpleException(
                        CloudflareLoopProtection,
                        f"!!Loop Protection!! We have tried to solve {_} time(s) in a row."
                    )

                self._solveDepthCnt += 1

                response = cloudflareV1.Challenge_Response(response, **kwargs)
            else:
                if not (response.status == 301 or response.status == 302) and response.status not in [429, 503]:
                    self._solveDepthCnt = 0

        return response

    async def get(self, url, *args, **kwargs):
        return await self.request('GET', url, *args, **kwargs)

    async def post(self, url, *args, **kwargs):
        return await self.request('POST', url, *args, **kwargs)

    async def put(self, url, *args, **kwargs):
        return await self.request('PUT', url, *args, **kwargs)

    async def delete(self, url, *args, **kwargs):
        return await self.request('DELETE', url, *args, **kwargs)

    @staticmethod
    def debug_request(req):
        try:
            print(dump.dump_all(req).decode('utf-8', errors='backslashreplace'))
        except ValueError as e:
            print(f"Debug Error: {getattr(e, 'message', e)}")

    def simple_exception(self, exception, msg):
        self._solveDepthCnt = 0
        sys.tracebacklimit = 0
        raise exception(msg)

    @classmethod
    async def create_scraper(cls, sess=None, **kwargs):
        scraper = cls(**kwargs)

        if sess:
            for attr in ['auth', 'cookies', 'headers', 'params', 'proxies', 'data']:
                val = getattr(sess, attr, None)
                if val is not None:
                    setattr(scraper, attr, val)

        return scraper

    @classmethod
    async def get_tokens(cls, url, **kwargs):
        async with cls.create_scraper(**{
            field: kwargs.pop(field, None) for field in [
                'allow_brotli',
                'browser',
                'debug',
                'delay',
                'doubleDown',
                'captcha',
                'interpreter',
                'source_address',
                'requestPreHook',
                'requestPostHook'
            ] if field in kwargs
        }) as scraper:
            resp = await scraper.get(url, **kwargs)
            resp.raise_for_status()

            domain = urlparse(resp.url).netloc
            cookie_domain = None

            for d in scraper.session.cookie_jar._cookies:
                if d.startswith('.') and d in (f'.{domain}'):
                    cookie_domain = d
                    break
            else:
                cls.simple_exception(
                    cls,
                    CloudflareIUAMError,
                    "Unable to find Cloudflare cookies. Does the site actually "
                    "have Cloudflare IUAM (I'm Under Attack Mode) enabled?"
                )

            return (
                {
                    'cf_clearance': scraper.session.cookie_jar.filter_cookies(url).get('cf_clearance', '').value
                },
                scraper.headers['User-Agent']
            )

    @classmethod
    async def get_cookie_string(cls, url, **kwargs):
        tokens, user_agent = await cls.get_tokens(url, **kwargs)
        return '; '.join('='.join(pair) for pair in tokens.items()), user_agent


create_scraper = CloudScraper.create_scraper
session = CloudScraper.create_scraper
get_tokens = CloudScraper.get_tokens
get_cookie_string = CloudScraper.get_cookie_string
