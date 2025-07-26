# MIT License
#
# Copyright (c) 2025 NagicHall
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from mitmproxy.http import HTTPFlow
from mitmproxy.connection import Client
from ja3 import process_clienthello
import logging

logger = logging.getLogger(__name__)

# mitmproxy doesn't have a way to pass information up a layer.
context_map = {}


class Ja3Addon:
    """
    sets flow.ja3 to a dict with the ja3 fingerprint & digest for https (not for http!) requests
    """

    def tls_clienthello(self, flow) -> None:
        client_id = flow.context.client.id

        clienthello = flow.client_hello.raw_bytes(wrap_in_record=False)
        ja3 = process_clienthello(clienthello)

        context_map[client_id] = ja3
        logger.debug(f"set ja3 for client {client_id}")

    def request(self, flow: HTTPFlow) -> None:
        client_id = flow.client_conn.id
        ja3 = context_map.get(client_id)
        if ja3:
            logger.debug(f"http request ja3 {ja3}")
            flow.ja3 = ja3

    def client_disconnected(self, client: Client):
        client_id = client.id
        if client_id in context_map:
            logger.debug(f"client {client_id} disconnected, removing ja3")
            del context_map[client_id]


addons = [Ja3Addon()]
