class TestAddon:
    def request(self, flow):
        is_https = hasattr(flow, "ja3")
        if is_https:
            print(flow.ja3)
        else:
            print("recieved a plain http request, no ja3 fingerprint")


addons = [TestAddon()]
