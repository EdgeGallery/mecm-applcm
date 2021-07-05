"""
# Copyright 2021 21CN Corporation Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""

# !python3
# -*- coding: utf-8 -*-

import time

import jwt

_JWT_PRIVATE_KEY = '-----BEGIN RSA PRIVATE KEY-----\n' \
                  'MIIEpAIBAAKCAQEAmesVPVWJmsRIzitiu6rsbbIfBbt3t97qiJ4yQH1bCHpYu+ab\n' \
                  '+Xs5heSnfFjHH8nZDAR0n2zvliztIvTDwl/2NF9+/loFvmQMrSv1dQQCOBc5qZ5r\n' \
                  'w/0o7Cq3buXHHJ7CwP0NnreK4N1sZ4oLBTQQe4ERkXhiBNVxAmnbgl7QuhemMV0g\n' \
                  'xPABSLLKGIrzYR7n8OFDCuSAyOcaoyxJihA/4Tkh+Vs82tWlFglV7UxtU2+3e5sN\n' \
                  '9u/TJ5J3qRZnYq/NWymix9RRD53vp1RGUMCgkT40wK5Ak9qdVkr82JTR1g7AtXm9\n' \
                  'SxlgMNr0rD35WSacioFwECWun+VPL4FyzZ30BwIDAQABAoIBAD3b6A5daU9FIcmS\n' \
                  'UD0CRcEUfDlOjZ/dPD8p7SJT/xkaKr1hwj/zETxJmDJ2b5jMA6o7xC8qleOyLKAG\n' \
                  '5QIilQ2Zb62Dupk5FosmhqC/urCWTPtpiwAap666wDwWpv5OpBDx4t5t/6e99cpr\n' \
                  'BWDS+ujYB5qCWkp9Cc0hhDISLysKpIF8pdVF4wRnyQMyycipY1qNyUOudvncfqSC\n' \
                  'Matdw96ptoU/MwIa9AexwEHuyl1x9xCrxQrtaevilLuqQxknV+WPzZH/qEzUE0at\n' \
                  'z+0eYz44Nxz1VF24SLrRXrI1PwxEyUZRIYpuq01CeyAPRjv9/ps8y9h5VrZy25m4\n' \
                  'xVRyunkCgYEAzQokos0ChW29vOFd9jxvrbsQp8N6Ctl2vEEqGfGxFU+ilGwX6PYM\n' \
                  'lviibAb0JUr437QhXkML94aeXTZidyCwVbtS1a5WXxL65voG2PFCT53nwDPYLLy4\n' \
                  'XTuwhySN89EX6s66hjb4KpdwJVZK4TEZccQFzrW35Cg81J3OtvVzKKUCgYEAwCxK\n' \
                  '77m05PzNXPat9z+7YuB6GH/g7yImfIXTgvGNkIV2Wcbc8NcNXKk1WFXCGAlHBy8z\n' \
                  '4lqD96+REOkxRdfRj9sXdBnIBhnybk5BXAtAiThZ1ZtN3cVNUpHhE34VpeT4LmfM\n' \
                  'LCr/W/PtOLBnh74bgdR5mR5GBuKsVkBwrhbbXjsCgYA/EQWfxasm21BnDnLWUFSR\n' \
                  'fV5sG6YoPCdXVDvc6whq46nAOVdJYpUQwr1CuQjTh7HxLPiug7Tkl9WSGi5DMhzK\n' \
                  '4elirFMIv0/JR9JfXCXnU0x7Q/cUG6AhnUB48PdwrTnMEXYx3iqK/zWRZm91wKJw\n' \
                  '6bhXknFTjkTXqQpyICEhuQKBgQCwRvDmPV7lvc9TOyQQ7PEine7hkkvuj1DmYIvI\n' \
                  'TXMh4orRh00bzuh+2ugIA4JrMfdpa68YLxdmmDFlZcLA4ltkrgAxi4SjtCFhdX8W\n' \
                  'w2uLc5lUC4W9rEJlP1NK4hlRd1sAlk3/JeHfoz0zBv2w0n3A9fokrlRl9H9JDwtN\n' \
                  'ZcIMCQKBgQCjjWca+9OARpPCCmxmZ+VyZawAUxz8fytXHZ4BZugmuYjtHBsVfhH9\n' \
                  'tmAbQChxdaF+C911pjoS748mvHEUnXOXmtepik5R4KwvBXEyic78aXJxAI8XMeHP\n' \
                  'KjY122i1BhnVpHeHSGMCZ/bpC0T7eWYzGhk3OkJpggmo3UsbmOu1sA==\n' \
                  '-----END RSA PRIVATE KEY-----'

_BODY = {
    'iat': time.time(),
    'exp': time.time() + 3600000,
    'authorities': 'user-mgmt',
    'userId': 'xxxx0001',
    'user_name': 'MEPM',
}

_HEADERS = {
    'alg': 'RS256',
    'type': 'JWT'
}

test_access_token = jwt.encode(_BODY, _JWT_PRIVATE_KEY, algorithm='RS256', headers=_HEADERS)

if __name__ == '__main__':
    print(test_access_token)
