from security.connection import Connection, NodeObject


conn = Connection(NodeObject("localhost3", b'AwuTgwUZ6EezzlmP9LOuh6d8z9waqucFv09rSUYq0slS'), [NodeObject("localhost2", b'AwuTgwUZ6EezzlmP9LOuh6d8z9waqucFv09rSUYq0slS')])
# la clé publique mise là correspond à la clé privée: b'AQcx++axCPTh3xOmYC8IzUSrrgynvVarDp+2fZj/wf4='
# pour tester: nc -lvk 9050