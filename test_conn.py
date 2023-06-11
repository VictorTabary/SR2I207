from security.connection import Connection, NodeObject


conn = Connection(NodeObject("localhost", 9053, b'AwuTgwUZ6EezzlmP9LOuh6d8z9waqucFv09rSUYq0slS'), [NodeObject("localhost", 9050, b'AwuTgwUZ6EezzlmP9LOuh6d8z9waqucFv09rSUYq0slS'), NodeObject("localhost", 9052, b'AwuTgwUZ6EezzlmP9LOuh6d8z9waqucFv09rSUYq0slS')])
# la clé publique mise là correspond à la clé privée: b'AQcx++axCPTh3xOmYC8IzUSrrgynvVarDp+2fZj/wf4='
# pour tester: utiliser test_node.sh pour lancer les noeuds sur les bons ports