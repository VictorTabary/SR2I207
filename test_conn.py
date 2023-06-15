from security.connection import ConnectionClient, NodeObject

conn = ConnectionClient(NodeObject(b'AwuTgwUZ6EezzlmP9LOuh6d8z9waqucFv09rSUYq0slS', "localhost", 9054, ),
                        [NodeObject(b'AwuTgwUZ6EezzlmP9LOuh6d8z9waqucFv09rSUYq0slS', "localhost", 9050),
                         NodeObject(b'AwuTgwUZ6EezzlmP9LOuh6d8z9waqucFv09rSUYq0slS', "localhost", 9052)])

# la clé publique mise là correspond à la clé privée: b'AQcx++axCPTh3xOmYC8IzUSrrgynvVarDp+2fZj/wf4='
# pour tester: utiliser test_node.sh pour lancer les noeuds sur les bons ports
