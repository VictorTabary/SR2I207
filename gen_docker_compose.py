
# Génère un Docker Compose avec plusieurs relais

N_RELAYS = 20

f = open("docker-compose.yml","w")

f.write("""
version: '3'
services:

    public-relay-list:
        build: ./public-relay-list
        hostname: public-relay-list
        ports:
            - "8080:8080"
        networks:
            private-network:
                ipv4_address: 10.1.2.200
""")

if False:
    f.write("""
    hidden-service:
        build: ./security
        hostname: hidden-service
        environment:
            - RUN_SCRIPT=run_hidden_service.py
            - PUBLIC_RELAY_LIST=http://10.1.2.200:8080
        networks:
            private-network:
                ipv4_address: 10.1.2.201
""")

for i in range(N_RELAYS):
    f.write(f"""
    relay{i}:
        build: ./security
        hostname: relay{i}
        environment:
            - RUN_SCRIPT=run_relay.py
            - PORT=9000
            - PUBLIC_RELAY_LIST=http://10.1.2.200:8080
        networks:
            private-network:
                ipv4_address: 10.1.2.{100+i}
        depends_on:
            public-relay-list:
                condition: service_started
""")


f.write("""
networks:
  private-network:
    driver: bridge
    ipam:
      driver: default
      config:
        - subnet: 10.1.2.0/24
""")

f.close()