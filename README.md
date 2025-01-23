# Post-Quantum MQTT-SN Gateway

This repository is a fork of the [Eclipse Paho MQTT-SN C/C++ client](https://github.com/eclipse-paho/paho.mqtt-sn.embedded-c) that integrates post-quantum cryptography capabilities through [wolfSSL](https://github.com/wolfSSL/wolfssl) integration. This work is part of our research on securing IoT protocols against quantum threats.

We have integrated PQC capabilities in both the Gateway and the GatewayTester clients. This Gateway can be also tested along our [wolfMQTT clients](https://github.com/qursa-uc3m/pq-mqtt-sn-clients).

## Research Paper

This implementation with some preliminary benchmarks is described in the following [conference paper](https://ieeexplore.ieee.org/abstract/document/10733716/):

> Blanco-Romero, J., Lorenzo, V., Almenares, F., Díaz-Sánchez, D., Campo, C., & García-Rubio, C. (2024). "Integrating Post-Quantum Cryptography into CoAP and MQTT-SN Protocols." In 2024 IEEE Symposium on Computers and Communications (ISCC), pp. 1-6.

## Building and Running

You can build the Gateway with wolfSSL DTLS support with the following command:

```bash
git clone https://github.com/qursa-uc3m/paho.mqtt-sn.embedded-c.wolfssl-pq
cd ./paho.mqtt-sn.embedded-c/MQTTSNGateway/
./build.sh dtls -DDEBUG -DDEBUG_NW wolfssl
```

Analogously, you can build the GatewayTester with:

```bash
./build.sh dtls wolfssl -DDEBUG_TESTER
```

Then modify the `MQTTSNGateway/gateway.conf` file to add the certificate and key files. For example:

```bash
DtlsCertsKey=../../certs/dtls.crt
DtlsPrivKey=../../certs/dtls.key
```

### Testing with GatewayTester

Run the gateway (from the `MQTTSNGateway` folder):

```bash
./bin/MQTT-SNGateway 
```

Then go to the `MQTTSNGateway/GatewayTester` folder and run, for example, the subscriber:

```bash
./Build/MQTT-SNSub
```

Or the publisher:

```bash
./Build/MQTT-SNPub
```

### Testing the Gateway with wolfMQTT clients

You can also test the gateway with the [wolfMQTT clients](https://github.com/qursa-uc3m/pq-mqtt-sn-clients). See the instructions there.

## Troubleshooting

Sometimes stopping the gateway with `Ctrl+C` doesn't stop the process. You can check if there are hanging processes in the relevant ports with:

```bash
sudo lsof -i :1883 -i :8883 -i :10000
```

If any, you can kill them by the name with:

```bash
sudo pgrep -f 'MQTT-SNGa' | while read pid; do sudo kill -9 $pid; done
```

## Traffic Analysis

For DTLS, you should capture the traffic in ports: `udp.port == 1883 || udp.port == 8883 || udp.port == 10000`. It is recommended to use Wireshark with the [OQS-wireshark](https://github.com/open-quantum-safe/oqs-demos/blob/main/wireshark/USAGE.md) due to the post-quantum cryptography support.