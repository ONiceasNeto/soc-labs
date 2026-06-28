SOC Labs
Laboratórios e anotações pessoais focados em segurança defensiva e fundamentos de redes.
---
Conteúdo
Análise de Tráfego — Wireshark
Capturas e análise de tráfego em ambiente local para identificação de protocolos e comportamentos de rede.
Protocolos estudados: DNS, HTTP, HTTPS, ICMP, ARP
Filtros utilizados:
```
dns
http
icmp
tcp.flags.syn == 1
tcp.flags.syn == 1 \&\& tcp.flags.ack == 0
ip.addr == <IP>
!(arp or dns)
```
Análise do handshake TCP:
```
\[SYN]     → Cliente envia pedido de conexão
\[SYN-ACK] → Servidor confirma e responde
\[ACK]     → Cliente confirma, conexão estabelecida
```
---
Simulação de Redes — Cisco Packet Tracer
Topologias criadas para simular ambientes de rede corporativos.
Cenários praticados:
Rede simples com switch e roteador
Configuração de DHCP server
Configuração de DNS local
Roteamento estático entre sub-redes
Segmentação básica com VLANs
Endereçamento utilizado nos labs:
```
Rede principal:  192.168.1.0/24
Sub-rede A:      192.168.10.0/24
Sub-rede B:      192.168.20.0/24
Gateway padrão:  192.168.1.1
```
---
Plataformas de Prática
Hack The Box
Enumeração de serviços com Nmap
Identificação de portas abertas e versões
Investigação de serviços HTTP e SMB
TryHackMe
Módulos de fundamentos de redes
Módulos de segurança defensiva
Introdução a análise de logs
---
Ferramentas
Ferramenta	Uso
Wireshark	Captura e análise de tráfego
Cisco Packet Tracer	Simulação de topologias de rede
Nmap	Enumeração de portas e serviços
VirtualBox	Ambiente virtualizado isolado
Kali Linux	Sistema operacional para labs
---
Status
A continuar
