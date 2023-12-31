# TEMA-1---PROTOCOALE-DE-COMUNICATII

## IMPLEMENTARE DATAPLANE ROUTER 

**ORGANIZARE**

**1. TASK1**
Primul task din tema cerea implementarea protocolului Ipv4. In vederea rezolvarii acestuia am urmat pasii prezentati in descrierea din cerinta pe care ii voi detalia in cele ce urmeaza:
- Verificare daca ruterul este destinatie. Am comparat adresa mac a interfetei pe care intra pachetul cu adresa de destinatie a pachetului pentru a ma asigura ca pachetul trebuie sa intre in ruterul respectiv.
- Verificarea checksum-ului pentru a asigura integritatea pachetului.
- Verificare si recalculare TTL. Daca acesta are valoarea 1 sau 0 am apelat functia de ICMP care este responsabila cu implementarea acestui protocol. In caz contrat, decrementez TTL-ul si recalculez suma de control cu noua valoarea a acestuia.
- Cautare in tabela de rutare. Am implementat o functie numita LPM prin care caut “next-hop ul” pachetului. Pentru aceasta am implementat o cautare liniara care cauta acea linie din tabela ARP (folosita static) pentru care adresa IP && masca == prefix. In cazul mai multor match uri este nevoie sa aleg potrivirea cu masca cea mai mare.
- Dupa identificarea next-hop-ului, urmeaza actualizarea adreselor de sursa si destinatie astfel incat adresa sursa devine adresa portului pe care pachetul paraseste ruterul, iar adresa destinatie devine adresa next-hop-ului apoi am trimis pachetul mai departe.
Atat tabela ARP cat si tabela de rutare sunt folosite in mod static. Am folosit fisierele puse la dispozitie in scheletul temei precum si functiile de parsare pentru acestea.

**2. TASK4**
Ultimul task presupune implementarea protocolului ICMP. Pentru acesta am tratat 3 posibilitati:
- Time exceeded, aparut la expirararea TTL-ului
- Destination unreachable, cand nu se gaseste niciun next-hop pentru pachet
- Reply-ul trimis drept confirmare host-ului sursa cand insusi ruterul este destinatia pachetului
In vederea realizarii acestui task am construit structuri cu campurile mentionate in descrierea protocolul pentru fiecare situatie in parte, apoi am completat aceste campuri si am alcatuit pachetul ICMP pe care l-am trimis. Am testat in main fiecare situatie critica in parte si am apelat functia de ICMP construita. Pentru a putea identifica situatiile mentionate mai sus am verificat tipul si codul date ca parametru functiei ICMP, aceste campuri avand valori specifice pentru fiecare situatie in parte.

**Testare**
Pentru testare am urmat instructiunile mentionate in sectiunea Testare din enuntul temei.
Pentru depanare am utilizat utilitarul ping si Wireshark.

**Bibliografie**
1. Laboratul 4 (de foarte mare ajutor pentru primul exerctiu)
2. Slide-urile de curs
3. https://bluecatnetworks.com/glossary/what-is-ipv4/
4. https://en.wikipedia.org/wiki/Internet_Protocol_version_4
5. https://ro.wikipedia.org/wiki/Internet_Control_Message_Protocol
6. https://www.javatpoint.com/icmp-protocol
7. https://www.rfc-editor.org/rfc/rfc792
