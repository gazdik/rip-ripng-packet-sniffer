# RIP and RIPng packet sniffer
-----------------------------------

Nástroje na odchytávanie RIP a RIPng paketov.
Vypracované v rámci projektu do predmetu ISA v ak.r. 2015/2016.

### Autor

Peter Gazdík

## Popis


## Spustenie

```
./myripresponse {-i <rozhranie>} -r <IPv4>/[8-30] {-n <IPv4>} {-m [0-16]}
                {-t [0-65535]} {-p <heslo>}
```

- `-i <rozhranie>` rozhranie, z ktorého má byť útočný paket odoslaný
- `-r <IPv4>/[8-30]` IP adresa podvrhovanej siete a za lomítkom číselná dĺžka
masky siete
- `-m` RIP metrika, teda počet hopov, implicitne 1
- `-n <IPv4>` adresa next-hopu pre podvrhovanú routu, implicitne 0.0.0.0
- `-t` hodnota Router Tagu, implicitne 0
- `-p` v prípade použitia tohoto prepínača je podvrhovaná RIP Response správa
zabezpečená pomocou single-password autentizácie s 16B heslom. Ak parameter
chýba, nie je použitý žiadny spôsob zabezpečenia správ

```
./myripsniffer -i <rozhranie>
```
- `-i <rozhranie>` rozhranie, na ktorom má byť odchyt paketov vykonávaný
