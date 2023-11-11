Before compiling xdp project, put this directory inside /usr/src/kernels/linux-$(uname -r | sed s/\-.*//).

Per far funzionare il ping dal controller verso internet occorre:
Pingare prima il server monitor o l'indirizzo remoto collegato alla wan di Mienro, occorre però tener presente che se i dispositivi MiEnRo sono due, essendo il routing asimmetrico in uscita pingare il monitor può non bastare (a meno di usare il source address delle interfacce del controller collegati verso i rispettivi MiEnRo) e può essere necessario pingare l'indirizzi remoti collegati alle due wan.

Per far funzionare il ping da MiEnRo verso internet occorre:
Pingare l'indirizzo remoto collegato alla wan.

Il traffico frammentato non è bloccato ove previsto.

Queste operazioni servono ad abilitare le complete funzionalità di ping.



Aggiunto supporto al trunking su tutte le interfaccie con configurazione dinamica delle vlan sulla wan.
Aggiunta configurazione dinamica (occorre mienromonnet attivo) dei peer bgp (non blacklist) attraverso tabella di routing con indirizzo a massimo cidr.
Controllo del traffico frammentato a livello tre in quanto a livello quattro occorrerebbe riassemblare (operazione altamente sconsigliata nei nodi intermedi)

mienroload - attiva XDP
mienromonnet - monitorizza le configurazione di rete
mienromon4 - rimuove dalla blacklist ssh gli indirizzi ipv4 che hanno terminato la quarantena
mienromon6 - rimuove dalla blacklist ssh gli indirizzi ipv6 che hanno terminato la quarantena
mienrounload - disattiva XDP
