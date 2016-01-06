#include "header.h"


int main(int argc, char *argv[])
{
	int loopear = 1;

	while(loopear)
	{
		pcap_if_t *alldevs;          // Puntero a la lista de dispositivos
		pcap_if_t *it;	             // Puntero que itera sobre esa lista
		pcap_t *adhandle;            // Descriptor del dispositivo a leer
	    int i=0;                     // Indice de dispositivo
		int numdev;                  // Numero que ingresa el usuario para seleccionar dipositivo
		struct pcap_pkthdr *header;  // Puntero a un "header" generico, que el driver le pone como encabezado a cada paquete
		const u_char *pkt_data;      // Puntero que va a puntar al paquete RAW que trae el driver
		/*pcap_dumper_t *dumpfile;	 // Archivo donde dumpear paquetes                                                        */
		char packet_filter[] = "tcp"; // Filtro en logica de alto nivel a aplicar sobre los paquetes, este filtro luego se compila con la funcion pcap_compile (lo transforma en binario)
		 bpf_program fcode;    // Struct donde se va a compilar el codigo del filtro, que se aplica en el decriptor con pcap_set
		std::ofstream myfile;		 // Archivo donde escribimos la cantidad de paquetes que recibimos en cada pedido al driver
		char errbuf[PCAP_ERRBUF_SIZE];//Buffer de error para las funciones del driver
		u_int netmask;				 // Para almacenar la mascara de red
	
		
	
		/* pcap_findalldevs_ex devuelve lista enlazada de dispositivos
			Cada nodo de la lista un dispositivo
			que puedo acceder con pcap_open()
			PCAP_SRC_IF_STRING es rcap://
		 */
	    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /* auth is not needed */, &alldevs, errbuf) == -1)
	    {
	        fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
	        exit(1);
	    }
	    
	    /* Imprimimos la lista de dispositivos en pantalla */
	    for(it= alldevs; it != NULL; it= it->next)
	    {
	        printf("%d. %s", ++i, it->name);
	        if (it->description)
	            printf(" (%s)\n", it->description);
	        else
	            printf(" (No description available)\n");
	    }
	    
	    if (i == 0)
	    {
	        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
	        return -1;
	    }
		/* Le pedimos al usuario la que dipositivo quiere */
		 printf("Enter the interface number (1-%d):",i);
	     scanf_s("%d", &numdev);
	    
	    if(numdev < 1 || numdev > i)
	    {
	        printf("\nInterface number out of range.\n");
	        /* Free the device list */
	        pcap_freealldevs(alldevs);
	        return -1;
	    }
		/* Le pedimos al usuario que ingrese el read timeout de cada llamada la funcion que recibe paquetes
		   Esta expresado en milisegundos. Para capturar paquetes usamos la funcion pcap_next_ex
		   con el read timeout le decimos cuando vuelva de la llamada	
	
		   El read timeout lo indicamos en la funcion pcap_open siguiente
		*/
		printf("Ingrese el read timeout en milisegundos \n");
		int rtimeout = 0;
		scanf_s("%d", &rtimeout);
	
		
	
		/* saltamos al dispositivo que nos pidieron */
	    for(it=alldevs, i=0; i< numdev-1 ;it=it->next, i++);
	
	
	
		  /* con pcap_open, abrimos el dispositivo para iniciar la lectura
			 Los parametros son:
	
			  	  
		  */
	    if ( (adhandle= pcap_open(it->name,          // nombre del dispositivo
	                              65536,            // Bytes del paquete a capturar
	                                                // 65536 guarantees that the whole packet will be captured on all the link layers
	                              PCAP_OPENFLAG_PROMISCUOUS,    // modo promiscuo
	                              rtimeout,             // read timeout
	                              NULL,             // authentication on the remote machine
	                              errbuf            // error buffer
	                              ) ) == NULL)
	    {
	        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", it->name);
	       
	        pcap_freealldevs(alldevs);
	        return -1;
	    }
		
		
		printf("\nLeyendo on %s...\n", it->description);
	
	      
		if(it->addresses != NULL)
	        /* Retrieve the mask of the first address of the interface */
	        netmask=((struct sockaddr_in *)(it->addresses->netmask))->sin_addr.S_un.S_addr;
	    else
	        /* If the interface is without addresses we suppose to be in a C class network */
	        netmask=0xffffff;
		
		//Compilamos el filtro
	    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0 )
	    {
	        fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
	        /* Free the device list */
	        pcap_freealldevs(alldevs);
	        return -1;
	    }
	    
	   // Seteamos el filtro
	    if (pcap_setfilter(adhandle, &fcode)<0)
	    {
	        fprintf(stderr,"\nError setting the filter.\n");
	        /* Free the device list */
	        pcap_freealldevs(alldevs);
	        return -1;
	    }
		
				 
		/* Ponemos el driver en modo estadistico. Esto generea que, pcap_next_ex, en cada llamada , en lugar de devolver el puntero te
		a el paquete RAW en *pkt_data, devuelva un puntero a un struct de dos LARGE_INTEGER,
			el primero con la cantidad de paquetes leidos en la llamada y el segundo con la cantidad de bytes
		
		*/
		if (pcap_setmode(adhandle, MODE_STAT)<0)
		{
		    fprintf(stderr,"\nError setting the mode.\n");
		    pcap_close(adhandle);
		    /* Free the device list */
		    return -1;
		}
	
		printf("Ingrese cantidad de segundos a leer \n");
		int stop = 0;
		scanf_s("%d", &stop);
	
		
		myfile.open("pps.txt");            // Abrimos el archivo
		int res;					       // El flag resultado de pcap_next_ex
		pcap_freealldevs(alldevs);		   // Liberamos la lista de dispositivos
		time_t start, end;				   // Creamos dos momentos para contar la cantidad de segundos que ingreso el usuario
		time(&start);					   // 
		int j = 0;						   // 
		struct timeval st_ts;	           // 
	
			while((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
			{
				struct timeval *old_ts = &st_ts;
				u_int delay;
				LARGE_INTEGER Bps,Pps;
				struct tm ltime;
				char timestr[16];
				time_t local_tv_sec;
	
				/* Calculate the delay in microseconds from the last sample. */
				/* This value is obtained from the timestamp that the associated with the sample. */
				delay=(header->ts.tv_sec - old_ts->tv_sec) * 1000000 - old_ts->tv_usec + header->ts.tv_usec;
				/* Get the number of Bits per second */
				Bps.QuadPart=(((*(LONGLONG*)(pkt_data + 8))  *8* 1000000)/ (delay));
				/*                                            ^      ^
				                                              |      |
				                                              |      | 
				                                              |      |
				                      converts bytes in bits --      |
				                                                     |
				                delay is expressed in m icroseconds --
				*/
				double mbps = (double) Bps.QuadPart;
				mbps= mbps / 1000000;
	
				/* Get the number of Packets per second */
				Pps.QuadPart=(((*(LONGLONG*)(pkt_data)) * 1000000) / (delay));
	
				/* Convert the timestamp to readable format */
				local_tv_sec = header->ts.tv_sec;
				localtime_s(&ltime, &local_tv_sec);
				strftime( timestr, sizeof timestr, "%H:%M:%S", &ltime);
				/* Print timestamp*/
				printf("%s ", timestr);
	
				/* Print the samples */
				printf("mbps=%f ",mbps);
				printf("PPS=%I64u\n", Pps.QuadPart);
				myfile << mbps << std::endl;
				j++;
				//store current timestamp
				old_ts->tv_sec=header->ts.tv_sec;
				old_ts->tv_usec=header->ts.tv_usec;
	
				time(&end);
				if(difftime(end,start)>=stop)
					break;
			}
		
			
			j--;//le resto uno a j porque el primero me lo voy a skippear porqu ees fruta
	
			double minimo, maximo, promedio, current;
	
			std::ifstream thefile("pps.txt");
			minimo = (double)2147483647;
			maximo = 0;
			int indice = j;
			promedio = 0;
	
			thefile >> current; // me salto el primero porq fruta
	
			while(indice>0)
			{
				thefile >> (double)current;
				//std::cout << "numero que agarre :" << current << std::endl;
				promedio += current;
	
				if(current < minimo)
					minimo=current;
				if(current>maximo)
					maximo=current;
				indice--;
				
			}
	
			promedio = promedio/(double)j;
	
			double current2, desviacion;
			desviacion = (double)0;
			indice = j;
			thefile.clear();
			thefile.seekg(0);
			thefile >> current2;
			while(indice>0)
			{
				thefile >> (double) current2;
				//std::cout << " " << promedio << " - " << current2 << "al cuadrado = ";
				current2 = (double)pow((double)promedio-current2,(double)2);
				//std::cout << current2 << std::endl;
				desviacion += current2;
				indice--;
	
			}
			
	
			desviacion = sqrt(desviacion/(double)(j-1));
	
		std::cout << " Minimo: " << minimo << " Maximo: " << maximo << " Promedio: " << promedio << " Desviacion: " << desviacion << std::endl;
		pcap_close(adhandle);
		thefile.close();
		myfile.close();
	
		std::cout << "Hacer otro test? Si (1) No (0) " << std::endl;
		scanf_s("%d", &loopear);
		std::cout << std::endl;
	}	
    system("pause");
	return 0;

}


