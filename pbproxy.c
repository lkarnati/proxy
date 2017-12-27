#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <error.h>
#include <math.h>
#include <sys/select.h>
#include <openssl/aes.h>
#include <openssl/rand.h> 
#include <openssl/hmac.h>
#include <openssl/buffer.h>

int cmode(char* d_ip, int d_port, char* enc_key);
int smode(int port, int d_port, char *d_ip, char* enc_key);

struct ctr_state 
{ 
	unsigned char ivec[AES_BLOCK_SIZE];  
	unsigned int num; 
	unsigned char ecount[AES_BLOCK_SIZE]; 
};

void init_ctr(struct ctr_state *state, const unsigned char iv[16])
{
	state->num = 0;
	memset(state->ecount, 0, AES_BLOCK_SIZE);
	memset(state->ivec + 8, 0, 8);
	memcpy(state->ivec, iv, 8);
}

int main(int argc, char *argv[])
{
	char c;
	int has_key = 0;
	int rev_mode = 0;
	int count = 0;
	int d_port = 0;
	int port = 0;
	char keyfile[4096]="";
	//char *key = NULL;
	int i;


	
	while( (c = getopt(argc, argv, "l:k:")) != -1)
	{
		switch (c)
		{
			case 'l':
                                //printf("hey");
				rev_mode = 1; //servermode
				port = atoi(optarg);
				break;
			case 'k':
				strcat(keyfile,optarg);
				has_key = 1;
				break; 
			case '?':
				if (optopt == 'k')
					fprintf (stderr, "Option -%c requires an argument.\n", optopt);
				else if (optopt == 'l')
					fprintf (stderr, "Option -%c requires an argument.\n", optopt);
				else if (isprint (optopt))
					fprintf (stderr, "Unknown option `-%c'.\n", optopt);
				else
					fprintf (stderr,"Unknown option character `\\x%x'.\n", optopt);
				return 1;
		
			default:
				return(0);
				break;
		}
	
	}
	unsigned char read_key[4096+1]="";
	if(has_key ==1)
	{
		FILE *fp;
		fp = fopen(keyfile, "r");
		fscanf(fp, "%s", read_key);
		fclose(fp);
	}
	else
	{
		fprintf (stderr, "Please give Key, -k key_file\n", optopt);
		exit(EXIT_FAILURE);
	}
	unsigned char enc_key[17] = {0};
	unsigned char convert[3];
	unsigned long hex;
        //printf("key - %s\n", read_key);
	convert[3] = '\0';
	for (int i = 0; i < 32; i+=2)
	{
		convert[0] = read_key[i];
		convert[1] = read_key[i+1];
		hex = strtoul(convert,NULL, 16);
		//printf("hex is %lu\n",hex);
		enc_key[i/2] = hex;
	}
	
	
	char d_ip[200] = "";
	if(rev_mode==1)
	{
	        //d_ip = argv[optind];
	        d_port = atoi(argv[optind+1]);
		if(strcmp(argv[optind], "localhost")==0)
		{
			strcat(d_ip, "127.0.0.1");
		}
		else
		{
			strcat(d_ip, argv[optind]);
		}
		//printf("d_ip is %s \n",d_ip);
             smode(port, d_port, d_ip, enc_key);
		
        }
	else
	{    
		
		d_port = atoi(argv[optind+1]);
		//fprintf(stderr, "D-port %d\n",d_port);
		if(strcmp(argv[optind], "localhost")==0)
		{
			strcat(d_ip, "127.0.0.1");
		}
		else
		{
			strcat(d_ip, argv[optind]);
		}
		cmode(d_ip, d_port, enc_key);
	}

}

int cmode(char* d_ip, int d_port, char* enc_key)
{
	struct sockaddr_in serv_addr;

	char input[2048] = {0};
	char output[2048] = {0};
	fd_set sockSet;
	int maxDesc;
	
	int sockc = socket(AF_INET, SOCK_STREAM, 0);
	
	if(sockc < 0)
	{
		perror("Socket failed");
		exit(EXIT_FAILURE);
	}

	memset(&serv_addr, '0', sizeof(serv_addr));

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(d_port);
	bzero(&serv_addr.sin_zero, 8);

	//127.0.0.1 and INADDR_ANY are local hosts.

	if(inet_pton(AF_INET, d_ip, &serv_addr.sin_addr)<=0) 
	{
		perror("Invalid address/ Address not supported"); 
		exit(EXIT_FAILURE);
	}

	if (connect(sockc, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
	{
	        perror("Connection failed");
	        exit(EXIT_FAILURE);
	}

	unsigned char iv1[AES_BLOCK_SIZE], iv2[AES_BLOCK_SIZE];
	if(!RAND_bytes(iv1, AES_BLOCK_SIZE))
	{
        	fprintf(stderr, "Could not create random bytes.");
        	exit(1);    
	}

	write(sockc, iv1, AES_BLOCK_SIZE); //iv is 8 bytes long
	read(sockc, iv2, AES_BLOCK_SIZE);
	
	struct ctr_state state1;
	init_ctr(&state1, iv1);

	struct ctr_state state2;
	init_ctr(&state2, iv2);

        int len = 1;
	maxDesc = sockc+1; //Since it is zero for stdin always
	int sel;

	AES_KEY key;
	if (AES_set_encrypt_key(enc_key, 128, &key) < 0)
		{
       			fprintf(stderr, "Could not set encryption key.");
        		exit(1); 
		}

	
	while(1)
	{
		FD_ZERO(&sockSet);
		FD_SET(STDIN_FILENO, &sockSet);
		FD_SET(sockc, &sockSet);
		if(sel = select(maxDesc, &sockSet, NULL, NULL, NULL)) //Last NULL is timeout
		
		{
			if(FD_ISSET(0, &sockSet))	
			{
				//fgets(input, 2048, stdin);
				int n = read(0, input, 2048);
				char outdata[n];
				
				AES_ctr128_encrypt(input, outdata, n, &key, state1.ivec, state1.ecount, &state1.num);
				write(sockc, outdata, n);
				//printf("From stdin - %s\n", input);	
			}			
			
			else if(FD_ISSET(sockc, &sockSet))
			{
				
				len = read(sockc, output, 2048);
				char doutput[len];
				AES_ctr128_encrypt(output, doutput, len, &key, state2.ivec, state2.ecount, &state2.num);
				if(len <= 0){break;}
				//output[len] = '\0';
				write(1, doutput, len);
				//printf("From server- %s", output);
								
			}
			
		}
	}	
	close(sockc);
	
}
int smode(int port, int d_port, char *d_ip, char* enc_key)
{
	
	int value = 1;
	char data[2048] = {0};
	fd_set sockSet;

	struct sockaddr_in server;
	//struct sockaddr_in client;
	struct sockaddr_in serv_addr;

	unsigned int addrlen = sizeof(server);

	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	int varconnect;

	if(sockfd < 0)
	{
		perror("Socket failed");
		exit(EXIT_FAILURE);
	}

	if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &value, sizeof(value)) < 0)
	{
		perror("Set socket opt");
		exit(EXIT_FAILURE);
	}

	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons(port);
	bzero(&server.sin_zero, 8);

	if(bind(sockfd, (struct sockaddr *)&server, addrlen) < 0)
	{
		perror("Could not bind");
		exit(EXIT_FAILURE);
	}

	if(listen(sockfd, 3) < 0)
	{
		perror("listen failed");
		exit(EXIT_FAILURE);
	}
	int data_len = 1;
	int sel;
	int maxDesc;

	AES_KEY key;
	if (AES_set_encrypt_key(enc_key, 128, &key) < 0)
		{
       			fprintf(stderr, "Could not set encryption key.");
        		exit(1); 
		}
	
	while(1)
	{	
		int sockfd1 = socket(AF_INET, SOCK_STREAM, 0);
	        int cli = accept(sockfd, (struct sockaddr *)&server, (socklen_t*)&addrlen);
                //printf("Client connected\n");
		if(cli < 0)
		{
			perror("Connection failed");
			exit(EXIT_FAILURE);
		}
		memset(&serv_addr, '0', sizeof(serv_addr));

		serv_addr.sin_family = AF_INET;
		serv_addr.sin_addr.s_addr = inet_addr(d_ip);
		serv_addr.sin_port = htons(d_port);
		bzero(&serv_addr.sin_zero, 8);

                /*
		if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0) 
		{
			perror("Invalid address/ Address not supported"); 
			exit(EXIT_FAILURE);
		}*/
		varconnect = connect(sockfd1, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
		if(varconnect < 0)
		{
			perror("Connection failed");
	        	exit(EXIT_FAILURE);
		}
		unsigned char iv2[AES_BLOCK_SIZE], iv1[AES_BLOCK_SIZE];
		if(!RAND_bytes(iv2, AES_BLOCK_SIZE))
		{
        		fprintf(stderr, "Could not create random bytes.");
        		exit(1);    
		}
		read(cli, iv1, AES_BLOCK_SIZE);
		write(cli, iv2, AES_BLOCK_SIZE);

		struct ctr_state state1;
		init_ctr(&state1, iv1);

		struct ctr_state state2;
		init_ctr(&state2, iv2);
		
		if(sockfd1>cli){maxDesc = sockfd1 + 1;}
		else if(cli > sockfd1) {maxDesc = cli + 1;}
		
		while(1)
		{
                        //printf("while1\n");
			FD_ZERO(&sockSet);
			FD_SET(cli, &sockSet);
			FD_SET(sockfd1, &sockSet);
			if(sel = select(maxDesc, &sockSet, NULL, NULL, NULL)) //Last NULL is timeout
			{
                                //printf("Inside select\n");
				if(FD_ISSET(cli, &sockSet))	
				{
          					data_len = read(cli, data, 2048);
						char outdata[data_len];	
						if(data_len > 0)
						{
							AES_ctr128_encrypt(data, outdata, data_len, &key, state1.ivec, state1.ecount, &state1.num);
							write(sockfd1, outdata, data_len);
						}
						else{break;}
					
				}
				if(FD_ISSET(sockfd1, &sockSet))	
				{
						
						data_len = read(sockfd1, data, 2048);
						char outdata[data_len];	
						if(data_len > 0)
						{
							AES_ctr128_encrypt(data, outdata, data_len, &key, state2.ivec, state2.ecount, &state2.num);
							write(cli, outdata, data_len);
	
						}else{break;}
						
				
				}
			}
		

		}

		close(cli);
		close(sockfd1);		
			
	}

	return 0;
	
}

