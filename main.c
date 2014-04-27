/***************************************************************************
                          short_stop.c - version 0.3
                             -------------------
    author               : Joerg Kost
    email                : joerg.kost@gmx.com
 
 ***************************************************************************
 
 *
 *              This program is free software; you can redistribute it
 *              and/or  modify it under  the terms of  the GNU General
 *              Public  License as  published  by  the  Free  Software
 *              Foundation;  either  version 2 of the License, or  (at
 *              your option) any later version.
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>

#define MAPS_FILE "/proc/%s/maps"
#define PTRACE_PEEKDATA 2
#define ROWS 512

char somebuffer[512];
char output_directory[768];


/* taken from netstat */
static const char *tcp_state[] =
{
    "",
    "ESTABLISHED",
    "SYN_SENT",
    "SYN_RECV",
    "FIN_WAIT1",
    "FIN_WAIT2",
    "TIME_WAIT",
    "CLOSE",
    "CLOSE_WAIT",
    "LAST_ACK",
    "LISTEN",
    "CLOSING",
	"UNKNOWN"
};

struct SEGMENT {
	unsigned long start;
	unsigned long end;
	int id;
	unsigned long offset;
	unsigned long inode;
	char flags[256];
	char name[PATH_MAX];
	char device[256];
	struct SEGMENT *next;
} ;

struct  FD {
	unsigned long sid;
	unsigned long fdno;
	struct FD *next;
};


struct SEGMENT *head;
struct FD *fdcollection;
int xflag = 0;
int pflag = 0;
int dflag = 0;

int cut_addresses(char *);
int print_proc_maps(pid_t);
int read_proc_maps(pid_t);
int print_memory(pid_t); 
int print_environment(pid_t);
int print_misc(pid_t);
int print_file_descriptors(pid_t);
int print_net();
int print_filename(const char*, const char *);
void ip_do_one(const char *, int , int );
void unix_do_one(const char *);
void pfkey_do_one(const char *);


int main (int argc,  char * argv[]) {
	
	/* Process ID */
	pid_t pid = -1;

	int c;
	
	while( (c  = getopt(argc, argv, "md:p:")) != -1 )
	{
		switch(c) 
		{
			case 'm':
				xflag = 1;
				break;
			case 'p':
				pid = atoi(optarg);
				pflag = 1;
				break;
			case 'd':
				if(optarg) {
					strncpy(somebuffer, optarg, 512);
					dflag = 1;
				}
				else {
					 dflag = 0;
				}
		}
	}
	
	if( pflag == 0) { 
			printf("shortstop 0.2\n\n");
			printf("lsof/status: %s -p pid | more\n", argv[0]);
			printf("lsof/status/memdump: %s -m -p pid > pid.dump \n", argv[0]);
            printf("lsof/status/memdump/save-segments-in-single-file: %s -m -p pid -d /tmp > pid.dump \n", argv[0]);
			return 1;
		}

	/*  Give me some memory on my heap */
	fdcollection = malloc(sizeof(struct FD));
	if(fdcollection == NULL) {
		printf("Whoops, not enough memory?\n");
		return 1;
	}
	fdcollection->sid = 0;
	fdcollection->next = NULL;
	
	if (xflag == 1) {
		ptrace(PT_ATTACH, pid, 0, 0);
	}
	
	
	if( read_proc_maps(pid) == 1 )
		return 1;

	print_environment(pid);
	print_misc(pid);
	print_file_descriptors(pid);
	print_net();	
	print_proc_maps(pid);
	
	if( xflag == 1) { 
		if(dflag == 1) {
			//FIX check return
			snprintf(output_directory, 512, "%s/%d-%d", somebuffer, pid, getpid());
				if( mkdir(output_directory,0700) != 0 ) {
					printf("Cant create output directory\n");
					return EXIT_FAILURE;
				}
		}
		
		print_memory(pid);
		ptrace(PT_DETACH, pid, 0, 0);
	}

    return EXIT_SUCCESS;
}

int print_filename(const char *filename, const char *reason)
{
	char buffer[PATH_MAX];
	char *ptr;
	int myfd;
	ptr = buffer;

	if( (myfd = open(filename, O_RDONLY)) > -1) {
	printf("\n\n%s\n",reason);
		while( read(myfd, ptr, 1) ) {
				if( *ptr == '\0') {
					fwrite("\n",1,1,stdout);
				} else {
					fwrite(ptr,1,1,stdout);
				}
				//ptr++;
				ptr = buffer;
			}
	}
	
	close(myfd);
	return EXIT_SUCCESS;
}

int print_environment(pid_t pid)
{
		char file[PATH_MAX];
		char buffer[PATH_MAX];

		printf("\nexecutable\n");
		snprintf(file, PATH_MAX, "/proc/%d/exe", pid);
		memset(buffer,'\0', PATH_MAX);
		if ( readlink(file, buffer, PATH_MAX) != - 1) {
			printf("%s\n\n",buffer);
		}

		snprintf(file, PATH_MAX, "/proc/%d/cmdline",pid);
		print_filename(file,"commandline");
		
		printf("\ncurrent working directory\n");
		snprintf(file, PATH_MAX, "/proc/%d/cwd", pid);
		memset(buffer,'\0', PATH_MAX);
		if ( readlink(file, buffer, PATH_MAX) != - 1) {
			printf("%s\n\n",buffer);
		}

		snprintf(file, PATH_MAX, "/proc/%d/environ",pid);
		print_filename(file,"environment");
		
	return EXIT_SUCCESS;
}


int print_file_descriptors(pid_t pid)
{
		char dir[PATH_MAX];
		char filename[PATH_MAX];
		char buffer[PATH_MAX];
		DIR *directory;
		struct dirent *file;
		struct FD *element;

		element = fdcollection;

		snprintf(dir, PATH_MAX, "/proc/%d/fd",pid);
		printf("\n\n%s\n",dir);
		if( (directory = opendir(dir)) != NULL) {
			
			while( (file = readdir(directory)) != NULL) {
				if ( file->d_type == DT_LNK) {
					memset(filename,'\0', PATH_MAX);
					memset(buffer, '\0', PATH_MAX);
					snprintf(filename, PATH_MAX, "/proc/%d/fd/%s", pid, file->d_name);
					if ( readlink(filename, buffer, PATH_MAX) != -1) {
						printf("fd %s\t->\t%s\n", file->d_name, buffer);
						if(strncmp(buffer,"socket:", 6) == 0) {
								/*save it for later*/
								if(element->sid != 0) {
									element->next = malloc(sizeof(struct FD));
									if(element == NULL) {
										printf("Whoops, not enough memory?\n");
										exit(1);
									}
									element = element->next;
									sscanf(buffer, "socket:[%ld]", &element->sid);
									sscanf(file->d_name, "%ld", &element->fdno);
									element->next = NULL;
								}
								else {
									sscanf(buffer, "socket:[%ld]", &element->sid);
									sscanf(file->d_name, "%ld", &element->fdno);

									element->next = NULL;

								}
						}
						
					}
				}
			}
		}
		printf("\n");

		return EXIT_SUCCESS;
}

void pfkey_do_one(const char *line)
{

    unsigned long number;
    int wmem, rmem, utype;
    int num, refcount;
    unsigned long inode;
	struct FD *element;
	char output[ROWS];
	
	memset(output,'\0', 512);
				
    num = sscanf(line,
			"%lX %d %d %d %d %ld\n",
			&number, &refcount, &rmem, &wmem, &utype, &inode);

	if (num < 6) {
		return;
    }

	for(element = fdcollection; ; ) {
	
		if(element->sid == inode) {
				snprintf(output,512,"[fd %ld]\t->\tinode %ld\tpfkey ", element->fdno,  inode);
				break;
		}

		if( element->next != NULL) {
				element = element->next;
		} else {	
				snprintf(output,512,"[other]\t->\tinode %ld\tpfkey ",  inode);
				break;
		}
		
	}
	
	printf("%s\n",output);
	
}

/*shorten netstat version*/
void unix_do_one(const char *line)
{

    unsigned long number;
	int num, state, utype;
	unsigned long refcount, protocol, flag, inode;
	char path[PATH_MAX];
	struct FD *element;
	char output[ROWS];
	memset(output,'\0', 512);
				
    num = sscanf(line,
			"%lX: %ld %lx %lx %X %X %lu %512s\n",
			&number, &refcount, &protocol, &flag, &utype, &state, &inode, path);

	if (num < 7) {
		return;
    }


	for(element = fdcollection; ; ) {
	
		if(element->sid == inode) {
				snprintf(output,512,"[fd %ld]\t->\tinode %ld\tunix ", element->fdno,  inode);
				break;
		}

		if( element->next != NULL) {
				element = element->next;
		} else {	
				snprintf(output,512,"[other]\t->\tinode %ld\tunix ",  inode);
				break;
		}
		
	}
	
	if( num == 8)
		{
			strncat(output, path, ROWS - strlen(output) -1) ; 
		}
		
	printf("%s\n",output);
	
}

/*shorten netstat version*/
void ip_do_one(const char *line, int protocol, int type)
{

    unsigned long rxq, txq, time_len, retr, inode;
    int num, local_port, rem_port, d, state, uid, timer_run, timeout;
    char rem_addr[128], local_addr[128], more[512];
	struct in6_addr ipv6_local, ipv6_remote;
	struct in_addr ipv4_local, ipv4_remote;
	struct FD *element;
	char output[ROWS];
	memset(output,'\0', 512);

    num = sscanf(line,
		"%d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X %lX:%lX %X:%lX %lX %d %d %lu %512s\n",
		 &d, local_addr, &local_port, rem_addr, &rem_port, &state,
		 &txq, &rxq, &timer_run, &time_len, &retr, &uid, &timeout, &inode, more);

	
	if (num < 11) {
		return;
    }

	if(protocol == AF_INET) {
	sscanf(local_addr, "%X",&((struct sockaddr_in *) &ipv4_local)->sin_addr.s_addr);
	sscanf(rem_addr, "%X",&((struct sockaddr_in *) &ipv4_remote)->sin_addr.s_addr);
		inet_ntop(AF_INET, &ipv4_local, local_addr, 64);
		inet_ntop(AF_INET, &ipv4_remote, rem_addr, 64);
	}
	else if (protocol == AF_INET6) {
		sscanf(local_addr, "%08X%08X%08X%08X",&ipv6_local.s6_addr32[0], &ipv6_local.s6_addr32[1], &ipv6_local.s6_addr32[2], &ipv6_local.s6_addr32[3]);
		sscanf(rem_addr, "%08X%08X%08X%08X",&ipv6_remote.s6_addr32[0], &ipv6_remote.s6_addr32[1], &ipv6_remote.s6_addr32[2], &ipv6_remote.s6_addr32[3]);
        
	inet_ntop(AF_INET6, &ipv6_local, local_addr, 128);
	inet_ntop(AF_INET6, &ipv6_remote, rem_addr, 128);
	}


	for(element = fdcollection; ; ) {
	
		if(type == IPPROTO_UDP) {
			if (state == 7) {
				state = 0;
			}
			else if(state == 1) {
				state = 1;
			}
			else {
				state = 0;
			}
		}
		
		if(element->sid == inode) {
				snprintf(output,512,"[fd %ld]\t->\tinode %ld\tlocal: %s:%d\tremote: %s:%d\t", element->fdno,  inode, local_addr, local_port, rem_addr, rem_port);
				break;
		}

		if( element->next != NULL) {
				element = element->next;
		} else {	
			snprintf(output,512,"[other]\t->\tinode %ld\tlocal: %s:%d\tremote: %s:%d\t", inode, local_addr, local_port, rem_addr, rem_port);
			break;
		}
		
	}

	if(type != IPPROTO_RAW) { strncat(output, tcp_state[state], ROWS - strlen(output) -1); }
	
	printf("%s\n",output);
	
}

void netlink_do_one(const char *line)
{
    printf("%s\n", line);
}


int print_net()
{
		char file[PATH_MAX];
		char buffer[4096];
		int i = 0;
		int myfd;
		int lnr = 0;
		memset(buffer, '\0', PATH_MAX);
		char *ptr;

		char *net_files[] =
					{
					"tcp",
					"tcp6",
					"udp",
					"udp6",
					"raw",
					"raw6",
					"unix",
					"route",
					"igmp",
					"igmp6",
                    "netlink",
					"pfkey",
                        
					NULL,
					};
		
		for (i = 0; net_files[i] != NULL; i++) {
			lnr = 0;
		
			snprintf(file, PATH_MAX, "/proc/net/%s",net_files[i]);
		
			if( (myfd = open(file, O_RDONLY)) > -1) {
		
				printf("\n%s\n", file);

				ptr = buffer;
					while( read(myfd, ptr, 1) ) {
						if( *ptr != '\n') {
							ptr++;
						} else {
					
						*ptr = '\0';

						if(lnr > 0) {

						if(strcmp(net_files[i],"tcp") == 0) {
							ip_do_one(buffer,AF_INET,IPPROTO_TCP); 
						}
						else if(strcmp(net_files[i],"udp") == 0) {
							ip_do_one(buffer,AF_INET,IPPROTO_UDP); 
						}
						else if(strcmp(net_files[i],"tcp6") == 0) {
							ip_do_one(buffer,AF_INET6,IPPROTO_TCP);
						}	
						else if(strcmp(net_files[i],"udp6") == 0) {
							ip_do_one(buffer,AF_INET6,IPPROTO_UDP); 
						}
						else if(strcmp(net_files[i],"raw") == 0) {
							ip_do_one(buffer,AF_INET,IPPROTO_RAW); 
						}
						else if(strcmp(net_files[i],"raw6") == 0) {
							ip_do_one(buffer,AF_INET6,IPPROTO_RAW); 
						}
						else if(strcmp(net_files[i],"unix") == 0) {
							unix_do_one(buffer); 
						}
						else if(strcmp(net_files[i],"pfkey") == 0) {
							pfkey_do_one(buffer); 
						}
                        else if(strcmp(net_files[i],"netlink") == 0) {
							netlink_do_one(buffer);
						}
						
						}
					ptr = buffer; 
					lnr++;
				}
			}

			close(myfd);
			}

		}
		
		return EXIT_SUCCESS ;
}


int print_misc(pid_t pid)
{
		char file[PATH_MAX];
		int i = 0;

		char *misc[] =
					{
					"mounts",
					"status",
					"maps",
					NULL,
					};
		
		for (i = 0; misc[i] != NULL; i++) {
				memset(file, '\0', PATH_MAX);
				snprintf(file, PATH_MAX, "/proc/%d/%s",pid,misc[i]);
				print_filename(file,file);
		}
		
		return EXIT_SUCCESS;
}

int print_memory(pid_t pid) 
{
	unsigned long data;
	struct SEGMENT *memory;
	char header[PATH_MAX];
	char filename[PATH_MAX];
	FILE *memory_snippets = NULL;

	for (memory = head; memory != NULL ; memory = memory->next) {
		
		snprintf(header,PATH_MAX, "\nmap\nfile %s\nbegin %lx\n"
					"end %lx\nflags %s\ninode %ld\n"
					"device %s\n"
					"data\n\n",
					memory->name,memory->start, memory->end, memory->flags, memory->inode, memory->device	);		
		
		if(dflag == 0) {
			fwrite(header, strlen(header), 1, stdout);
			setvbuf(stdout,(char*)NULL,_IONBF,0);	
		} else {
			snprintf(filename, PATH_MAX, "%s/%lx-%lx", output_directory, memory->start, memory->end);
			memory_snippets = fopen(filename, "a+");
			if(memory_snippets == NULL) {
				printf("Cant write out memory contents at %s!\n", filename);
			}
		}

		
		while(memory->start < memory->end) {
		
		data = ptrace(PTRACE_PEEKDATA, pid, memory->start, NULL);
		if( data != -1 ) {
			if(dflag == 0) {	
					fwrite(&data, sizeof(unsigned long), 1, stdout);
				}
			else {
					if(memory_snippets != NULL) {
						fwrite(&data, sizeof(unsigned long), 1, memory_snippets);
					}
				}
			}
			memory->start += sizeof(unsigned long);
		}
		if(memory_snippets != NULL) fclose(memory_snippets);

	}
	

	return EXIT_SUCCESS;
}

int print_proc_maps(pid_t pid)
{
	struct SEGMENT *memory;
	
	for (memory = head; memory != NULL ; memory = memory->next) {
		//printf("%d\t%8lx\t%8lx\t%s\n", memory->id,  memory->start, memory->end, memory->name);
	}
	return EXIT_SUCCESS;
}

int read_proc_maps(pid_t pid)
{
		char dst[PATH_MAX];
		int myfd;
		char buffer[1024];
		char *ptr;
		
		memset(dst, '\0', PATH_MAX);
		snprintf(dst, PATH_MAX, "/proc/%d/maps", pid);

		if(  (myfd = open(dst,O_RDONLY)) == -1 ) {
			printf("Cant open %s\n", dst);
			return 1;
		}
		
		ptr = buffer;
		while( read(myfd, ptr, 1) ) {
				if( *ptr != '\n') {
					ptr++;
				} else {
					*ptr = '\0';
					cut_addresses(buffer);
					ptr = buffer; 
				}
				
		}
		
		close(myfd);

	return EXIT_SUCCESS;
}

int cut_addresses(char *ptr)
{
	struct SEGMENT *memory;
	int id = 0;
	
	for (memory = head; memory != NULL ; memory = memory->next) {
		if ( memory->next == NULL ) {
			break;
		}
		id++;
	}
	
	if(memory == NULL) {
			memory = malloc(sizeof(struct SEGMENT));
			memory->id = id;
			memory->next = NULL;
			if(id == 0) head = memory;
	}
	else if(memory->next == NULL)
	{
		memory->next = malloc(sizeof(struct SEGMENT));
		memory = memory->next; memory->id = 0x661; memory->next = NULL;
	}
	
	sscanf(ptr, "%lx-%lx %4s %lx %5s %ld %s", &memory->start, &memory->end, memory->flags, &memory->offset, memory->device, &memory->inode, memory->name);
		
	return EXIT_SUCCESS;
}

