#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>

#include "defs.h"

pthread_mutex_t file_mutex;
struct scanned_file *scanned_files;
int scanned_files_sz;
int scanned_files_len;
int scan_stop = 0;

pthread_mutex_t trie_mutex[LETTERS];
struct trie_node *root;

char *current_prefix = NULL;
void (*cback)(char *word) = NULL;

void scanner_init(){
	scanned_files_sz = 0;
	scanned_files_len = 64;
	scanned_files = (scanned_file*) malloc(scanned_files_len * sizeof(scanned_file));
	pthread_mutex_init(&file_mutex, NULL);
}

struct scanned_file* add_scanned_file(char *name, time_t time)
{
	//popunjavamo niz scanned_files pod mutexom

	strcpy(scanned_files[scanned_files_sz].name, name);
	scanned_files[scanned_files_sz].mod_time = time;
	scanned_files_sz++;

	if (scanned_files_sz == scanned_files_len){
		scanned_files_sz *= 2;
		scanned_files = realloc(scanned_files, scanned_files_sz * sizeof(scanned_file));
	}

	return &scanned_files[scanned_files_sz - 1];
}

struct scanned_file* find_scanned_file(char* name)
{
	//iteriramo kroz niz skeniranih fajlova pod mutexom

	for (int i= 0; i < scanned_files_sz; i++) {
		if (strncmp(scanned_files[i].name, name, strlen(name)) == 0) {
			pthread_mutex_unlock(&file_mutex);
			return &scanned_files[i];
		}
	}
	return NULL;
}

void scan_file(char *path)
{
	FILE *f = fopen(path, "r");
	errno = 0;
	if(!f) {
		printf("%s error %d\n, wrong file path \n",path, errno);
		return;
	}
	printf("successfully opened file\n");
	char word[MAX_WORD_LEN];
	int idx = 0;
	int ignore = 0;
	char c;
	while ((c = fgetc(f)) != EOF)			//parsiranje fajla rec po rec
	{
		if(c == ' ' || c == '\n' || c == '\t')
		{	
			word[idx] = '\0';	
			if (!ignore && idx > 0){
				trie_add_word(word);			//ubacivanje reci u trie	
			} 
			ignore = 0;
			idx = 0;
			word[0] = '\0';
		}
		else
		{
			if (c >= 'A' && c <= 'Z')
				c = c + 32;				//to lowercase
			if (! (c >= 'a' && c <= 'z')) ignore = 1;	//ako sadrzi nedozvoljeni karakter ignorise se
			else if (!ignore && idx < 63) word[idx++] = c;
		}
	}			
	fclose(f);
	printf("file closed\n");
}

void free_scanned () {
	pthread_mutex_destroy(&file_mutex);
	free(scanned_files);
}

void* scanner_work(void* _args)
{
	DIR *dr;
	char dir_name[256];
	strcpy(dir_name, (char*)_args);

	dr = opendir(dir_name);		//otvaranje direktorijuma
	if (! dr) {
		printf("odabrani direktorijum ne postoji\n");
		pthread_exit(NULL);
	}

	do {
		if(! dr) {
			printf("odabrani direktorijum je uklonjen\n");
			break;
		}

		rewinddir(dr);					//premotamo na pocetak dir-a
		struct dirent *en;
		while(en = readdir(dr))			//citamo entry po entry
		{
			if (en->d_type == DT_REG)	//ako je entry obican fajl
			{
				printf("%s\n", en->d_name);
				char *path = malloc(strlen(dir_name) + strlen(en->d_name) + 3);
				strcpy(path, dir_name);
				strcat(path, "/");
				strcat(path, en->d_name);	//kreiramo fajlov path
				struct stat statbuf;		
				stat(path, &statbuf);		//izvlacimo fajl statistiku za vreme modifikacije
				time_t time = statbuf.st_mtime;
				
				pthread_mutex_lock(&file_mutex);					//pod istim mutexom odjednom se radi iteracija kroz niz fajlova kao i upisivanje/menjanje njega
				struct scanned_file *sf = find_scanned_file(en->d_name);	//da bi se sprecilo svako moguce preplitanje zbog neatomicnih operacija
				if (sf == NULL) sf = add_scanned_file(en->d_name, statbuf.st_mtime);	//ako fajl nije u nizu skeniranih fajlova dodajemo ga
				else if (sf->mod_time != statbuf.st_mtime){								//ako je menjan od proslog skeniranja azuriramo mu vreme skeniranja
						sf->mod_time = time;
				}
				else {																	//ako fajl nije menjan od proslog skeniranja preskacemo ga
					pthread_mutex_unlock(&file_mutex);
					continue;			
				}
				pthread_mutex_unlock(&file_mutex);
				//printf("%s, en name %s\n", path, en->d_name);
				scan_file(path);
			}
		}
		sleep(5);
	} while (!scan_stop && dr);

	if (dr) closedir(dr);
	pthread_exit(NULL);
}

struct trie_node* make_node()
{
	struct trie_node *node = (struct trie_node*)calloc(1, sizeof(struct trie_node));
	node->c = 0;
	node->term = 0;
	node->subwords = 0;
	node->parent = NULL;
	for (int i=0; i<LETTERS; i++){
		node->children[i] = NULL;
	}
	return node;
}

void trie_init(){
	root = make_node();
	for(int i = 0; i < LETTERS; i++)
	{
		pthread_mutex_init(&trie_mutex[i], NULL);
	}
}

void trie_add_word(char *arg)
{
	int level;
	char word[64];
	strcpy(word, arg);
	int length = strlen(word);
	struct trie_node *temp = root;
	int index;

	int lock = CHAR_TO_INDEX(word[0]);
	if(lock < 0 || lock > 25) return;
	pthread_mutex_lock(&trie_mutex[lock]);			//zakljucavamo mutex sa indeksom pocetnog slova reci
	
	for (level = 0; level < length; level++)		//prolazimo kroz sva slova reci
	{
		index = CHAR_TO_INDEX(word[level]);	
		if (index < 0 || index > 25) {
			pthread_mutex_unlock(&trie_mutex[lock]);
			return;	
		}	
		if (! temp->children[index]){				//ako za trenutni node trazeni child char ne postoji pravimo ga
			temp->children[index] = make_node();
			temp->children[index]->parent = temp;
			temp->children[index]->c = word[level];
		}
		temp = temp->children[index];				//ako trazeni child postoji, idemo dalje u dubinu
	}
	if (temp->term == 0){							//ako kraj dodate reci nije vec bio oznacen kao kraj
		temp->term = 1;								//podizemo term flag i svim roditeljima povecamo broj subwords za 1
		for (level = length-1; level >= 0; level--){
			temp->parent->subwords++;
			temp = temp->parent;
		}
		//ako je rec nova, proveravamo da li je rezultat trenutne pretrage
		if (current_prefix != NULL && cback != NULL && strncmp(current_prefix, word, strlen(current_prefix)) == 0) {
			cback(word);
		}
	}

	pthread_mutex_unlock(&trie_mutex[lock]);
}

int isLastNode (struct trie_node *node){
	for (int i=0; i<LETTERS; i++)
		if(node->children[i]) return 0;
	return 1;
}

struct search_result* recursive_search(struct trie_node *temp, char *prefix, struct search_result *result)
{
	if (temp->term) {
		strcpy(result->words[result->count++], prefix);
	}
	if (isLastNode(temp)) {
		return result;
	}
	if (result->count == result->size){
		printf("panic: the result count has reached the allocated result size\n");
		return result;
	}																	

	for(int i = 0; i < LETTERS; i++)
	{
		if (temp->children[i])			//za svako dete poslednjeg slova prefiksa
		{								//pozivamo rekurzivnu funkciju za rec (prefix + child char)
			char new[strlen(prefix) + 2];
			strcpy(new, prefix);
			char str[2];
			str[0] = i + 'a';
			str[1] = '\0';
			strcat(new, str);
			result = recursive_search(temp->children[i], new, result);
			
		}
	}
	return result;
}

search_result* trie_get_words(char *prefix)	
{
	struct trie_node *temp = root;
	struct search_result *result = (struct search_result*)malloc(sizeof(struct search_result));	//TODO dinamicka alokacija tj realloc
	result->count = 0;
	int n = strlen(prefix);
	int index;

	int lock = CHAR_TO_INDEX(prefix[0]);
	if (index < 0 || index > 25) return NULL;
	pthread_mutex_lock(&trie_mutex[lock]);		//lock nad pocetnim slovom reci koju trazimo

	for (int level = 0; level < n; level++)
	{
		index = CHAR_TO_INDEX(prefix[level]);
		if (index < 0 || index > 25) {
			pthread_mutex_unlock(&trie_mutex[lock]);
			return NULL;
		}
		if (!temp->children[index]){
			pthread_mutex_unlock(&trie_mutex[lock]);	
			return NULL;											//ako ne moze da se dodje do kraja nema rezultata za taj prefiks
		}
		temp = temp->children[index];
	}
	result->size = temp->subwords;	//u rezultatu ce biti sve podreci datog prefiksa
	if (temp->term) result->size++;	//ako je sam prefiks rec u trie, dodati i nju u rezultat
	
	result->words = malloc(result->size * sizeof(char*)); 
	for(int i = 0; i < result->size; i++){
		result->words[i] = malloc(MAX_WORD_LEN * sizeof(char));
	}
	result = recursive_search(temp, prefix, result);

	pthread_mutex_unlock(&trie_mutex[lock]);
	return result;
}

void trie_set_current_prefix(char *prefix, void (*callback)(char *word)) {
	current_prefix = prefix;
	cback = callback;
}

void trie_reset_current_prefix() {
	current_prefix = NULL;
	cback = NULL;
}

void add_result (char *word) {
	printf("%s\n", word);
}

void free_trie(trie_node *node){
	if (node == NULL) return;
	if (node->children == NULL) return;
	for (int i = 0; i < LETTERS; i++) {
		if (node->children[i] != NULL) {
			free_trie(node->children[i]);
			node->children[i] = NULL;
		}
	}
	free(node);
}


void trie_free_result(search_result *result) {
	
	for (int i = 0; i < result->size; i++){
		if (result->words[i]) {
			free(result->words[i]);
			result->words[i] = NULL;
		}
	}
	free(result->words);
	result->words = NULL;
	free(result);
	result = NULL;
}

int main(int argc, char *argv[])
{
	pthread_t scan_threads[16];
	search_result *result = NULL;
	int dir_count = 0;
	scanner_init();
	trie_init();

	char *add_code = "_add_";
	char *stop_code = "_stop_";
	char dir[256];
	char *line = malloc(256);
    size_t size = 255;
    int flagStop;

    while (1) {
   		flagStop = 1;
    	int flagAdd = 1;
      	int c = getline(&line, &size, stdin);
        int i = 0 ;

        while(line[i]!='\n' && line[i]!='\0')
        {
        	if(line[0]!='_')
        	{
        		flagStop = 0;
        		flagAdd = 0;
        		char* token;
        		char* prev;
        		token = strtok(line," \n");

        		while(token!=NULL)
        		{
        			prev = token;
        			token = strtok(NULL," ");
        		}
        		printf("uneta rec za pretragu: %s\n", prev);
        		result = trie_get_words(prev);		//zapocinjanje search-a
        		printf("posle pretrage\n");
        		if (result) {
   					for (int i = 0; i < result->size; i++) {
   						printf("%s\n", result->words[i]);
   					}
        			trie_free_result(result);
        		} 
        		else printf("no results for this prefix\n");

    			trie_set_current_prefix(prev, add_result);

        		while (getc(stdin) != EOF) {}
    			trie_reset_current_prefix();

        		printf("search stopped\n");
        		break;
       		}
       		if(i<5 && line[i] != add_code[i]) flagAdd = 0;
      		if(i<6 && line[i] != stop_code[i]) flagStop = 0;
      		if(i == 5 && flagAdd == 1)
      		{
      			int n = 0;
      			i++;

      			while(line[i]!='\n' && line[i] !=' ')
      			{
     				dir[n] = line[i];
     				i++;
      				n++;
      				dir[n] = '\0';
     			}
    			pthread_create(&scan_threads[dir_count++], NULL, scanner_work, (void*)dir);	//zapocinjanje scanner threada za prosledjeni dir
      			break;
     		}
     
        	i++;
        	if(i==6 && flagStop == 1) break;	
       }   
       if(i >= 6 && flagStop == 1) break;	
    }

    scan_stop = 1;
    for (int i = 0; i < dir_count; i++) {		//joinovanje scanner threadova
    	printf("joining thread %d of %d\n", i, dir_count - 1);
    	pthread_join (scan_threads[i], NULL);
    }
	free_scanned();	//unistavanje mutexa za niz fajlova i free-ovanje niza
	printf("free scanned\n");
	for (int i = 0; i< LETTERS; i++){
		pthread_mutex_destroy(&trie_mutex[i]);
	}
	printf("trie mutex destroyed\n");
	free_trie(root);
	printf("free root\n");

	return 0;
}


