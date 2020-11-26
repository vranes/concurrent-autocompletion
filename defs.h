#define MAX_WORD_LEN 64
#define LETTERS 26
#define CHAR_TO_INDEX(c) ((int)c - (int)'a')	// all words should be lowercase
	
typedef struct trie_node
{
	char c;
	int term;			// end of word flag
	int subwords;			// number of words in the subtree (not counting itself)
	struct trie_node *parent;
	struct trie_node *children[LETTERS];
} trie_node;

typedef struct search_result
{
	int count;	// array length
	int size;
	char **words;		// string array, each string [MAX_WORD_LEN]
} search_result;

typedef struct scanned_file
{
	char name[256];
	time_t mod_time;	// last modification time
} scanned_file;

extern void scanner_init(); 			// called at the system initialization
extern void *scanner_work(void* _args);
extern void trie_init(); 				
extern void trie_add_word(char* word);			// word adding
extern search_result* trie_get_words(char *prefix); 	// word search
extern void trie_free_result(search_result *result);
extern void trie_set_current_prefix(char *prefix, void (*callback)(char *word));	// to support concurrent word search and adding