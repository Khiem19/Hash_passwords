#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <string.h>
#include <pthread.h>
#include <stdbool.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h> 

#define NUM_THREADS 13

pthread_mutex_t mutex;
pthread_cond_t condition;


char** share_data2; //dict found
char** share_data3; //email found

int count = 0; 

struct thread_args {
  char **pool_hash; 
  char **pool_dict;
  char ** email_pool;
  int num_hashes;
  int num_dict;
  
};
   
struct MyStruct {
  int id;
  char hash[33];
  char *email;
  char *name;
};

//copy string
char* copyString(char s[])
{
  char* s2;
  s2 = (char*)malloc(strlen(s));
  strcpy(s2, s);
  return (char*)s2;
}

//Prefix and Postfix method
char* prefix_digit(char* word, int digit) {
  char* prefixed = malloc(strlen(word) + sizeof(int));
  sprintf(prefixed, "%d%s", digit, word); 
  return prefixed;
}

char * postfix_digit(char* word, int digit) {
  char* postfixed = malloc(strlen(word) + sizeof(int));
  sprintf(postfixed, "%s%d", word, digit);
  return postfixed;
}

char* twodigit(char* word, int pre, int post){
  char* pre_and_post = malloc(strlen(word) + 2*sizeof(int));
  sprintf(pre_and_post, "%d%s%d", pre, word, post);
  return pre_and_post;
}

// UPPERCASE
char* upper_case(char* word) {
  char* result = word;
  for (int i = 0; i< strlen(result); i++) {
    result[i] = toupper(result[i]);
  }
  return result;
}

char* capitalize(char* word) {
  char* result = word;
  if (strlen(result) > 0) 
  {
    result[0] = toupper(result[0]);
  }
  return result;
}

//Function MD5
void bytes2md5(const char *data, int len, char *md5buf) {
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	const EVP_MD *md = EVP_md5();
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len, i;
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, data, len);
	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	EVP_MD_CTX_free(mdctx);
	for (i = 0; i < md_len; i++) {
		snprintf(&(md5buf[i * 2]), 16 * 2, "%02x", md_value[i]);
	}
}

//Compare 2 strings
bool compare2Strings(char* string1, char* string2) {
  if (sizeof(string1) != sizeof(string2)){
    printf("2 strings dont have the same size\n");
  }
  for (int i = 0; i < sizeof(string1); i++)
  {
    if (string1[i] != string2[i])
    {
      return false;
    }
  }
  return true;
}

//Display all broken passwords
void sighup_handler(int sig) {
  printf("Number of passwords cracked: %d\n",count);
}

/////////////////////// PRODUCERs 1,2,3 (small letters,Upper,Capitalize ) ////////////////////////////////
void *  producer1(void* arg) { 
  struct thread_args *args = (struct thread_args*)arg;
  char **pool_hash = args->pool_hash;
  char **pool_dict = args->pool_dict;
  int num_hashes = args->num_hashes;
  int num_dict = args->num_dict;
  char **email_pool = args->email_pool;

  //calculate MD5
  for (int j = 0; j < num_dict; j++) {
    char *input_string;
    char *hash = malloc(33); //works, because it is independent to anothers
    input_string = copyString(pool_dict[j]); //small words // copy the data, do not assign it
    bytes2md5(input_string,strlen(input_string),hash);
    for (int k = 0; k < num_hashes; k++) {
      pthread_mutex_lock(&mutex);
    
      if (compare2Strings(hash,pool_hash[k]) == true) {
        share_data2[count] = copyString(input_string);
        share_data3[count] = copyString(email_pool[k]);
        count++;
        pthread_cond_signal(&condition);
      }

      pthread_mutex_unlock(&mutex);
    }
    free(input_string); // error: free everything
    free(hash);
  } 
  return NULL;
}  

void *  producer2(void* arg) {
  struct thread_args *args = (struct thread_args*)arg;
  char **pool_hash = args->pool_hash;
  char **pool_dict = args->pool_dict;
  int num_hashes = args->num_hashes;
  int num_dict = args->num_dict;
  char **email_pool = args->email_pool;

  //calculate MD5
  for (int j = 0; j < num_dict; j++) {
          
    char *input_string;
    char *hash = malloc(33); 
    input_string = copyString(pool_dict[j]);
    input_string = upper_case(input_string);
    bytes2md5(input_string,strlen(input_string),hash);
    for (int k = 0; k < num_hashes; k++) {
      pthread_mutex_lock(&mutex);

      if (compare2Strings(hash,pool_hash[k]) == true) {
        share_data2[count] = copyString(input_string);
        share_data3[count] = copyString(email_pool[k]);
        count++;
        pthread_cond_signal(&condition);
      }

      pthread_mutex_unlock(&mutex);
    }
    free(input_string);
    free(hash);
  }
  return NULL;
} 

void *  producer3(void* arg) {
  struct thread_args *args = (struct thread_args*)arg;
  char **pool_hash = args->pool_hash;
  char **pool_dict = args->pool_dict;
  int num_hashes = args->num_hashes;
  int num_dict = args->num_dict;
  char **email_pool = args->email_pool;

  //calculate MD5
  for (int j = 0; j < num_dict; j++) {
          
    char *input_string;
    char *hash= malloc(33); 
    input_string = copyString(pool_dict[j]);
    input_string = capitalize(input_string);
    bytes2md5(input_string,strlen(input_string),hash);
    for (int k = 0; k < num_hashes; k++) {
      pthread_mutex_lock(&mutex);

      if (compare2Strings(hash,pool_hash[k]) == true) {
        share_data2[count] = copyString(input_string);
        share_data3[count] = copyString(email_pool[k]);
        count++;
        pthread_cond_signal(&condition);
      }

      pthread_mutex_unlock(&mutex);
    }
    free(input_string);
    free(hash);
  }
  return NULL;
} 

///////////////////Producer 4,5,6 (Prefix)///////////////////////////
void *  producer4(void* arg) { 
  struct thread_args *args = (struct thread_args*)arg;
  char **pool_hash = args->pool_hash;
  char **pool_dict = args->pool_dict;
  int num_hashes = args->num_hashes;
  int num_dict = args->num_dict;
  char **email_pool = args->email_pool;

  //calculate MD5
  for (int  i = 0; i < 100; i++)
  {
    for (int j = 0; j < num_dict; j++) {
    char *input_string;
    char *hash = malloc(33); //works, because it is independent to anothers
    input_string = copyString(pool_dict[j]); //small words // copy the data, do not assign it
    input_string = prefix_digit(input_string,i);
    bytes2md5(input_string,strlen(input_string),hash);
    for (int k = 0; k < num_hashes; k++) {
      pthread_mutex_lock(&mutex);
      
      if (compare2Strings(hash,pool_hash[k]) == true) {
        share_data2[count] = copyString(input_string);
        share_data3[count] = copyString(email_pool[k]);
        count++;
        pthread_cond_signal(&condition);
      }

      pthread_mutex_unlock(&mutex);
    }
    free(input_string); // error: free everything
    free(hash);
    } 
  }
  return NULL;
} 
    
void *  producer5(void* arg) {
  struct thread_args *args = (struct thread_args*)arg;
  char **pool_hash = args->pool_hash;
  char **pool_dict = args->pool_dict;
  int num_hashes = args->num_hashes;
  int num_dict = args->num_dict;
  char **email_pool = args->email_pool;

  //calculate MD5
  for (int i = 0; i < 100; i++)
  {
    for (int j = 0; j < num_dict; j++) {
          
    char *input_string;
    char *hash = malloc(33); 
    input_string = copyString(pool_dict[j]);
    input_string = upper_case(input_string);
    input_string = prefix_digit(input_string,i);
    bytes2md5(input_string,strlen(input_string),hash);
    for (int k = 0; k < num_hashes; k++) {
      pthread_mutex_lock(&mutex);

      if (compare2Strings(hash,pool_hash[k]) == true) {
        share_data2[count] = copyString(input_string);
        share_data3[count] = copyString(email_pool[k]);
        count++;
        pthread_cond_signal(&condition);
      }

      pthread_mutex_unlock(&mutex);
    }
    free(input_string);
    free(hash);
    }
  }
  return NULL;
} 

void *  producer6(void* arg) {
  struct thread_args *args = (struct thread_args*)arg;
  char **pool_hash = args->pool_hash;
  char **pool_dict = args->pool_dict;
  int num_hashes = args->num_hashes;
  int num_dict = args->num_dict;
  char **email_pool = args->email_pool;

  //calculate MD5
  for (int i = 0; i < 100; i++)
  {
    for (int j = 0; j < num_dict; j++) {
          
    char *input_string;
    char *hash = malloc(33); 
    input_string = copyString(pool_dict[j]);
    input_string = capitalize(input_string);
    input_string = prefix_digit(input_string,i);
    bytes2md5(input_string,strlen(input_string),hash);
    for (int k = 0; k < num_hashes; k++) {
      pthread_mutex_lock(&mutex);

      if (compare2Strings(hash,pool_hash[k]) == true) {
        share_data2[count] = copyString(input_string);
        share_data3[count] = copyString(email_pool[k]);
        count++;
        pthread_cond_signal(&condition);
      }

      pthread_mutex_unlock(&mutex);
    }
    free(input_string);
    free(hash);
    }
  }
  return NULL;
} 
///////////////////Producer 7,8,9 (Postfix)///////////////////////////
void *  producer7(void* arg) { 
  struct thread_args *args = (struct thread_args*)arg;
  char **pool_hash = args->pool_hash;
  char **pool_dict = args->pool_dict;
  int num_hashes = args->num_hashes;
  int num_dict = args->num_dict;
  char **email_pool = args->email_pool;

  //calculate MD5
  for (int  i = 0; i < 100; i++)
  {
    for (int j = 0; j < num_dict; j++) {
    
    char *input_string;
    char *hash = malloc(33); //works, because it is independent to anothers
    input_string = copyString(pool_dict[j]); //small words // copy the data, do not assign it
    input_string = postfix_digit(input_string,i);
    bytes2md5(input_string,strlen(input_string),hash);
    for (int k = 0; k < num_hashes; k++) {
      pthread_mutex_lock(&mutex);
      
      if (compare2Strings(hash,pool_hash[k]) == true) {
        share_data2[count] = copyString(input_string);
        share_data3[count] = copyString(email_pool[k]);
        count++;
        pthread_cond_signal(&condition);
      }

      pthread_mutex_unlock(&mutex);
    }
    free(input_string); // error: free everything
    free(hash);
    } 
  }
  return NULL;
} 

void *  producer8(void* arg) {
  struct thread_args *args = (struct thread_args*)arg;
  char **pool_hash = args->pool_hash;
  char **pool_dict = args->pool_dict;
  int num_hashes = args->num_hashes;
  int num_dict = args->num_dict;
  char **email_pool = args->email_pool;

  //calculate MD5
  for (int i = 0; i < 100; i++)
  {
    for (int j = 0; j < num_dict; j++) {
          
    char *input_string;
    char *hash = malloc(33); 
    input_string = copyString(pool_dict[j]);
    input_string = upper_case(input_string);
    input_string = postfix_digit(input_string,i);
    bytes2md5(input_string,strlen(input_string),hash);
    for (int k = 0; k < num_hashes; k++) {
      pthread_mutex_lock(&mutex);

      if (compare2Strings(hash,pool_hash[k]) == true) {
        share_data2[count] = copyString(input_string);
        share_data3[count] = copyString(email_pool[k]);
        count++;
        pthread_cond_signal(&condition);
      }

      pthread_mutex_unlock(&mutex);
    }
    free(input_string);
    free(hash);
    }
  }
  return NULL;
}

void *  producer9(void* arg) {
  struct thread_args *args = (struct thread_args*)arg;
  char **pool_hash = args->pool_hash;
  char **pool_dict = args->pool_dict;
  int num_hashes = args->num_hashes;
  int num_dict = args->num_dict;
  char **email_pool = args->email_pool;

  //calculate MD5
  for (int i = 0; i < 100; i++)
  {
    for (int j = 0; j < num_dict; j++) {
          
    char *input_string;
    char *hash = malloc(33); 
    input_string = copyString(pool_dict[j]);
    input_string = capitalize(input_string);
    input_string = postfix_digit(input_string,i);
    bytes2md5(input_string,strlen(input_string),hash);
    for (int k = 0; k < num_hashes; k++) {
      pthread_mutex_lock(&mutex);

      if (compare2Strings(hash,pool_hash[k]) == true) {
        share_data2[count] = copyString(input_string);
        share_data3[count] = copyString(email_pool[k]);
        count++;
        pthread_cond_signal(&condition);
      }

      pthread_mutex_unlock(&mutex);
    }
    free(input_string);
    free(hash);
    }
  }
  return NULL;
} 
///////////////////Producer 10,11,12 (2digits)///////////////////////
void *  producer10(void* arg) { 
  struct thread_args *args = (struct thread_args*)arg;
  char **pool_hash = args->pool_hash;
  char **pool_dict = args->pool_dict;
  int num_hashes = args->num_hashes;
  int num_dict = args->num_dict;
  char **email_pool = args->email_pool;

  //calculate MD5
  for (int  i = 0; i < 100; i++)//pre
  {
    for (int y = 0; y < 100; y++)//post
    {
      for (int j = 0; j < num_dict; j++) {
      char *input_string;
      char *hash = malloc(33); //works, because it is independent to anothers
      input_string = copyString(pool_dict[j]); //small words // copy the data, do not assign it
      input_string = twodigit(input_string,i,y);
      bytes2md5(input_string,strlen(input_string),hash);
      for (int k = 0; k < num_hashes; k++) {
        pthread_mutex_lock(&mutex);
        
        if (compare2Strings(hash,pool_hash[k]) == true) {
          share_data2[count] = copyString(input_string);
          share_data3[count] = copyString(email_pool[k]);
          count++;
          pthread_cond_signal(&condition);
        }

        pthread_mutex_unlock(&mutex);
      }
      free(input_string); // error: free everything
      free(hash);
      } 
    }  
  }
  return NULL;
}

void *  producer11(void* arg) { 
  struct thread_args *args = (struct thread_args*)arg;
  char **pool_hash = args->pool_hash;
  char **pool_dict = args->pool_dict;
  int num_hashes = args->num_hashes;
  int num_dict = args->num_dict;
  char **email_pool = args->email_pool;

  //calculate MD5
  for (int  i = 0; i < 100; i++)//pre
  {
    for (int y = 0; y < 100; y++)//post
    {
      for (int j = 0; j < num_dict; j++) {
      char *input_string;
      char *hash = malloc(33); //works, because it is independent to anothers
      input_string = copyString(pool_dict[j]); //small words // copy the data, do not assign it
      input_string = upper_case(input_string);
      input_string = twodigit(input_string,i,y);
      bytes2md5(input_string,strlen(input_string),hash);
      for (int k = 0; k < num_hashes; k++) {
        pthread_mutex_lock(&mutex);
        
        if (compare2Strings(hash,pool_hash[k]) == true) {
          share_data2[count] = copyString(input_string);
          share_data3[count] = copyString(email_pool[k]);
          count++;
          pthread_cond_signal(&condition);
        }

        pthread_mutex_unlock(&mutex);
      }
      free(input_string); // error: free everything
      free(hash);
      } 
    }
  }
  return NULL;
}

void *  producer12(void* arg) { 
  struct thread_args *args = (struct thread_args*)arg;
  char **pool_hash = args->pool_hash;
  char **pool_dict = args->pool_dict;
  int num_hashes = args->num_hashes;
  int num_dict = args->num_dict;
  char **email_pool = args->email_pool;

  //calculate MD5
  for (int  i = 0; i < 100; i++)//pre
  {
    for (int y = 0; y < 100; y++)//post
    {
      for (int j = 0; j < num_dict; j++) {
      char *input_string;
      char *hash = malloc(33); //works, because it is independent to anothers
      input_string = copyString(pool_dict[j]); //small words // copy the data, do not assign it
      input_string = capitalize(input_string);
      input_string = twodigit(input_string,i,y);
      bytes2md5(input_string,strlen(input_string),hash);
      for (int k = 0; k < num_hashes; k++) {
        pthread_mutex_lock(&mutex);
        
        if (compare2Strings(hash,pool_hash[k]) == true) {
          share_data2[count] = copyString(input_string);
          share_data3[count] = copyString(email_pool[k]);
          count++;
          pthread_cond_signal(&condition);
        }

        pthread_mutex_unlock(&mutex);
      }
      free(input_string); // error: free everything
      free(hash);
      } 
    }
  }
  return NULL;
}
////////////////////////////consumer /////////////////////////////////
void *consumer() {
  while (1)
  {
    pthread_mutex_lock(&mutex);
    pthread_cond_wait(&condition, &mutex);
    printf("Password for %s is %s\n", share_data3[count-1], share_data2[count-1]);
    pthread_mutex_unlock(&mutex);
  }
  
}

//////////////////////////////////////////////////////////////////////
int main() {
  char **array;
  int capacity = 10;
  int size = 0;
  char line[1024];

/////////////////////////////////////////////S L O W N I K/////////////////////////////////////////////////////////
  // Open the file
  FILE *file1 = fopen("slownik.txt", "r");
  if (file1 == NULL) {
    printf("open file error\n");
  }

  // Allocate memory for the initial array
  array = (char**)malloc(capacity * sizeof(char*));
  if (array == NULL) {
    printf("malloc error\n");
  }

  // Read the file line by line
  while (fgets(line, sizeof(line), file1) != NULL) {
    // Check if the array is full
    if (size == capacity) {
      // Double the capacity of the array
      capacity *= 2;
      array = (char**)realloc(array, capacity * sizeof(char*));
      if (array == NULL) {
        printf("realloc error\n");
      }
    }

    // Allocate memory for the line
    array[size] = malloc(strlen(line) + 1);
    if (array[size] == NULL) {
      printf("Failed to allocate memory for the line \n");
    }
    
    //removing newline char
    int len = strlen(line);
    if(line[len-1] == '\n') {
      line[len-1] = '\0';
    }

    // Copy the line into the array
    strcpy(array[size], line);
    size++;
  }

  // Close the file
  fclose(file1);
  
///////////////////////////////////////H A S L A/////////////////////////////////////////////////////////
  // Open the text file for reading
  FILE *file2 = fopen("Hasla.txt", "r");
  if (file2 == NULL) {
    perror("Error opening file");
    return 1;
  }

  // Determine the number of elements in the struct
  int num_elements = 1; //if = 0, lost the last element
  while (!feof(file2)) {
    if (fgetc(file2) == '\n') {
      num_elements++;
    }
  }
  rewind(file2);

  // Allocate memory for the struct and its elements
  struct MyStruct *my_struct = malloc(num_elements * sizeof(struct MyStruct));
  if (my_struct == NULL) {
    perror("Error allocating memory");
    return 1;
  }
  for (int i = 0; i < num_elements; i++) {
    my_struct[i].email = malloc(1024 * sizeof(char));
    if (my_struct[i].email == NULL) {
      perror("Error allocating memory");
      return 1;
    }
  }

  for (int i = 0; i < num_elements; i++) {
    my_struct[i].name = malloc(1024 * sizeof(char));
    if (my_struct[i].name == NULL) {
      perror("Error allocating memory");
      return 1;
    }
  }

  // Read the values from the text file and store them in the struct and its elements
  for (int i = 0; i < num_elements; i++) {
    fscanf(file2, "%d %s %s %[^\n]", &my_struct[i].id, my_struct[i].hash, my_struct[i].email, my_struct[i].name);
  }

  // Close the text file
  fclose(file2);


//////////////////T H R E A D S////////////////////////////////////////////////////////////////
  //Initialize mutex
  pthread_mutex_init(&mutex, NULL); 
  
  //Create threads
  pthread_t threads[NUM_THREADS];
  pthread_cond_init(&condition,NULL);
  struct thread_args args;
  
  //Initialize shared_data

  share_data2 = (char**)malloc(num_elements*sizeof(char*));
  for (int i = 0; i < num_elements; i++)
  {
    share_data2[i] = (char*)malloc(20*sizeof(char));
  }

  share_data3 = (char**)malloc(num_elements*sizeof(char*));
  for (int i = 0; i < num_elements; i++)
  {
    share_data3[i] = (char*)malloc(33*sizeof(char));
  }

  /////////////////////malloc for args////////////////////
  args.pool_hash = (char**)malloc(num_elements*sizeof(char*));
  for (int i = 0; i < num_elements; i++)
  {
    args.pool_hash[i] = (char*)malloc(33*sizeof(char));
    args.pool_hash[i] = my_struct[i].hash;
  }
  
  args.pool_dict = (char**)malloc(size * sizeof(char*));

  for (int i = 0; i < size; i++)
  {
    args.pool_dict[i] = malloc(12);
    args.pool_dict[i] = array[i];
  }
  
  args.num_hashes = num_elements;
  args.num_dict = size;

  args.email_pool = (char**)malloc(num_elements * sizeof(char*));
  for (int i = 0; i < num_elements; i++)
  {
    args.email_pool[i] = malloc(20);
    args.email_pool[i] = my_struct[i].email;
  }
  //////////////////////////////////////////////////////////
  //signal(SIGHUP,sighup_handler);

  /////////////////////////////////////////////////////////
  pthread_create(&threads[0], NULL, consumer, NULL);
  pthread_create(&threads[1], NULL, producer1, &args);
  pthread_create(&threads[2], NULL, producer2, &args);
  pthread_create(&threads[3], NULL, producer3, &args);
  pthread_create(&threads[4], NULL, producer4, &args);
  pthread_create(&threads[5], NULL, producer5, &args);
  pthread_create(&threads[6], NULL, producer6, &args);
  pthread_create(&threads[7], NULL, producer7, &args);
  pthread_create(&threads[8], NULL, producer8, &args);
  pthread_create(&threads[9], NULL, producer9, &args);
  pthread_create(&threads[10], NULL, producer10, &args);
  pthread_create(&threads[11], NULL, producer11, &args);
  pthread_create(&threads[12], NULL, producer12, &args);

  
  //Join threads
  for (int i = 0; i < NUM_THREADS; i++) {
    pthread_join(threads[i], NULL);
  }


  //Destroy the mutex
  pthread_mutex_destroy(&mutex);
  pthread_cond_destroy(&condition);

////////////////////////////////////////////////////////////////////////////
  //free prefix and postfix
  //remember to put in funcitons after using

  //Free shared_data
  for (int i = 0; i < num_elements; i++)
  {
    free(share_data2[i]);
  }
  free(share_data2);

  for (int i = 0; i < num_elements; i++)
  {
    free(share_data3[i]);
  }
  free(share_data3);

  ////////////////////////////////////////////////////////////////
  for (int i = 0; i < num_elements; i++)
  {
    free(args.email_pool[i]);
    free(args.pool_hash[i]);
  }
  free(args.pool_hash);
  free(args.email_pool);

  // Free the memory when you're done with it
  for (int i = 0; i < size; i++) {
    free(array[i]);
    free(args.pool_dict[i]);
  }
  free(array);
  free(args.pool_dict);

  // Deallocate memory for the struct and its elements
  for (int i = 0; i < num_elements; i++) {
    free(my_struct[i].email);
    free(my_struct[i].name);
  }
  free(my_struct);
  return 0;
}
