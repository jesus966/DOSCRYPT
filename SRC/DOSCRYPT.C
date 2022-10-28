/*
**        File:  DOSCRYPT.C
**      Author:  Jesus Fernandez Gamito
**        Date:  27/10/22
**
** Description:  DOSCRYPT encrypt or decrypts a file using AES256
**               
*/

/* System includes */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

/* Application includes */
#include "aes.h"
#include "sha256.h"

/* Constants */
#define MAGIC_WORD              "PASSPHRASEDOK"
#define MAX_BUFFER_SIZE         64
#define KEY_SIZE                32
#define IV_SIZE                 16
#define FILE_BLOCK_SIZE         1024
#define AES_FILE_VERSION        0                   
#define AES_CIPHER_MODE         0                   //0 is CBC mode

/* Error constants */
#define NO_ERROR                0
#define HELP_DISPLAYED          1
#define INVALID_PARAMETERS      2
#define IO_ERROR                3
#define INVALID_FILE            4
#define INVALID_PASSPHRASE      5
#define OUT_OF_MEMORY           6

/* String constants */
#define INVALID_PARAMETERS_MSG  \
"Invalid parameters, use /? for help.\n\n"

#define MSG_INFO                \
"DOSCRYPT version 1.0.0\n\n"

#define MSG_HELP                \
"Encrypts or decrypts a file using AES-256.\n" \
"\n" \
"Use:\n" \
"\n" \
"DOSCRYPT.EXE [/?] [/D] [/S] [/V] [/P][passphrase] SOURCE DEST" \
"\n\n" \
"/?                     Shows this help screen.\n"\
"/D                     Decrypts the given file.\n"\
"/S                     Silent mode.\n"\
"/V                     Verbose mode.\n"\
"/P PASSPHRASE          Set the passphrase to encrypt or decrypt.\n"\
"SOURCE                 Source file to encrypt or decrypt.\n"\
"DEST                   Encrypted or decrypted destination file.\n"

#define MSG_PASSPHRASE          \
"Please introduce your passphrase: "

#define MSG_INV_PASSPHRASE      \
"\nInvalid passphrase!\n"

#define MSG_IO_ERROR            \
"\nI/O Error in file operation!\n"

#define MSG_INVALID_FILE        \
"\nInvalid encrypted file!\n"

#define MSG_OUT_OF_MEMORY       \
"\nNot enought memory!\n"

#define DECRYPT_MSG             \
"\nDecrypting file, please wait...\n\n"

#define DECRYPT_OK_MSG          \
"File decrypted successfully in %llu seconds!\n"

#define ENCRYPT_MSG             \
"\nEncrypting file, please wait...\n\n"

#define ENCRYPT_OK_MSG          \
"File encrypted successfully in %llu seconds!\n"

#define VERBOSE_KEY             \
"KEY=%s\n"

#define VERBOSE_IV              \
"IV=%s\n"

#define VERBOSE_MW              \
"EMW=%s\n"

#define VERBOSE_BLOCK_SIZE      \
"BLOCK SIZE=%u Bytes\n\n"

#define VERBOSE_PADDING         \
"PADDING=%u\n\n"

/* Structs */
typedef struct
{
    const char      signature[3];                   //File header signature
    unsigned char   version;                        //AES file version
    unsigned char   ciphermode;                     //Cipher mode (0 is CBC)
    unsigned int    padding;                        //Pading
    char            iv[AES_BLOCKLEN];               //Initialization Vector
    char            magicword[AES_BLOCKLEN];        //MAGIC_WORD encrypted
} fileHeader;

/* Function declarations */
int parse_cmd_line(int argc, char * argv[]);
void show_error_msg(int return_code);
int search_parameter(int argc, char* argv[], char parameter);
int find_paths(int argc, char* argv[]);
void get_passphrase();
void vector_to_string(char* string, uint8_t* vector, int length);
void random_iv(char * iv, int size);
int encrypt_file();
int decrypt_file();
int initialize_buffer();

/* Global variables */
uint8_t DECRYPT_MODE = 0;
uint8_t SILENT_MODE = 0;
uint8_t VERBOSE_MODE = 0;
char PASSPHRASE[MAX_BUFFER_SIZE];
char SOURCE_FILE[MAX_BUFFER_SIZE];
char DEST_FILE[MAX_BUFFER_SIZE];
uint8_t* BUFFER = NULL;
uint8_t STR[(KEY_SIZE*2)+1];

/****************************************************************************/

/**
*       int main(int argc, char * argv[]){
*
*       Main function of the program
*
*       Parameters
*       ----------                                                                  
*       argc: int
*           Number of command line arguments
*   
*       argv[]: char *
*           Command line data buffer
*           
**/
int main(int argc, char * argv[])
{
    /* Declare variables */
    int return_code = NO_ERROR;
    time_t t;
    
    /* Initialice variables */
    PASSPHRASE[0] = 0;
    SOURCE_FILE[0] = 0;
    DEST_FILE[0] = 0;
    srand((unsigned) time(&t)); //Start random generator with time as a seed
    
    /* Process comand line parameters, if any */
    return_code = parse_cmd_line(argc, argv);
    
    if(return_code == NO_ERROR){
        /* Show program info on screen */
        if (!SILENT_MODE) printf(MSG_INFO);
        
        if (!SILENT_MODE && VERBOSE_MODE) {
            printf(VERBOSE_BLOCK_SIZE, FILE_BLOCK_SIZE);
        }
        
        /* Get passphrase, if it wasn't on the command line */
        get_passphrase();
        
        if (!PASSPHRASE[0]){
            /* No passphrase provided */
            return_code = INVALID_PARAMETERS;
        }else{
            
            /* Encrypt or decrypt files */
            if (DECRYPT_MODE){
                /* Show message */
                if (!SILENT_MODE) printf(DECRYPT_MSG);
                
                /* Measure execution time */
                t = time(NULL);
                
                return_code = decrypt_file();
                
                if (!SILENT_MODE 
                    && return_code == NO_ERROR) printf(DECRYPT_OK_MSG, 
                                                    (unsigned long long)
                                                    (time(NULL)- t));
                
            }else{
                /* Show message */
                if (!SILENT_MODE) printf(ENCRYPT_MSG);
                
                /* Measure execution time */
                t = time(NULL);
                
                return_code = encrypt_file();
                
                if (!SILENT_MODE 
                    && return_code == NO_ERROR) printf(ENCRYPT_OK_MSG, 
                                                    (unsigned long long)
                                                    (time(NULL)- t));
            }
        }
    }   
    
    /* Print error messages on screen, if any */
    show_error_msg(return_code);
    
    return return_code;
}

/**
*       int initialize_buffer()
*
*       Initializes the buffer in wich we will read/write/encrypt/decrypt.
*
*       Parameters
*       ----------
*       None
*   
*           
*       Returns
*       -------
*       int:
*            NO_ERROR if there was no error, or OUT_OF_MEMORY error code
*
**/
int initialize_buffer()
{
    /* Declare variables */
    int return_code = NO_ERROR;
    
    /* Try to reserve memory */
    BUFFER = (uint8_t*) malloc(FILE_BLOCK_SIZE);

    if (BUFFER == NULL) return_code = OUT_OF_MEMORY;
    
    return return_code;
}

/**
*       void random_iv(char * iv, int size)
*
*       Generates a random iv vector of the specified size
*
*       Parameters
*       ----------
*       char*: iv
*            IV vector
*       int: size
*            Vector size
*   
*           
*       Returns
*       -------
*       None
*
**/
void random_iv(char * iv, int size)
{
    /* Declare variables */
    int i;

    /* Fill iv vector with random byte values */
    for (i = 0; i < size; i++)
    {
        uint8_t random_value = rand() % 256;
        iv[i] = random_value;
    }
}

/**
*       int encrypt_file()
*
*       Encrypts SOURCE_FILE to DEST_FILE using AES256.
*
*       Parameters
*       ----------
*       None
*   
*           
*       Returns
*       -------
*       int:
*            ERRORLEVEL with the result
*
**/
int encrypt_file(){
    
    /* Declare variables */
    int return_code = NO_ERROR;
    uint8_t key[KEY_SIZE];
    uint8_t iv[IV_SIZE];
    uint8_t magic_word[AES_BLOCKLEN];
    struct AES_ctx ctx;
    fileHeader header;
    FILE *sfptr = NULL;
    FILE *dfptr = NULL;
    size_t ret_value; 
    
    /* Initialize header */
    header.signature[0] = 'A';
    header.signature[1] = 'E';
    header.signature[2] = 'S';
    header.version = AES_FILE_VERSION;
    header.ciphermode = AES_CIPHER_MODE;
    header.padding = 0;
    strcpy(header.magicword, MAGIC_WORD);
    
    /* Initialize data buffer */
    return_code = initialize_buffer();
    
    if (return_code != OUT_OF_MEMORY){
        /* Calculate SHA256 hash of the passphrase */
        calc_sha_256(key, PASSPHRASE, strlen(PASSPHRASE));
        
        /* Generate a random IV and copy it to header */
        random_iv(iv, IV_SIZE);
        strncpy(header.iv, iv, IV_SIZE);
        
        /* Encrypt magic word */
        AES_init_ctx_iv(&ctx, key, iv);
        AES_CBC_encrypt_buffer(&ctx, header.magicword, AES_BLOCKLEN);

        /* Verbose data if needed */
        if (!SILENT_MODE && VERBOSE_MODE) {
            vector_to_string(STR, key, KEY_SIZE);
            printf(VERBOSE_KEY, STR);
            vector_to_string(STR, iv, AES_BLOCKLEN);
            printf(VERBOSE_IV, STR);
            vector_to_string(STR, header.magicword, AES_BLOCKLEN);
            printf(VERBOSE_MW, STR);
        }
        
        /* Open source an dest file */
        sfptr = fopen(SOURCE_FILE, "rb");
        dfptr = fopen(DEST_FILE, "wb");
        
        /* Write header to destination file*/
        ret_value = fwrite(&header, 1, sizeof(fileHeader), dfptr);  
        
        if (sfptr == NULL 
                || dfptr == NULL 
                || ret_value != sizeof(fileHeader)){
                    
            return_code = IO_ERROR;
            
        }else{
            
            AES_init_ctx_iv(&ctx, key, iv);
            
            do
            {
                /* Read file in chunks of FILE_BLOCK_SIZE */
                ret_value = fread(BUFFER, 1, FILE_BLOCK_SIZE, sfptr);

                /* Encrypt buffer and write to the dest file */
                AES_CBC_encrypt_buffer(&ctx, BUFFER, FILE_BLOCK_SIZE);
                if (fwrite(BUFFER, 1, FILE_BLOCK_SIZE, dfptr) 
                        != FILE_BLOCK_SIZE) return_code = IO_ERROR;
                
                    
                /* If this is the last data block, calculate padding */
                if (feof(sfptr)){
                    
                    header.padding = ret_value;
                    
                    if (!SILENT_MODE && VERBOSE_MODE)
                        printf(VERBOSE_PADDING, ret_value);
                    
                    /* Move to the beggining of the file and rewrite header */
                    fseek(dfptr, 0, SEEK_SET);
                    if (fwrite(&header, 1, sizeof(fileHeader), dfptr)
                        != sizeof(fileHeader)) return_code = IO_ERROR;
                    
                }               
            }while (ret_value == FILE_BLOCK_SIZE && return_code == NO_ERROR);
        }
        
        /* Close files, if opened */
        if (sfptr != NULL)
            fclose(sfptr);
        
        if (dfptr != NULL)
            fclose(dfptr);
    }
    
    return return_code;
}

/**
*       int decrypt_file()
*
*       Decrypts SOURCE_FILE to DEST_FILE using AES256.
*
*       Parameters
*       ----------
*       None
*   
*           
*       Returns
*       -------
*       int:
*            ERRORLEVEL with the result
*
**/
int decrypt_file(){
    
    int return_code = NO_ERROR;
    uint8_t key[KEY_SIZE];
    uint8_t iv[IV_SIZE];
    uint8_t magic_word[AES_BLOCKLEN];
    struct AES_ctx ctx;
    fileHeader header;
    FILE *sfptr = NULL;
    FILE *dfptr = NULL;
    size_t ret_value;
    
    /* Initialize variables and data buffer */
    strcpy(magic_word, MAGIC_WORD);
    return_code = initialize_buffer();
    
    if (return_code != OUT_OF_MEMORY){
        
        /* Calculate SHA256 hash of the passphrase */
        calc_sha_256(key, PASSPHRASE, strlen(PASSPHRASE));
        
        /* Open source file */
        sfptr = fopen(SOURCE_FILE, "rb");
        
        if (sfptr == NULL){
            return_code = IO_ERROR;
        }else{
            /* Read header from source file */
            if(fread(&header, 1, sizeof(fileHeader), sfptr) 
                != sizeof(fileHeader)){
                    return_code = IO_ERROR;
            }else{
                
                /* Check if is a valid AES file */
                if (header.signature[0] != 'A' 
                    || header.signature[1] != 'E'
                    || header.signature[2] != 'S'
                    || header.version != AES_FILE_VERSION
                    || header.ciphermode != AES_CIPHER_MODE){
                        
                        return_code = INVALID_FILE;
                        
                }else{
                    /* Verbose data if needed */
                    if (!SILENT_MODE && VERBOSE_MODE) {
                        vector_to_string(STR, key, KEY_SIZE);
                        printf(VERBOSE_KEY, STR);
                        vector_to_string(STR, header.iv, AES_BLOCKLEN);
                        printf(VERBOSE_IV, STR);
                        vector_to_string(STR, header.magicword, AES_BLOCKLEN);
                        printf(VERBOSE_MW, STR);
                        printf(VERBOSE_PADDING, header.padding);
                    }   
                    
                    /* Try to decrypt magic word */
                    AES_init_ctx_iv(&ctx, key, header.iv);
                    AES_CBC_decrypt_buffer(&ctx, header.magicword, 
                                                AES_BLOCKLEN);

                    if (strcmp(magic_word, header.magicword) != 0){
                        return_code = INVALID_PASSPHRASE;
                    }else{
                        
                        /* Password is OK, decrypt file */
                        AES_init_ctx_iv(&ctx, key, header.iv);
                        
                        dfptr = fopen(DEST_FILE, "wb");
                        
                        if (dfptr == NULL){
                            return_code = IO_ERROR;
                        }else{
                            /* Read file in chunks of FILE_BLOCK_SIZE */
                            do
                            {
                                ret_value = fread(BUFFER, 1, FILE_BLOCK_SIZE, 
                                                    sfptr);
                                
                                /* There is more FILE_BLOCK_SIZE chunks? */
                                fgetc(sfptr);
                                if (feof(sfptr)){
                                    /* This is the last FILE_BLOCK_SIZE,
                                        apply padding.*/
                                    AES_CBC_decrypt_buffer(&ctx, BUFFER, 
                                                            FILE_BLOCK_SIZE);
                                    ret_value = 0;

                                    if(header.padding
                                        && fwrite(BUFFER, 1, header.padding, 
                                                dfptr) != header.padding)
                                            return_code = IO_ERROR;
                                }else{
                                    /* There is more FILE_BLOCK_SIZE chunks,
                                       seek back and read the chunk */
                                    fseek(sfptr, -1, SEEK_CUR);
                                    
                                    /* Decrypt buffer and write to the 
                                       dest file */
                                    AES_CBC_decrypt_buffer(&ctx, BUFFER, 
                                                            FILE_BLOCK_SIZE);

                                    if (fwrite(BUFFER, 1, FILE_BLOCK_SIZE, 
                                            dfptr) != FILE_BLOCK_SIZE){
                                        return_code = IO_ERROR;
                                    }
                                }
                            }while (ret_value == FILE_BLOCK_SIZE 
                                        && return_code == NO_ERROR);
                        }
                    }
                    
                }
            }

        }
        
        /* Close files, if opened */
        if (sfptr != NULL)
            fclose(sfptr);
        
        if (dfptr != NULL)
            fclose(dfptr);
    }
    return return_code;
}

/**
*       void vector_to_string(char* string, uint8_t* vector, int length)
*
*       Converts any vector to a string with hexadecimal values.
*
*       Parameters
*       ----------                                                                  
*       string: char*
*           String with hexadecimal values
*       vector: uint8_t*
*           Vector to convert
*       length: int
*           Length of the vector
*   
*           
*       Returns
*       -------
*       None
*
**/
void vector_to_string(char* string, uint8_t* vector, int length)
{
    /* Declare variables */
    int i;
    
    /* Format each hex value and append it to the string */
    for (i = 0; i < length; i++) {
        string += sprintf(string, "%02x", vector[i]);
    }
}

/**
*       void get_passphrase()
*
*       Gets the passphrase from the screen if it wasn't supplied in the 
*       command line.
*
*       Parameters
*       ----------                                                                  
*       None
*   
*           
*       Returns
*       -------
*       None
*
**/
void get_passphrase(){
    
    /* Declare variables */
    int i;
    
    if (!PASSPHRASE[0] && !SILENT_MODE){
        /* Get input from user */
        printf(MSG_PASSPHRASE);
        fgets(PASSPHRASE, MAX_BUFFER_SIZE, stdin);
        
        /* Remove carry flag from the input string */
        for(i=0; i<MAX_BUFFER_SIZE; i++){
            if (PASSPHRASE[i] == 10 || PASSPHRASE[i] == 13){
                PASSPHRASE[i] = 0;
            }
        }
    }
}

/**
*       int parse_cmd_line(int argc, char * argv[])
*
*       Parses the command line.
*
*       Parameters
*       ----------                                                                  
*       argc: int
*           Number of command line arguments
*       argv: char *
*           Command line arguments
*   
*           
*       Returns
*       -------
*       int:
*           Paremeter code
*
**/
int parse_cmd_line(int argc, char * argv[]){
    
    /* Declare variables */
    int return_code;
    int i;

    return_code = NO_ERROR;
    
    if (argc == 1){
        /* No parameters specified */
        return_code = HELP_DISPLAYED;
    }else{

        /* Check for the '/?' parameter */
        if (search_parameter(argc, argv, '?'))
            return_code = HELP_DISPLAYED;
        
        /* If there is no help parameters, check for others */
        if (return_code != HELP_DISPLAYED){
            
            /* Check for decrypt mode */
            if (search_parameter(argc, argv, 'D'))
                DECRYPT_MODE = 1;

            /* Check for silent mode */
            if (search_parameter(argc, argv, 'S'))
                SILENT_MODE = 1;

            /* Check for verbose mode */
            if (search_parameter(argc, argv, 'V'))
                VERBOSE_MODE = 1;
            
            /* Check if there is a passphrase */
            i = search_parameter(argc, argv, 'P');
            /* The next parameter in the cmd is assumed to be the 
               phassphrase */
            if (i && (argc > i)){
                strcpy(PASSPHRASE, argv[i+1]);
            }
            
            /* Find source and destination file paths*/
            if (!find_paths(argc, argv)){
                return_code = INVALID_PARAMETERS;
            }
        }
    }
    
    return return_code;
}


/**
*       int find_paths(int argc, char* argv[])
*
*
*       Searchs for the origin and destination file paths in the command
*       line.
*
*       Parameters
*       ----------                  
*       argc: int
*           Number of command line arguments                                                
*       argv: char *
*           Command line arguments
*           
*       Returns
*       -------
*       int:
*           0 if there where no origin or destiny file in command line, >0
*           if yes.
*
**/
int find_paths(int argc, char* argv[]){
    
    /* Declare variables */
    int return_code = 0;
    int i = 0;
    int j = 0;
    
    /* Get if there where a passphrase, to avoid this index number */
    j = search_parameter(argc, argv, 'p');
    if (j && (argc > j)) j++;

    /* Search for paths */
    if (argc > 2){
        
        for (i = 1; i<argc; i++){
            if (argv[i][0] != '-' && argv[i][0] != '/'){        
                /* Source file path found, get also destination file path */
                if (i && (argc > i)){
                    strcpy(SOURCE_FILE, argv[i-1]);
                    strcpy(DEST_FILE, argv[i]);
                    return_code = i;
                }
            }
            
            /* Skip passphrase position, if any */
            if (i+1 == j) i++;
        }
    }
    
    return return_code;
}


/**
*       int search_parameter(int argc, char* argv[], char parameter)
*
*
*       Searchs if the specified parameter is in the command line
*       arguments.
*
*       Parameters
*       ----------                  
*       argc: int
*           Number of command line arguments                                                
*       argv: char *
*           Command line arguments
*       parameter: char
*           Parameter to find
*           
*       Returns
*       -------
*       int:
*           0 if the parameter isn't in the commandline, element index 
*           number if found
*
**/
int search_parameter(int argc, char* argv[], char parameter){
    
    /* Declare variables */
    int return_code = 0;
    int i = 0;
    
    /* Search parameter */
    if (argc > 1 ){
        for (i = 1; i<argc; i++){
            if ((argv[i][0] == '-' || argv[i][0] == '/') 
                    && argv[i][1] == parameter){
                /* Parameter found, return its index */
                return_code = i;
            }
        }
    }
    
    return return_code;
}

/**
*       void show_error_msg(int return_code)
*
*       Shows error messages on screen, if any.
*
*       Parameters
*       ----------                                                                  
*       int: return_code
*           Error value to show on screen
*   
*           
*       Returns
*       -------
*       None
*
**/
void show_error_msg(int return_code){
    
    /* Switch between each error message code, if not in silent mode */
    if (!SILENT_MODE){
        switch (return_code)
        {
            case HELP_DISPLAYED:
                printf(MSG_HELP);
                break;
            
            case INVALID_PARAMETERS:
                printf(INVALID_PARAMETERS_MSG);
                break;
            
            case IO_ERROR:
                printf(MSG_IO_ERROR);
                break;
            
            case INVALID_FILE:
                printf(MSG_INVALID_FILE);
                break;
            
            case INVALID_PASSPHRASE:
                printf(MSG_INV_PASSPHRASE);
                break;
            
            case OUT_OF_MEMORY:
                printf(MSG_OUT_OF_MEMORY);
                break;
        }
    }
}
