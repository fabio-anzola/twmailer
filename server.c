#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <dirent.h>
#include <errno.h>
#include <linux/limits.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/wait.h>
#define LDAP_DEPRECATED 1
#include <ldap.h>
#include <lber.h>
#include <openssl/sha.h>
#include <time.h>

///////////////////////////////////////////////////////////////////////////////

// Buffer size
#define BUF 4096

///////////////////////////////////////////////////////////////////////////////

// Initialize global vars
int abortRequested = 0;
int create_socket = -1;
int new_socket = -1;

// Mutex (semaphore) for file system access
pthread_mutex_t *mutex;

///////////////////////////////////////////////////////////////////////////////

// Path to blacklist file
const char BLACKLIST[PATH_MAX] = "./.blacklist.txt";

// Generated sha256 hash from username and ip addr
char *generate_hash(char *user, char *addr)
{
    // Buffer to store the resulting SHA256 hash as a string
    static char hash[65];
    unsigned char digest[SHA256_DIGEST_LENGTH];

    // Buffer to store concatenated input
    char input[512];

    // Concatenate the input strings
    snprintf(input, sizeof(input), "%s%s", user, addr);

    // Compute the SHA256 hash
    SHA256((unsigned char *)input, strlen(input), digest);

    // Convert the SHA256 hash to a hexadecimal string
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
    {
        sprintf(&hash[i * 2], "%02x", digest[i]);
    }

    return hash;
}

// Check if the user + ip combo is blacklisted
int checkBlacklist(char *user, char *addr)
{
    // get current timestamp
    time_t now = time(NULL);

    // gen referance hash of user and addr
    char *hash = generate_hash(user, addr);

    // Check if fs access is available
    pthread_mutex_lock(mutex);

    // open blacklist file
    FILE *file = fopen(BLACKLIST, "r");
    if (file == NULL)
    {
        perror("Error opening file");
        fclose(file);
        pthread_mutex_unlock(mutex);
        exit(EXIT_FAILURE);
        return 1;
    }

    // Buffer to store line (line by line)
    char line[256];

    // Var to store nr of attempts by above hash
    int nr_of_attempts = 0;

    // Var to store time of latest attempt
    time_t last_attempt = 0;

    // loop thorugh lines of Blacklist
    while (fgets(line, sizeof(line), file))
    {
        // Remove the newline character at the end of the line and null terminate it
        char *newline = strchr(line, '\n');
        if (newline)
        {
            *newline = '\0';
        }

        // Cut line at '#'
        // part1 is hash
        // part2 is time
        // Use a temporary pointer to pass to strsep (as it needs double ptr)
        char *temp = line;                // temp points to line
        char *part1 = strsep(&temp, "#"); // strsep splits the string at #
        char *part2 = temp;               // temp now points to the remaining part

        // if line is eual to rference hash
        if (strcmp(part1, hash) == 0)
        {
            // Convert part2 to time_t
            char *endptr; // used for error check
            time_t stored_time = (time_t)strtoll(part2, &endptr, 10);

            // Check if the conversion was successful
            if (*endptr != '\0')
            {
                printf("Invalid timestamp: %s\n", part2);
                exit(EXIT_FAILURE);
            }

            // Increase nr of attepts by one
            nr_of_attempts++;

            // Check if this line shows more current event than already ssen
            if (difftime(stored_time, last_attempt) > 0)
            {
                last_attempt = stored_time;
            }
        }
    }

    // Close blacklist file and remove lock
    fclose(file);                // Close the file
    pthread_mutex_unlock(mutex); // release fs

    // check if more than 3 attempts have been made
    if (nr_of_attempts >= 3)
    {
        // check if 60s have passed since last attempt
        if (difftime(now, last_attempt) < 60)
        {
            // if not -> blacklisted for 60s!
            return 1;
        }
    }

    return 0; // not blacklisted
}

// log login attempt in blacklist file
void addLoginAttempt(char *user, char *addr)
{
    // get current epoch time
    time_t now = time(NULL);

    // generate hash of user + ip
    char *hash = generate_hash(user, addr);

    // pointer to blacklist file
    FILE *sbjFilePtr;

    // Check if fs access is available
    pthread_mutex_lock(mutex);

    // open blacklist file
    sbjFilePtr = fopen(BLACKLIST, "a");
    if (!sbjFilePtr)
    {
        perror("Failed to open blacklist file");
        pthread_mutex_unlock(mutex);
        return;
    }

    // Write hash + current time into blacklist
    fprintf(sbjFilePtr, "%s#%ld\n", hash, now);

    // Close blacklist file and unlock fs
    fclose(sbjFilePtr);
    pthread_mutex_unlock(mutex);
}

// remove user + ip hash combo from blacklist file
void removeLoginAttempt(char *user, char *addr)
{
    // generate hash of user + ip
    char *hash = generate_hash(user, addr);

    // add 2 pointers one fror blacklist file and one for temp file
    FILE *blacklistPtr;
    FILE *tempFilePtr;

    // Check if fs access is available
    pthread_mutex_lock(mutex);

    // open blacklist file
    blacklistPtr = fopen(BLACKLIST, "r");
    if (!blacklistPtr)
    {
        perror("Failed to open blacklist file");
        pthread_mutex_unlock(mutex);
        return;
    }

    // open temporary file
    tempFilePtr = fopen("./.blacklist_temp.txt", "w");
    if (!tempFilePtr)
    {
        perror("Failed to open temporary blacklist file");
        fclose(tempFilePtr);
        pthread_mutex_unlock(mutex);
        return;
    }

    // loop through blacklist file
    char line[256];
    while (fgets(line, sizeof(line), blacklistPtr))
    {
        // Remove trailing newline and null terminate
        char *newline = strchr(line, '\n');
        if (newline)
        {
            *newline = '\0';
        }

        // Check if the line contains the hash
        if (strstr(line, hash) == NULL) // null if not found or first pos if found
        {
            // hash not found -> write to temp file
            fprintf(tempFilePtr, "%s\n", line);
        }
    }

    // Close both files
    fclose(blacklistPtr);
    fclose(tempFilePtr);

    // delete original blacklist file
    if (remove(BLACKLIST) != 0)
    {
        perror("Failed to remove original blacklist file");
    }
    // move temp file to new blacklist file
    else if (rename("./.blacklist_temp.txt", BLACKLIST) != 0)
    {
        perror("Failed to rename temporary file");
    }

    // unlock fs
    pthread_mutex_unlock(mutex);
}

///////////////////////////////////////////////////////////////////////////////

// Function to send "ERR" via socket
void sendErr(int *current_socket)
{
    if (send(*current_socket, "ERR", 3, 0) == -1)
    {
        perror("send answer failed");
        return;
    }
}

// Function to send "OK" via socket
void sendOk(int *current_socket)
{
    if (send(*current_socket, "OK", 3, 0) == -1)
    {
        perror("send answer failed");
        return;
    }
}

// Ldap authentication here
int checkUserLogon(char ldapUser[128], char ldapPasswd[128]) // ldapuser=if24b001 ldappasswd=s3cret
{
    // return 0; // enable for developemnt

    // Setup var for ldap handle
    LDAP *ldap_handle;

    // Setup vars for ldap connections
    const char *ldapUri = "ldap://ldap.technikum-wien.at:389";
    const int ldapVersion = LDAP_VERSION3;

    // For users designuished name (dn)
    char ldapBindUser[256];
    // For users bind password
    char ldapBindPassword[256];

    // Setup dn
    sprintf(ldapBindUser, "uid=%s,ou=people,dc=technikum-wien,dc=at", ldapUser);

    // Setup pw
    strcpy(ldapBindPassword, ldapPasswd);

    // Initialize LDAP connection
    int rc = ldap_initialize(&ldap_handle, ldapUri);
    if (rc != LDAP_SUCCESS)
    {
        fprintf(stderr, "Failed to initialize LDAP connection: %s\n", ldap_err2string(rc));
        return EXIT_FAILURE;
    }

    // Set LDAP protocol version
    ldap_set_option(ldap_handle, LDAP_OPT_PROTOCOL_VERSION, &ldapVersion);

    // Attempt to bind (authenticate) with provided DN and password
    rc = ldap_simple_bind_s(ldap_handle, ldapBindUser, ldapBindPassword);

    // if (rc == LDAP_SUCCESS)
    // {
    //     printf("Ldap Authentication successful.\n");
    // }
    // else
    // {
    //     fprintf(stderr, "Authentication failed: %s\n", ldap_err2string(rc));
    // }

    // Cleanup
    ldap_unbind_ext_s(ldap_handle, NULL, NULL);
    return rc == LDAP_SUCCESS ? EXIT_SUCCESS : EXIT_FAILURE;
}

// Signal handler for SIGINT - shutdown socket
void signalHandler(int sig)
{
    if (sig == SIGINT)
    {
        printf("abort Requested... "); // ignore error
        abortRequested = 1;
        /////////////////////////////////////////////////////////////////////////
        // With shutdown() one can initiate normal TCP close sequence ignoring
        // the reference count.
        // https://beej.us/guide/bgnet/html/#close-and-shutdownget-outta-my-face
        // https://linux.die.net/man/3/shutdown
        if (new_socket != -1)
        {
            if (shutdown(new_socket, SHUT_RDWR) == -1)
            {
                perror("shutdown new_socket");
            }
            if (close(new_socket) == -1)
            {
                perror("close new_socket");
            }
            new_socket = -1;
        }

        if (create_socket != -1)
        {
            if (shutdown(create_socket, SHUT_RDWR) == -1)
            {
                perror("shutdown create_socket");
            }
            if (close(create_socket) == -1)
            {
                perror("close create_socket");
            }
            create_socket = -1;
        }

        // Non-blocking wait for child processes
        pid_t pid;
        while ((pid = waitpid(-1, NULL, WNOHANG)))
        {
            if ((pid == -1) && (errno != EINTR))
            {
                break;
            }
        }

        pthread_mutex_destroy(mutex);
        munmap(mutex, sizeof(pthread_mutex_t));
    }
    else
    {
        exit(sig);
    }
}

// function to check for recv error based on size
int checkError(int size)
{
    // if size is neagtive then error occured
    if (size == -1)
    {
        perror("recv error");
        return 0;
    }
    // if size is zero socket must be closed?
    else if (size == 0)
    {
        printf("Remote socket closed\n");
        return 0;
    }
    return 1;
}

// function to create a new directory
void createDir(char *directoryName)
{
    // var to open directory
    DIR *dir;

    // try to open dir
    dir = opendir(directoryName);
    if (dir)
    {
        // Directory exists
        // nothing to do
        // close dir
        closedir(dir);
    }
    else if (ENOENT == errno) // if could not enter directory
    {
        // Directory does not exist

        // create directory
        int check = mkdir(directoryName, 0755);

        // check for return code
        if (check == 0)
        {
            return; // erfolreich
        }
        else if (errno == ENOENT)
        {
            perror("Mail Spool directory does not exist!");
            exit(1);
        }
        else
        {
            perror("Unable to create directory\n");
            exit(1);
        }
    }
    else
    {
        // could not enter dir for other reasons
        perror("Could not check for directory");
        exit(1);
    }
    return;
}

// function to handle mailer function list
void mailerList(int *current_socket, char *buffer, char *mailSpoolDirectory, char *userptr)
{
    // Check if fs access is available
    pthread_mutex_lock(mutex);

    // Prepare vars for mail direcotry
    DIR *directory;
    struct dirent *entry;

    // Open Mailspool dir
    directory = opendir(mailSpoolDirectory);

    // Check if dir could be opened
    if (directory == NULL)
    {
        perror("Error opening directory");
        sendErr(current_socket);
        // Unlock mutex
        pthread_mutex_unlock(mutex);
        return;
    }

    // Check if there is an inbox for the username
    int foundUsrInbox = 0;
    while ((entry = readdir(directory)) != NULL)
    {
        if (strcmp(userptr, entry->d_name) == 0)
        {
            foundUsrInbox = 1;
            break;
        }
    }

    // Close mail spool directory
    if (closedir(directory) == -1)
    {
        printf("%s\n", "Error closing directory");
        sendErr(current_socket);
        // Unlock mutex
        pthread_mutex_unlock(mutex);
        return;
    }
    // Unlock mutex
    pthread_mutex_unlock(mutex);

    // If no inbox found return message count 0
    if (!foundUsrInbox)
    {
        if (send(*current_socket, "0", 3, 0) == -1)
        {
            perror("send answer failed");
            return;
        }
    }
    else
    {
        // Inbox found

        // Prpare vars for dir listing
        DIR *directory;
        struct dirent *entry;

        // Create var for user inbox folder
        char userFolder[PATH_MAX];

        // create path to user inbox (.../mailSpool/username)
        strcpy(userFolder, mailSpoolDirectory);
        strcat(userFolder, "/");
        strcat(userFolder, userptr);

        // Check if fs access is available
        pthread_mutex_lock(mutex);

        // open user inbox
        directory = opendir(userFolder);

        // check if directory could be opened
        if (directory == NULL)
        {
            perror("Error opening directory");
            // Unlock mutex
            pthread_mutex_unlock(mutex);
        }

        // init vars for file search / lisiting
        int foundMessages = 0;

        // create new temp buffer for subject names
        char msg[BUF] = {0}; // Auf 0 initialisieren damit speicher ggf nich überlebt

        // loop though user inbox
        while ((entry = readdir(directory)) != NULL)
        {
            // If not . or ..
            if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
            {
                foundMessages += 1;

                // add newline to msg for client
                strcat(msg, "\n");
                // add subject title to msg for client
                strcat(msg, entry->d_name);
            }
        }

        // Close inbox dir
        if (closedir(directory) == -1)
        {
            printf("%s\n", "Error closing directory");
            // Unlock mutex
            pthread_mutex_unlock(mutex);
            return;
        }
        // Unlock mutex
        pthread_mutex_unlock(mutex);

        // Add nr of messages to buffer
        sprintf(buffer, "%d", foundMessages);

        // Add temp buffer of subject names to buffer
        strcat(buffer, msg);

        // send contructed msg to client
        if (send(*current_socket, buffer, strlen(buffer), 0) == -1)
        {
            perror("send answer failed");
            // Unlock mutex
            pthread_mutex_unlock(mutex);
            return;
        }
    }

    // Free dynamic copy for username
    return;
}

// function to handle mailer function read
void mailerRead(int *current_socket, char *buffer, char *mailSpoolDirectory, char *userptr)
{
    // prepare directory for message read
    DIR *directory;
    struct dirent *entry;

    // Check if fs access is available
    pthread_mutex_lock(mutex);

    // Open mailspool directory
    directory = opendir(mailSpoolDirectory);

    // check if dir could be opened
    if (directory == NULL)
    {
        perror("Error opening directory");
        sendErr(current_socket);
        // Unlock mutex
        pthread_mutex_unlock(mutex);
        return;
    }

    // Check if there is an inbox for the username
    int foundUsrInbox = 0;
    while ((entry = readdir(directory)) != NULL)
    {
        if (strcmp(userptr, entry->d_name) == 0)
        {
            foundUsrInbox = 1;
            break;
        }
    }

    // Close mail spool directory
    if (closedir(directory) == -1)
    {
        printf("%s\n", "Error closing directory");
        sendErr(current_socket);
        // Unlock mutex
        pthread_mutex_unlock(mutex);
        return;
    }

    // Unlock mutex
    pthread_mutex_unlock(mutex);

    // If no inbox found return ERR else OK and proceed
    if (!foundUsrInbox)
    {
        sendErr(current_socket);
    }
    else
    {
        sendOk(current_socket);

        // Get Message ID
        int size = recv(*current_socket, buffer, BUF - 1, 0);
        if (!checkError(size))
        {
            sendErr(current_socket);
            return;
        }

        // sanitize msg ending and 0 temrinate buffer
        if (buffer[size - 2] == '\r' && buffer[size - 1] == '\n')
        {
            size -= 2;
        }
        else if (buffer[size - 1] == '\n')
        {
            --size;
        }
        buffer[size] = '\0';

        // create dynamic copy of message id (from buffer)
        char *messageid = strdup(buffer);

        // Get and read file
        // prepare vars for file reading
        DIR *directory;
        struct dirent *entry;

        // create var for message path
        char userFolder[PATH_MAX] = {0}; // Intit as new! Speicher überlebt nicht!

        // contruct mesage path (.../mailSpool/username/)
        strcat(userFolder, mailSpoolDirectory);
        strcat(userFolder, userptr);
        strcat(userFolder, "/");

        // Check if fs access is available
        pthread_mutex_lock(mutex);

        // Open inbox folder
        directory = opendir(userFolder);

        // check if inbox could be opened
        if (directory == NULL)
        {
            perror("Error oppening directory");
            free(messageid);
            sendErr(current_socket);
            // Unlock mutex
            pthread_mutex_unlock(mutex);
            return;
        }

        // get file by msg nr
        int currFile = 0;
        int foundFile = 0;
        while ((entry = readdir(directory)) != NULL)
        {
            // If not . or ..
            if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
            {
                currFile += 1;
                if (currFile == atoi(messageid)) // check if current iteration is = to specified message number
                {
                    foundFile = 1;
                    strcat(userFolder, entry->d_name); // add filename to path (.../mailSpool/username/ + subject.txt)
                    break;
                }
            }
        }

        // close inbox directory
        if (closedir(directory) == -1)
        {
            printf("%s\n", "Error closing directory");
            free(messageid);
            sendErr(current_socket);
            // Unlock mutex
            pthread_mutex_unlock(mutex);
            return;
        }

        // Unlock mutex
        pthread_mutex_unlock(mutex);

        // check if file has been found
        if (foundFile)
        {
            // Check if fs access is available
            pthread_mutex_lock(mutex);

            // Open file
            FILE *file = fopen(userFolder, "r");

            // check if file could be opened
            if (file == NULL)
            {
                printf("%s\n", "Error opening message ");
                free(messageid);
                sendErr(current_socket);
                // Unlock mutex
                pthread_mutex_unlock(mutex);
                return;
            }

            // Get File size
            fseek(file, 0, SEEK_END);     // go to end of file
            long file_size = ftell(file); // get pos -> file size
            rewind(file);                 // go back to start of file for read

            // Create new temp buffer (dynamic for filesize)
            char *f_buffer = (char *)malloc(file_size + 1 + 3); // 3 for "OK"

            // check if buffer could be allocated
            if (f_buffer == NULL)
            {
                perror("Temp buffer alloc failed");
                free(f_buffer);
                fclose(file);
                free(messageid);
                sendErr(current_socket);
                // Unlock mutex
                pthread_mutex_unlock(mutex);
                return;
            }

            // Write OK to buffer
            strcpy(f_buffer, "OK\n");

            // Read file into buffer
            size_t bytes_read = fread(f_buffer + 3, 1, file_size, file); // +3 offset for OK

            // check if file was read correctly
            if (bytes_read != file_size)
            {
                perror("File could not be read");
                free(f_buffer);
                fclose(file);
                free(messageid);
                sendErr(current_socket);
                // Unlock mutex
                pthread_mutex_unlock(mutex);
                return;
            }

            // Null terminate file buffer
            f_buffer[file_size + 3] = '\0'; // +3 for OK prefix

            // Send (temp) buffer back to client
            if (send(*current_socket, f_buffer, strlen(f_buffer), 0) == -1)
            {
                perror("send answer failed");
                free(f_buffer);
                fclose(file);
                free(messageid);
                // Unlock mutex
                pthread_mutex_unlock(mutex);
                return;
            }

            // free dynamic alloc file buffer
            free(f_buffer);
            // close file descr
            fclose(file);
            // Unlock mutex
            pthread_mutex_unlock(mutex);
        }
        else
        {
            sendErr(current_socket);
        }

        // finally free dynam copy for messageid
        free(messageid);
    }

    return;
}

// function to handle mailer function send
void mailerSend(int *current_socket, char *buffer, char *mailSpoolDirectory, char *userptr)
{
    // Answer OK
    sendOk(current_socket);

    // Get Receiver ID
    int size = recv(*current_socket, buffer, BUF - 1, 0);
    if (!checkError(size))
    {
        sendErr(current_socket);
        return;
    }

    // sanitize msg and 0 terminate
    if (buffer[size - 2] == '\r' && buffer[size - 1] == '\n')
    {
        size -= 2;
    }
    else if (buffer[size - 1] == '\n')
    {
        --size;
    }
    buffer[size] = '\0';

    // make dynamic copy of receiver from  buffer
    char *receiver = strdup(buffer);

    // Answer OK
    sendOk(current_socket);

    // Create Receiver Directory (.../spooldir/receiver)
    char receiverDir[PATH_MAX] = {0}; // initialize to prevent saved stack
    strcpy(receiverDir, mailSpoolDirectory);
    strcat(receiverDir, "/");
    strcat(receiverDir, receiver);

    // Check if fs access is available
    pthread_mutex_lock(mutex);

    // Create directory for receiver
    createDir(receiverDir);

    // Unlock mutex
    pthread_mutex_unlock(mutex);

    // Get Subject
    size = recv(*current_socket, buffer, BUF - 1, 0);

    if (!checkError(size))
    {
        free(receiver);
        sendErr(current_socket);
        return;
    }

    // sanitize msg and 0 terminate
    if (buffer[size - 2] == '\r' && buffer[size - 1] == '\n')
    {
        size -= 2;
    }
    else if (buffer[size - 1] == '\n')
    {
        --size;
    }
    buffer[size] = '\0';

    // make dynamic copy for subject out of buffer
    char *subject = strdup(buffer);

    // Answer OK
    sendOk(current_socket);

    // Create File with Subject Name (.../spooldir/receiver + /subject.txt)
    FILE *sbjFilePtr;
    strcat(receiverDir, "/");
    strcat(receiverDir, subject);
    strcat(receiverDir, ".txt");

    // Check if fs access is available
    pthread_mutex_lock(mutex);

    // open subject file
    sbjFilePtr = fopen(receiverDir, "w");

    // Write header with sender name
    fprintf(sbjFilePtr, "# Message by %s:\n\n", userptr);

    // Get Message
    // TODO: Could write into temp buffer so mutex doesnt stay locked for too long
    do
    {
        size = recv(*current_socket, buffer, BUF - 1, 0);
        if (!checkError(size))
        {
            free(receiver);
            free(subject);
            fclose(sbjFilePtr);
            sendErr(current_socket);
            // Unlock mutex
            pthread_mutex_unlock(mutex);
            return;
        }

        // sanize msg and 0 terminate
        if (buffer[size - 2] == '\r' && buffer[size - 1] == '\n')
        {
            size -= 2;
        }
        else if (buffer[size - 1] == '\n')
        {
            --size;
        }
        buffer[size] = '\0';

        // write msg into file descr
        fprintf(sbjFilePtr, "%s\n", buffer);

    } while (!((buffer[0] == '.') && (strlen(buffer) == 1)));

    // File ptr freigeben
    fclose(sbjFilePtr);

    // Unlock mutex
    pthread_mutex_unlock(mutex);

    // Answer OK
    sendOk(current_socket);

    // Danymische kopien freigeben
    free(receiver);
    free(subject);

    return;
}

// function to handle mailer function del
void mailerDel(int *current_socket, char *buffer, char *mailSpoolDirectory, char *userptr)
{
    // prep ars to open mail spool
    DIR *directory;
    struct dirent *entry;

    // Check if fs access is available
    pthread_mutex_lock(mutex);

    // open mail spool
    directory = opendir(mailSpoolDirectory);

    // check if dir could be opened
    if (directory == NULL)
    {
        perror("Error opening directory");
        sendErr(current_socket);
        // Unlock mutex
        pthread_mutex_unlock(mutex);
        return;
    }

    // Check if there is an inbox for the username
    int foundUsrInbox = 0;
    while ((entry = readdir(directory)) != NULL)
    {
        if (strcmp(userptr, entry->d_name) == 0)
        {
            foundUsrInbox = 1;
            break;
        }
    }

    // Close mail spool directory
    if (closedir(directory) == -1)
    {
        perror("Error closing directory");
        sendErr(current_socket);
        // Unlock mutex
        pthread_mutex_unlock(mutex);
        return;
    }

    // Unlock mutex
    pthread_mutex_unlock(mutex);

    // If no inbox found return ERR else OK
    if (!foundUsrInbox)
    {
        sendErr(current_socket);
    }
    else
    {
        sendOk(current_socket);
        // Get Message ID
        int size = recv(*current_socket, buffer, BUF - 1, 0);
        if (!checkError(size))
        {
            return;
        }

        // sanitize msg and 0 terminate it
        if (buffer[size - 2] == '\r' && buffer[size - 1] == '\n')
        {
            size -= 2;
        }
        else if (buffer[size - 1] == '\n')
        {
            --size;
        }
        buffer[size] = '\0';

        // make dynamic copy of message id
        char *messageid = strdup(buffer);

        // Prep vars to find and del file
        DIR *directory;
        struct dirent *entry;

        // contruct inbox path (.../mailSpoolDirectory/username/)
        char userFolder[PATH_MAX];
        strcpy(userFolder, mailSpoolDirectory);
        strcat(userFolder, "/");
        strcat(userFolder, userptr);
        strcat(userFolder, "/");

        // Check if fs access is available
        pthread_mutex_lock(mutex);

        // Open inbox folder
        directory = opendir(userFolder);

        // check if inbox could be opened
        if (directory == NULL)
        {
            perror("Error opening directory");
            sendErr(current_socket);
            free(messageid);
            // Unlock mutex
            pthread_mutex_unlock(mutex);
            return;
        }

        // get file with msg nr
        int currFile = 0;
        while ((entry = readdir(directory)) != NULL)
        {
            // If not . or ..
            if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
            {
                currFile += 1;
                if (currFile == atoi(messageid)) // current iteration = message number specified
                {
                    strcat(userFolder, entry->d_name); // add filename to filepath construct
                    break;
                }
            }
        }

        // delete file
        if (remove(userFolder) == 0)
        {
            // Remove is successful
            sendOk(current_socket);
        }
        else
        {
            sendErr(current_socket);
        }

        // Close inbox directory
        if (closedir(directory) == -1)
        {
            perror("Error closing directory");
            free(messageid);
            sendErr(current_socket);
            // Unlock mutex
            pthread_mutex_unlock(mutex);
            return;
        }

        // Unlock mutex
        pthread_mutex_unlock(mutex);

        // Free dynam alloc messageid
        free(messageid);
    }

    // Free dynam alloc username
    return;
}

// Handle user authentication procedure
int mailerLogon(int *current_socket, char *buffer, char *userptr, char *addr)
{
    int size = 0;

    // Answer OK
    sendOk(current_socket);

    // Get username
    size = recv(*current_socket, buffer, BUF - 1, 0);
    if (!checkError(size))
    {
        sendErr(current_socket);
        return EXIT_FAILURE;
    }

    // sanitize msg and 0 terminate
    if (buffer[size - 2] == '\r' && buffer[size - 1] == '\n')
    {
        size -= 2;
    }
    else if (buffer[size - 1] == '\n')
    {
        --size;
    }
    buffer[size] = '\0';

    // make dynamic copy of username in buffer
    char *username = strdup(buffer);

    // pass username back to client handler for further use
    strcpy(userptr, username);

    // check for blacklisted
    if (checkBlacklist(username, addr))
    {
        free(username);
        sendErr(current_socket);
        return 0;
    }

    // Answer OK
    sendOk(current_socket);

    // Get password
    size = recv(*current_socket, buffer, BUF - 1, 0);
    if (!checkError(size))
    {
        sendErr(current_socket);
        free(username);
        return EXIT_FAILURE;
    }

    // sanitize msg and 0 terminate
    if (buffer[size - 2] == '\r' && buffer[size - 1] == '\n')
    {
        size -= 2;
    }
    else if (buffer[size - 1] == '\n')
    {
        --size;
    }
    buffer[size] = '\0';

    // make dynamic copy of username in buffer
    char *password = strdup(buffer);

    int status = checkUserLogon(username, password);

    free(username);
    free(password);

    if (status == EXIT_SUCCESS)
    {
        sendOk(current_socket);
        return 1;
    }

    sendErr(current_socket);
    return 0;
}

// function to handle client communication and call mailer funcs
void *clientCommunication(int *current_socket, char *mailSpoolDirectory, char *cliAddr)
{
    // initialize communications vars
    char buffer[BUF];
    int size;
    // int *current_socket = (int *)data;

    // flag for user auth
    int user_authenticated = 0;
    char username[16];

    ////////////////////////////////////////////////////////////////////////////
    // SEND welcome message
    // strcpy(buffer, "Welcome to TWMailer Basic!\r\nPlease enter your commands...\r\n");
    snprintf(buffer, BUF, "%s", "Welcome to TWMailer Basic!\r\nPlease enter your commands...\r\n");
    if (send(*current_socket, buffer, strlen(buffer), 0) == -1)
    {
        perror("send failed");
        return NULL;
    }

    do
    {
        /////////////////////////////////////////////////////////////////////////
        // RECEIVE
        size = recv(*current_socket, buffer, BUF - 1, 0);
        if (!checkError(size))
        {
            sendErr(current_socket);
            break;
        }

        // remove ugly debug message, because of the sent newline of client
        if (buffer[size - 2] == '\r' && buffer[size - 1] == '\n')
        {
            size -= 2;
        }
        else if (buffer[size - 1] == '\n')
        {
            --size;
        }
        buffer[size] = '\0';

        printf("Message received: %s\n", buffer); // ignore error

        // Enter correct mailer function based on input
        if (strcmp(buffer, "LOGIN") == 0)
        {
            printf("%s", "Entered LOGIN \n");
            user_authenticated = mailerLogon(current_socket, buffer, username, cliAddr); //  username is now also set!
            // If not sucessful
            if (!user_authenticated)
            {
                // Add login attempt
                addLoginAttempt(username, cliAddr);
            }
            else
            {
                // If sucessfull
                removeLoginAttempt(username, cliAddr);
            }
        }
        // if not authenticated
        else if (!user_authenticated)
        {
            // Err and no other command than login allowed
            sendErr(current_socket);
        }
        else
        {

            // Enter correct mailer function based on input
            if (strcmp(buffer, "SEND") == 0)
            {
                printf("%s", "Entered SEND \n");
                mailerSend(current_socket, buffer, mailSpoolDirectory, username);
            }

            // Enter correct mailer function based on input
            else if (strcmp(buffer, "LIST") == 0)
            {
                printf("%s", "Entered LIST \n");
                mailerList(current_socket, buffer, mailSpoolDirectory, username);
            }

            // Enter correct mailer function based on input
            else if (strcmp(buffer, "READ") == 0)
            {
                printf("%s", "Entered READ \n");
                mailerRead(current_socket, buffer, mailSpoolDirectory, username);
            }

            // Enter correct mailer function based on input
            else if (strcmp(buffer, "DEL") == 0)
            {
                printf("%s", "Entered DEL \n");
                mailerDel(current_socket, buffer, mailSpoolDirectory, username);
            }

            else
            {
                sendErr(current_socket);
            }
        }

    } while (strcmp(buffer, "QUIT") != 0 && !abortRequested);

    // closes/frees the descriptor if not already
    if (*current_socket != -1)
    {
        if (shutdown(*current_socket, SHUT_RDWR) == -1)
        {
            perror("could not shutdown socket");
        }
        if (close(*current_socket) == -1)
        {
            perror("could not close socket");
        }
        *current_socket = -1;
    }

    return NULL;
}

///////////////////////////////////////////////////////////////////////////////

int main(int argc, char *argv[])
{
    // prepare socket vars
    socklen_t addrlen;
    struct sockaddr_in address, cliaddress;
    int reuseValue = 1;

    ////////////////////////////////////////////////////////////////////////////u

    // Prpeare vars fro arguments
    int PORT;
    char *mailSpoolDirectory;

    // Read args from terminal call
    if (argc != 3)
    {
        printf("Usage: %s <port> <mail-spool-directoryname>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    else
    {
        PORT = atoi(argv[1]); // String to int
        mailSpoolDirectory = argv[2];
    }

    ////////////////////////////////////////////////////////////////////////////
    // SIGNAL HANDLER
    // SIGINT (Interrup: ctrl+c)
    // https://man7.org/linux/man-pages/man2/signal.2.html
    if (signal(SIGINT, signalHandler) == SIG_ERR)
    {
        perror("signal can not be registered");
        return EXIT_FAILURE;
    }

    ////////////////////////////////////////////////////////////////////////////
    // CREATE A SOCKET
    // https://man7.org/linux/man-pages/man2/socket.2.html
    // https://man7.org/linux/man-pages/man7/ip.7.html
    // https://man7.org/linux/man-pages/man7/tcp.7.html
    // IPv4, TCP (connection oriented), IP (same as client)
    if ((create_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("Socket error"); // errno set by socket()
        return EXIT_FAILURE;
    }

    ////////////////////////////////////////////////////////////////////////////
    // SET SOCKET OPTIONS
    // https://man7.org/linux/man-pages/man2/setsockopt.2.html
    // https://man7.org/linux/man-pages/man7/socket.7.html
    // socket, level, optname, optvalue, optlen
    if (setsockopt(create_socket,
                   SOL_SOCKET,
                   SO_REUSEADDR,
                   &reuseValue,
                   sizeof(reuseValue)) == -1)
    {
        perror("set socket options - reuseAddr");
        return EXIT_FAILURE;
    }

    if (setsockopt(create_socket,
                   SOL_SOCKET,
                   SO_REUSEPORT,
                   &reuseValue,
                   sizeof(reuseValue)) == -1)
    {
        perror("set socket options - reusePort");
        return EXIT_FAILURE;
    }

    ////////////////////////////////////////////////////////////////////////////
    // INIT ADDRESS
    // Attention: network byte order => big endian
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    ////////////////////////////////////////////////////////////////////////////
    // ASSIGN AN ADDRESS WITH PORT TO SOCKET
    if (bind(create_socket, (struct sockaddr *)&address, sizeof(address)) == -1)
    {
        perror("bind error");
        return EXIT_FAILURE;
    }

    ////////////////////////////////////////////////////////////////////////////
    // Initialize Shared Memory
    mutex = mmap(NULL, sizeof(pthread_mutex_t),      // mmap maps file into memeory -> Null menas os chooses adress
                 PROT_READ | PROT_WRITE,             // Allow read & write access
                 MAP_SHARED | MAP_ANONYMOUS, -1, 0); // Updates to memeory should be shared across processes and is not file backed

    if (mutex == MAP_FAILED)
    {
        perror("mmap fehlgeschlagen");
        exit(EXIT_FAILURE);
    }

    // Initialize mutex
    pthread_mutexattr_t attr;                                    // define attribute object for mutex
    pthread_mutexattr_init(&attr);                               // initialize attribute object
    pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED); // makes mutex shared across processes
    pthread_mutex_init(mutex, &attr);                            // initialize mutex in mapped memeory region and with attributes object
    pthread_mutexattr_destroy(&attr);                            // cleans up attribute object as its not used anymore

    ////////////////////////////////////////////////////////////////////////////
    // ALLOW CONNECTION ESTABLISHING
    // Socket, Backlog (= count of waiting connections allowed)
    if (listen(create_socket, 5) == -1)
    {
        perror("listen error");
        return EXIT_FAILURE;
    }

    while (!abortRequested)
    {
        /////////////////////////////////////////////////////////////////////////
        // ignore errors here... because only information message
        // https://linux.die.net/man/3/printf
        printf("Waiting for connections...\n");

        /////////////////////////////////////////////////////////////////////////
        // ACCEPTS CONNECTION SETUP
        // blocking, might have an accept-error on ctrl+c
        addrlen = sizeof(struct sockaddr_in);
        if ((new_socket = accept(create_socket,
                                 (struct sockaddr *)&cliaddress,
                                 &addrlen)) == -1)
        {
            if (abortRequested)
            {
                perror("accept error after aborted");
            }
            else
            {
                perror("accept error");
            }
            break;
        }

        /////////////////////////////////////////////////////////////////////////
        // START CLIENT
        // ignore printf error handling
        printf("Client connected from %s:%d...\n",
               inet_ntoa(cliaddress.sin_addr),
               ntohs(cliaddress.sin_port));

        pid_t pid = fork();
        if (pid < 0)
        {
            perror("fork error");
            close(new_socket); // close socket on error
            continue;
        }
        else if (pid == 0)
        {
            // Child process
            close(create_socket); // child does not need listening socket
            clientCommunication(&new_socket, mailSpoolDirectory, inet_ntoa(cliaddress.sin_addr));
            close(new_socket);
            exit(EXIT_SUCCESS); // exit child process
        }

        // clientCommunication(&new_socket, mailSpoolDirectory); // returnValue can be ignored
        new_socket = -1;
    }

    // frees the descriptor
    if (create_socket != -1)
    {
        if (shutdown(create_socket, SHUT_RDWR) == -1)
        {
            perror("could not shutdown socket");
        }
        if (close(create_socket) == -1)
        {
            perror("could not close socket");
        }
        create_socket = -1;
    }

    // Destroy mutex and unmap memory space
    pthread_mutex_destroy(mutex);
    munmap(mutex, sizeof(pthread_mutex_t));

    // Non-blocking wait for child processes
    pid_t pid;
    while ((pid = waitpid(-1, NULL, WNOHANG)))
    {
        if ((pid == -1) && (errno != EINTR))
        {
            break;
        }
    }

    return EXIT_SUCCESS;
}
