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

///////////////////////////////////////////////////////////////////////////////

// Buffer size
#define BUF 4096

///////////////////////////////////////////////////////////////////////////////

// Initialize global vars
int abortRequested = 0;
int create_socket = -1;
int new_socket = -1;

pthread_mutex_t *mutex;

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

int checkUserLogon()
{
    return 1;
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
    if (size == -1)
    {
        perror("recv error");
        return 0;
    }
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
void mailerList(int *current_socket, char *buffer, char *mailSpoolDirectory)
{
    // Answer OK
    sendOk(current_socket);

    // Get User ID
    int size = recv(*current_socket, buffer, BUF - 1, 0);
    if (!checkError(size))
    {
        sendErr(current_socket);
        return;
    }

    // Clean msg from rn and 0 terminate
    if (buffer[size - 2] == '\r' && buffer[size - 1] == '\n')
    {
        size -= 2;
    }
    else if (buffer[size - 1] == '\n')
    {
        --size;
    }
    buffer[size] = '\0';

    // Make dynamic copy of buffer for username
    char *username = strdup(buffer);

    // Check if fs access is available
    pthread_mutex_lock(mutex);

    // Prepare vars for mail direcotry
    DIR *directory;
    struct dirent *entry;
    directory = opendir(mailSpoolDirectory);

    // Check if dir could be opened
    if (directory == NULL)
    {
        perror("Error opening directory");
        sendErr(current_socket);
        free(username);
        // Unlock mutex
        pthread_mutex_unlock(mutex);
        return;
    }

    // Check if there is an inbox for the username
    int foundUsrInbox = 0;
    while ((entry = readdir(directory)) != NULL)
    {
        if (strcmp(username, entry->d_name) == 0)
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
        free(username);
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
            free(username);
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
        strcat(userFolder, username);

        // Check if fs access is available
        pthread_mutex_lock(mutex);

        // open user inbox
        directory = opendir(userFolder);

        // check if directory could be opened
        if (directory == NULL)
        {
            perror("Error opening directory");
            free(username);
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
            free(username);
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
            free(username);
            // Unlock mutex
            pthread_mutex_unlock(mutex);
            return;
        }
    }

    // Free dynamic copy for username
    free(username);
    return;
}

// function to handle mailer function read
void mailerRead(int *current_socket, char *buffer, char *mailSpoolDirectory)
{
    // Answer OK
    sendOk(current_socket);

    // Get User ID
    int size = recv(*current_socket, buffer, BUF - 1, 0);
    if (!checkError(size))
    {
        sendErr(current_socket);
        return;
    }

    // sanitize message ending and 0 terminate
    if (buffer[size - 2] == '\r' && buffer[size - 1] == '\n')
    {
        size -= 2;
    }
    else if (buffer[size - 1] == '\n')
    {
        --size;
    }
    buffer[size] = '\0';

    // create dynamic copy of username (in buffer)
    char *username = strdup(buffer);

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
        free(username);
        sendErr(current_socket);
        // Unlock mutex
        pthread_mutex_unlock(mutex);
        return;
    }

    // Check if there is an inbox for the username
    int foundUsrInbox = 0;
    while ((entry = readdir(directory)) != NULL)
    {
        if (strcmp(username, entry->d_name) == 0)
        {
            foundUsrInbox = 1;
            break;
        }
    }

    // Close mail spool directory
    if (closedir(directory) == -1)
    {
        printf("%s\n", "Error closing directory");
        free(username);
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
        size = recv(*current_socket, buffer, BUF - 1, 0);
        if (!checkError(size))
        {
            free(username);
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
        strcat(userFolder, username);
        strcat(userFolder, "/");

        // Check if fs access is available
        pthread_mutex_lock(mutex);

        // Open inbox folder
        directory = opendir(userFolder);

        // check if inbox could be opened
        if (directory == NULL)
        {
            perror("Error oppening directory");
            free(username);
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
            free(username);
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
                free(username);
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
                free(username);
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
                free(username);
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
                free(username);
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

    // finally free danymic copy for usernameid
    free(username);
    return;
}

// function to handle mailer function send
void mailerSend(int *current_socket, char *buffer, char *mailSpoolDirectory)
{
    // Answer OK
    sendOk(current_socket);

    // Get Sender ID
    int size = recv(*current_socket, buffer, BUF - 1, 0);
    if (!checkError(size))
    {
        sendErr(current_socket);
        return;
    }

    // sanitize message and 0 terminate it
    if (buffer[size - 2] == '\r' && buffer[size - 1] == '\n')
    {
        size -= 2;
    }
    else if (buffer[size - 1] == '\n')
    {
        --size;
    }
    buffer[size] = '\0';

    // make dynamic copy of  sender from buffer
    char *sender = strdup(buffer); // dynamisch statt fixe groesse mit strcpy

    // Answer OK
    sendOk(current_socket);

    // Get Receiver ID
    size = recv(*current_socket, buffer, BUF - 1, 0);
    if (!checkError(size))
    {
        sendErr(current_socket);
        free(sender);
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
        free(sender);
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
    fprintf(sbjFilePtr, "# Message by %s:\n\n", sender);

    // Get Message
    // TODO: Could write into temp buffer so mutex doesnt stay locked for too long
    do
    {
        size = recv(*current_socket, buffer, BUF - 1, 0);
        if (!checkError(size))
        {
            free(sender);
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

    } while ((buffer[0] != '.') && (strlen(buffer) != 1));

    // File ptr freigeben
    fclose(sbjFilePtr);

    // Unlock mutex
    pthread_mutex_unlock(mutex);

    // Answer OK
    sendOk(current_socket);

    // Danymische kopien freigeben
    free(sender);
    free(receiver);
    free(subject);

    return;
}

// function to handle mailer function del
void mailerDel(int *current_socket, char *buffer, char *mailSpoolDirectory)
{
    // Answer OK
    sendOk(current_socket);

    // Get User ID
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

    // make dynamic copy of username in buffer
    char *username = strdup(buffer);

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
        free(username);
        sendErr(current_socket);
        // Unlock mutex
        pthread_mutex_unlock(mutex);
        return;
    }

    // Check if there is an inbox for the username
    int foundUsrInbox = 0;
    while ((entry = readdir(directory)) != NULL)
    {
        if (strcmp(username, entry->d_name) == 0)
        {
            foundUsrInbox = 1;
            break;
        }
    }

    // Close mail spool directory
    if (closedir(directory) == -1)
    {
        perror("Error closing directory");
        free(username);
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
        size = recv(*current_socket, buffer, BUF - 1, 0);
        if (!checkError(size))
        {
            free(username);
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
        strcat(userFolder, username);
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
            free(username);
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

        close(userFolder);

        // Unlock mutex
        pthread_mutex_unlock(mutex);

        // Free dynam alloc messageid
        free(messageid);
    }

    // Free dynam alloc username
    free(username);
    return;
}

// function to handle client communication and call mailer funcs
void *clientCommunication(int *current_socket, char *mailSpoolDirectory)
{
    // initialize communications vars
    char buffer[BUF];
    int size;
    // int *current_socket = (int *)data;

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

        // printf("Message received: %s\n", buffer); // ignore error

        // Enter correct mailer function based on input
        if (strcmp(buffer, "SEND") == 0)
        {
            printf("%s", "Entered SEND \n");
            mailerSend(current_socket, buffer, mailSpoolDirectory);
        }

        // Enter correct mailer function based on input
        if (strcmp(buffer, "LIST") == 0)
        {
            printf("%s", "Entered LIST \n");
            mailerList(current_socket, buffer, mailSpoolDirectory);
        }

        // Enter correct mailer function based on input
        if (strcmp(buffer, "READ") == 0)
        {
            printf("%s", "Entered READ \n");
            mailerRead(current_socket, buffer, mailSpoolDirectory);
        }

        // Enter correct mailer function based on input
        if (strcmp(buffer, "DEL") == 0)
        {
            printf("%s", "Entered DEL \n");
            mailerDel(current_socket, buffer, mailSpoolDirectory);
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
            perror("coudl not close socket");
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
            clientCommunication(&new_socket, mailSpoolDirectory);
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

    pthread_mutex_destroy(mutex);
    munmap(mutex, sizeof(pthread_mutex_t));

    return EXIT_SUCCESS;
}
