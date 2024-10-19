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

///////////////////////////////////////////////////////////////////////////////

#define BUF 4096

///////////////////////////////////////////////////////////////////////////////

int abortRequested = 0;
int create_socket = -1;
int new_socket = -1;

///////////////////////////////////////////////////////////////////////////////

void *clientCommunication(void *data, char *mailSpoolDirectory);
void signalHandler(int sig);

int checkError(int size)
{
    if (size == -1)
    {
        perror("recv error");
        return 0;
    }
    else if (size == 0)
    {
        printf("Server closed remote socket\n"); // ignore error
        return 0;
    }
    return 1;
}

void createDir(char *newDir)
{
    int check;
    DIR *dir;

    dir = opendir(newDir);
    if (dir)
    {
        /* Directory exists. */
        closedir(dir);
    }
    else if (ENOENT == errno)
    {
        /* Directory does not exist. */
        check = mkdir(newDir, 0755); // 0777 = permissions: read, write, & execute for owner, group and others

        // check if directory is created or not
        if (!check)
            printf("Directory created\n");
        else
        {
            printf("Unable to create directory\n");
            exit(1);
        }
    }
    else
    {
        /* opendir() failed for some other reason. */
    }
    return;
}

void mailerList(int *current_socket, char *buffer, char *mailSpoolDirectory)
{
    // Answer OK
    if (send(*current_socket, "OK", 3, 0) == -1)
    {
        perror("send answer failed");
        return;
    }

    // Get User ID
    int size = recv(*current_socket, buffer, BUF - 1, 0);
    if (!checkError(size))
    {
        return;
    }
    if (buffer[size - 2] == '\r' && buffer[size - 1] == '\n')
    {
        size -= 2;
    }
    else if (buffer[size - 1] == '\n')
    {
        --size;
    }
    buffer[size] = '\0';
    char *username = strdup(buffer);

    DIR *directory;
    struct dirent *entry;
    directory = opendir(mailSpoolDirectory);

    if (directory == NULL)
    {
        perror("Error opening directory");
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
    }

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
        DIR *directory;
        struct dirent *entry;
        char userFolder[PATH_MAX];
        strcpy(userFolder, mailSpoolDirectory);
        strcat(userFolder, "/");
        strcat(userFolder, buffer);

        directory = opendir(userFolder);
        if (directory == NULL)
        {
            perror("Error opening directory");
        }

        int foundMessages = 0;
        char msg[BUF] = {0}; // Auf 0 initialisieren damit speicher ggf nich überlebt
        while ((entry = readdir(directory)) != NULL)
        {
            // If not . or ..
            if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
            {
                foundMessages += 1;
                strcat(msg, "\n");
                strcat(msg, entry->d_name);
            }
        }
        // Add nr of messages to buffer
        sprintf(buffer, "%d", foundMessages);
        // Add temp buffer of subject names to buffer
        strcat(buffer, msg);
        if (send(*current_socket, buffer, strlen(buffer), 0) == -1)
        {
            perror("send answer failed");
            return;
        }

        // Close inbox dir
        if (closedir(directory) == -1)
        {
            printf("%s\n", "Error closing directory");
        }
    }

    // Free dynamic copy for username
    free(username);
}

void mailerRead(int *current_socket, char *buffer, char *mailSpoolDirectory)
{
    // Answer OK
    if (send(*current_socket, "OK", 3, 0) == -1)
    {
        perror("send answer failed");
        return;
    }

    // Get User ID
    int size = recv(*current_socket, buffer, BUF - 1, 0);
    if (!checkError(size))
    {
        return;
    }
    if (buffer[size - 2] == '\r' && buffer[size - 1] == '\n')
    {
        size -= 2;
    }
    else if (buffer[size - 1] == '\n')
    {
        --size;
    }
    buffer[size] = '\0';
    char *username = strdup(buffer);
    DIR *directory;
    struct dirent *entry;
    directory = opendir(mailSpoolDirectory);
    if (directory == NULL)
    {
        perror("Error opening directory");
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
    }

    // If no inbox found return ERR else OK
    if (!foundUsrInbox)
    {
        if (send(*current_socket, "ERR", 3, 0) == -1)
        {
            perror("send answer failed");
            return;
        }
    }
    else
    {
        if (send(*current_socket, "OK", 3, 0) == -1)
        {
            perror("send answer failed");
            return;
        }

        // Get Message ID
        size = recv(*current_socket, buffer, BUF - 1, 0);
        if (!checkError(size))
        {
            return;
        }
        if (buffer[size - 2] == '\r' && buffer[size - 1] == '\n')
        {
            size -= 2;
        }
        else if (buffer[size - 1] == '\n')
        {
            --size;
        }
        buffer[size] = '\0';
        char *messageid = strdup(buffer);

        // Get and read file
        DIR *directory;
        struct dirent *entry;
        char userFolder[PATH_MAX] = {0}; // Intit as new! Speicher überlebt nicht!
        strcat(userFolder, mailSpoolDirectory);
        strcat(userFolder, username);
        strcat(userFolder, "/");
        // Open inbox folder
        directory = opendir(userFolder);
        if (directory == NULL)
        {
            perror("Error oppening directory");
        }
        // get file with msg nr
        int currFile = 0;
        int foundFile = 0;
        while ((entry = readdir(directory)) != NULL)
        {
            // If not . or ..
            if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
            {
                currFile += 1;
                if (currFile == atoi(messageid))
                {
                    foundFile = 1;
                    strcat(userFolder, entry->d_name);
                    break;
                }
            }
        }
        if (closedir(directory) == -1)
        {
            printf("%s\n", "Error closing directory");
        }
        if (foundFile)
        {
            // Open file
            FILE *file = fopen(userFolder, "r");
            if (file == NULL)
            {
                printf("%s\n", "Error opening message ");
                return;
            }

            // Get File size
            fseek(file, 0, SEEK_END);     // go to end of file
            long file_size = ftell(file); // get pos -> file size
            rewind(file);                 // go back to start of file for read

            // Create new temp buffer (dynamic for filesize)
            char *f_buffer = (char *)malloc(file_size + 1 + 3); // 3 for "OK"
            if (f_buffer == NULL)
            {
                perror("Temp buffer alloc failed");
                fclose(file);
                return;
            }

            // Write OK to BUFFER
            strcpy(f_buffer, "OK\n");

            // Read file into buffer
            size_t bytes_read = fread(f_buffer + 3, 1, file_size, file); // +3 for OK
            if (bytes_read != file_size)
            {
                perror("Fiel could not be read");
                free(f_buffer);
                fclose(file);
                return;
            }
            f_buffer[file_size + 3] = '\0'; // +3 for OK prefix

            // Send buffer back to client
            if (send(*current_socket, f_buffer, strlen(f_buffer), 0) == -1)
            {
                perror("send answer failed");
                free(f_buffer);
                fclose(file);
                return;
            }

            free(f_buffer);
            fclose(file);
        }
        else
        {
            if (send(*current_socket, "ERR", 3, 0) == -1)
            {
                perror("send answer failed");
                return;
            }
        }

        free(messageid);
    }

    free(username);
}

void mailerSend(int *current_socket, char *buffer, char *mailSpoolDirectory)
{
    // Answer OK
    if (send(*current_socket, "OK", 3, 0) == -1)
    {
        perror("send answer failed");
        return;
    }

    // Get Sender ID
    int size = recv(*current_socket, buffer, BUF - 1, 0);
    if (!checkError(size))
    {
        return;
    }
    if (buffer[size - 2] == '\r' && buffer[size - 1] == '\n')
    {
        size -= 2;
    }
    else if (buffer[size - 1] == '\n')
    {
        --size;
    }
    buffer[size] = '\0';
    char *sender = strdup(buffer); // dynamisch statt fixe groesse mit strcpy

    // Answer OK
    if (send(*current_socket, "OK", 3, 0) == -1)
    {
        perror("send answer failed");
        return;
    }

    // Get Receiver ID
    size = recv(*current_socket, buffer, BUF - 1, 0);
    if (!checkError(size))
    {
        return;
    }
    if (buffer[size - 2] == '\r' && buffer[size - 1] == '\n')
    {
        size -= 2;
    }
    else if (buffer[size - 1] == '\n')
    {
        --size;
    }
    buffer[size] = '\0';
    char *receiver = strdup(buffer);

    // Answer OK
    if (send(*current_socket, "OK", 3, 0) == -1)
    {
        perror("send answer failed");
        return;
    }

    // Create Receiver Directory (.../spooldir/receiver)
    char receiverDir[PATH_MAX] = {0}; // initialize to prevent saved stack
    strcpy(receiverDir, mailSpoolDirectory);
    strcat(receiverDir, "/");
    strcat(receiverDir, receiver);
    createDir(receiverDir);

    // Get Subject
    size = recv(*current_socket, buffer, BUF - 1, 0);
    if (!checkError(size))
    {
        return;
    }
    if (buffer[size - 2] == '\r' && buffer[size - 1] == '\n')
    {
        size -= 2;
    }
    else if (buffer[size - 1] == '\n')
    {
        --size;
    }
    buffer[size] = '\0';
    char *subject = strdup(buffer);

    // Answer OK
    if (send(*current_socket, "OK", 3, 0) == -1)
    {
        perror("send answer failed");
        return;
    }

    // Create File with Subject Name (.../spooldir/receiver + /subject.txt)
    FILE *sbjFilePtr;
    strcat(receiverDir, "/");
    strcat(receiverDir, subject);
    strcat(receiverDir, ".txt");
    sbjFilePtr = fopen(receiverDir, "w");

    // Write header with sender name
    fprintf(sbjFilePtr, "# Message by %s:\n\n", sender);

    // Get Message
    do
    {
        size = recv(*current_socket, buffer, BUF - 1, 0);
        if (!checkError(size))
        {
            break;
        }
        if (buffer[size - 2] == '\r' && buffer[size - 1] == '\n')
        {
            size -= 2;
        }
        else if (buffer[size - 1] == '\n')
        {
            --size;
        }
        buffer[size] = '\0';

        fprintf(sbjFilePtr, "%s\n", buffer);

    } while ((buffer[0] != '.') && (strlen(buffer) != 1));

    // Answer OK
    if (send(*current_socket, "OK", 3, 0) == -1)
    {
        perror("send answer failed");
        return;
    }

    // Danymische kopien freigeben
    // File ptr freigeben
    fclose(sbjFilePtr);
    free(sender);
    free(receiver);
    free(subject);
}

void mailerDel(int *current_socket, char *buffer, char *mailSpoolDirectory)
{
    // Answer OK
    if (send(*current_socket, "OK", 3, 0) == -1)
    {
        perror("send answer failed");
        return;
    }

    // Get User ID
    int size = recv(*current_socket, buffer, BUF - 1, 0);
    if (!checkError(size))
    {
        return;
    }
    if (buffer[size - 2] == '\r' && buffer[size - 1] == '\n')
    {
        size -= 2;
    }
    else if (buffer[size - 1] == '\n')
    {
        --size;
    }
    buffer[size] = '\0';
    char *username = strdup(buffer);

    DIR *directory;
    struct dirent *entry;
    directory = opendir(mailSpoolDirectory);

    if (directory == NULL)
    {
        perror("Error opening directory");
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
        return;
    }

    // If no inbox found return ERR else OK
    if (!foundUsrInbox)
    {
        if (send(*current_socket, "ERR", 3, 0) == -1)
        {
            perror("send answer failed");
            return;
        }
    }
    else
    {
        if (send(*current_socket, "OK", 3, 0) == -1)
        {
            perror("send answer failed");
            return;
        }

        // Get Message ID
        size = recv(*current_socket, buffer, BUF - 1, 0);
        if (!checkError(size))
        {
            return;
        }
        if (buffer[size - 2] == '\r' && buffer[size - 1] == '\n')
        {
            size -= 2;
        }
        else if (buffer[size - 1] == '\n')
        {
            --size;
        }
        buffer[size] = '\0';
        char *messageid = strdup(buffer);

        // Get & del file
        DIR *directory;
        struct dirent *entry;

        // contruct inbox path (.../mailSpoolDirectory/username/)
        char userFolder[PATH_MAX];
        strcpy(userFolder, mailSpoolDirectory);
        strcat(userFolder, "/");
        strcat(userFolder, username);
        strcat(userFolder, "/");

        // Open inbox folder
        directory = opendir(userFolder);
        if (directory == NULL)
        {
            perror("Error opening directory");
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
                if (currFile == atoi(messageid))
                {
                    strcat(userFolder, entry->d_name);
                    break;
                }
            }
        }
        if (remove(userFolder) == 0)
        {
            // Remove is successful
            if (send(*current_socket, "OK", 3, 0) == -1)
            {
                perror("send answer failed");
                return;
            }
        }
        else
        {
            if (send(*current_socket, "ERR", 3, 0) == -1)
            {
                perror("send answer failed");
                return;
            }
        }

        free(messageid);
    }

    free(username);
}

///////////////////////////////////////////////////////////////////////////////

int main(int argc, char *argv[])
{
    socklen_t addrlen;
    struct sockaddr_in address, cliaddress;
    int reuseValue = 1;

    ////////////////////////////////////////////////////////////////////////////u

    int PORT;
    char *mailSpoolDirectory;
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
        clientCommunication(&new_socket, mailSpoolDirectory); // returnValue can be ignored
        new_socket = -1;
    }

    // frees the descriptor
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

    return EXIT_SUCCESS;
}

void *clientCommunication(void *data, char *mailSpoolDirectory)
{
    char buffer[BUF];
    int size;
    int *current_socket = (int *)data;

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
        // printf("Size: %d", size);
        if (!checkError(size))
        {
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

        if (strcmp(buffer, "SEND") == 0)
        {
            printf("%s", "Entered SEND");
            mailerSend(current_socket, buffer, mailSpoolDirectory);
        }

        if (strcmp(buffer, "LIST") == 0)
        {
            printf("%s", "Entered LIST");
            mailerList(current_socket, buffer, mailSpoolDirectory);
        }

        if (strcmp(buffer, "READ") == 0)
        {
            printf("%s", "Entered READ");
            mailerRead(current_socket, buffer, mailSpoolDirectory);
        }

        if (strcmp(buffer, "DEL") == 0)
        {
            printf("%s", "Entered DEL");
            mailerDel(current_socket, buffer, mailSpoolDirectory);
        }

        // if (send(*current_socket, "OK", 3, 0) == -1)
        //{
        //     perror("send answer failed");
        //     return NULL;
        // }
    } while (strcmp(buffer, "QUIT") != 0 && !abortRequested);

    // closes/frees the descriptor if not already
    if (*current_socket != -1)
    {
        if (shutdown(*current_socket, SHUT_RDWR) == -1)
        {
            perror("shutdown new_socket");
        }
        if (close(*current_socket) == -1)
        {
            perror("close new_socket");
        }
        *current_socket = -1;
    }

    return NULL;
}

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
    }
    else
    {
        exit(sig);
    }
}
