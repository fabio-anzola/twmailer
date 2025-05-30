#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

///////////////////////////////////////////////////////////////////////////////

// Buffer size
#define BUF 4096

// Function to process user input and clean from new line
char userInput(char buffer[BUF])
{
    printf(">> ");
    // get line from stdin
    if (fgets(buffer, BUF, stdin) != NULL)
    {
        int size = strlen(buffer);
        // remove rn sign and add n for nl
        if (buffer[size - 2] == '\r' && buffer[size - 1] == '\n')
        {
            size -= 2;
            buffer[size] = 0;
        }
        else if (buffer[size - 1] == '\n')
        {
            --size;
            buffer[size] = 0;
        }
    }
    return *buffer;
}

// function to check socket recv for error based on size
int checkError(int size)
{
    // error if size is set to negative
    if (size == -1)
    {
        perror("recv error");
        return 0;
    }
    // if size not negative but zero then no connection anymore
    else if (size == 0)
    {
        printf("Server closed remote socket\n"); // ignore error
        return 0;
    }
    // no issue
    return 1;
}

// function that calls for user input and sends it to server
int socketUserMsgSend(char buffer[BUF], int socket)
{
    // get sanitized user in
    userInput(buffer);
    int size = strlen(buffer);
    // send user in via socket
    // if input is more than zeor (not only "enter") send to server
    if (size != 0) {
        // return 0 if no issue or 1 for error
        return ((send(socket, buffer, size, 0)) == -1);
    }
    // if nothing sent to server return error code 0
    return 0;
}

// function to handle mailer send
void mailerSend(int create_socket, char *buffer)
{
    // init size
    int size = 0;
    // current input nr
    int input_rows = 0;
    // input needed for protocol
    int msg_type_rows = 3;
    do
    {
        // practically expect 3 responses from server
        // 1 - OK for intitial command
        // 2 - OK for receiver name
        // 3 - OK for subject name
        if (input_rows < msg_type_rows)
        {
            // wait for server repsonse (3) times
            size = recv(create_socket, buffer, BUF - 1, 0);
            if (checkError(size))
            {
                buffer[size] = '\0';       // null terminate string
                printf("<< %s\n", buffer); // OK or ERR expected here
                if (strcmp(buffer, "ERR") == 0)
                {
                    return;
                }
            }
        }

        // After each server respone send answer -> last interation is message!
        if (socketUserMsgSend(buffer, create_socket))
        {
            perror("send error");
            break; // break out of function wait for new user input
        }
        input_rows++;
        buffer[size] = '\0';
    } while (!((buffer[0] == '.') && (strlen(buffer) == 1)));

    // Get server answer to message 
    size = recv(create_socket, buffer, BUF - 1, 0);
    if (checkError(size))
    {
        buffer[size] = '\0';       // null terminate string
        printf("<< %s\n", buffer); // OK or ERR expected here
        if (strcmp(buffer, "ERR") == 0)
        {
            return;
        }
    }
    return;
}

// function to hande mailer list
void mailerList(int create_socket, char *buffer)
{
    // init size
    int size = 0;

    // receive answer from server with subject names
    size = recv(create_socket, buffer, BUF - 1, 0);
    if (checkError(size))
    {
        buffer[size] = '\0';
        printf("<< %s\n", buffer); // Msg Nrs & Subjects // if not found will only return 0 not err
    }

    return;
}

// function to handel mailer read
void mailerRead(int create_socket, char *buffer)
{
    // init size
    int size = 0;

    // Get answer from server - OK
    size = recv(create_socket, buffer, BUF - 1, 0);
    if (checkError(size))
    {
        buffer[size] = '\0';
        printf("<< %s\n", buffer); // Ok or ERR
        if (strcmp(buffer, "ERR") == 0)
        {
            return;
        }
    }

    // Write msg to server (message nr)
    if (socketUserMsgSend(buffer, create_socket))
    {
        perror("send error");
        return;
    }

    // Get msg from server - OK & Mesage content
    size = recv(create_socket, buffer, BUF - 1, 0);
    if (checkError(size))
    {
        buffer[size] = '\0';
        printf("<< %s\n", buffer); // Ok & msg content or ERR
        if (strcmp(buffer, "ERR") == 0)
        {
            return;
        }
    }

    return;
}

// function to handel mailer delete
void mailerDel(int create_socket, char *buffer)
{
    // init size
    int size = 0;

    // get answer from server - OK
    size = recv(create_socket, buffer, BUF - 1, 0);
    if (checkError(size))
    {
        buffer[size] = '\0';
        printf("<< %s\n", buffer); // Ok or ERR
        if (strcmp(buffer, "ERR") == 0)
        {
            return;
        }
    }

    // send msg to server - msg nr
    if (socketUserMsgSend(buffer, create_socket))
    {
        perror("send error");
        return;
    }

    // get answer from server - OK
    size = recv(create_socket, buffer, BUF - 1, 0);
    if (checkError(size))
    {
        buffer[size] = '\0';
        printf("<< %s\n", buffer); // Ok or ERR
        if (strcmp(buffer, "ERR") == 0)
        {
            return;
        }
    }

    return;
}

// function to handel mailer login
void mailerLogin(int create_socket, char *buffer)
{
    // init size
    int size = 0;

    // get answer from server - OK
    size = recv(create_socket, buffer, BUF - 1, 0);
    if (checkError(size))
    {
        buffer[size] = '\0';
        printf("<< %s\n", buffer); // Ok or ERR
        if (strcmp(buffer, "ERR") == 0)
        {
            return;
        }
    }

    // send msg to server - username
    if (socketUserMsgSend(buffer, create_socket))
    {
        perror("send error");
        return;
    }

    // get answer from server - OK
    size = recv(create_socket, buffer, BUF - 1, 0);
    if (checkError(size))
    {
        buffer[size] = '\0';
        printf("<< %s\n", buffer); // Ok or ERR
        if (strcmp(buffer, "ERR") == 0)
        {
            return;
        }
    }

    // send msg to server - password
    char passBuf[256];
    strncpy(passBuf, getpass("Enter password: "), sizeof(passBuf) - 1);
    passBuf[sizeof(passBuf) - 1] = '\0';
    size = strlen(passBuf);

    // send user passwd via socket
    if (((send(create_socket, passBuf, size, 0)) == -1))
    {
        perror("send error");
        return;
    }

    // get answer from server - OK
    size = recv(create_socket, buffer, BUF - 1, 0);
    if (checkError(size))
    {
        buffer[size] = '\0';
        printf("<< %s\n", buffer); // Ok or ERR
        if (strcmp(buffer, "ERR") == 0)
        {
            return;
        }
    }

    return;
}

///////////////////////////////////////////////////////////////////////////////

int main(int argc, char *argv[])
{
    // var for initial socket
    int create_socket;
    // buffer array with size BUF
    char buffer[BUF];
    // Address to connect to
    struct sockaddr_in address;
    // Size in for recieving
    int size;
    // Check if quit is entered
    int isQuit = 0;
    // Port to connect to
    int PORT;

    ////////////////////////////////////////////////////////////////////////////

    // Get args from terminal call
    if (argc != 3)
    {
        printf("Usage: %s <ip> <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    else
    {
        PORT = atoi(argv[2]); // ascii to int
    }

    ////////////////////////////////////////////////////////////////////////////
    // CREATE A SOCKET
    // https://man7.org/linux/man-pages/man2/socket.2.html
    // https://man7.org/linux/man-pages/man7/ip.7.html
    // https://man7.org/linux/man-pages/man7/tcp.7.html
    // IPv4, TCP (connection oriented), IP (same as server)
    if ((create_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("Socket error");
        return EXIT_FAILURE;
    }

    ////////////////////////////////////////////////////////////////////////////
    // INIT ADDRESS
    // Attention: network byte order => big endian
    memset(&address, 0, sizeof(address)); // init storage with 0
    address.sin_family = AF_INET;         // IPv4
    // https://man7.org/linux/man-pages/man3/htons.3.html
    address.sin_port = htons(PORT);
    // https://man7.org/linux/man-pages/man3/inet_aton.3.html
    if (argc < 2)
    {
        inet_aton("127.0.0.1", &address.sin_addr);
    }
    else
    {
        inet_aton(argv[1], &address.sin_addr);
    }

    ////////////////////////////////////////////////////////////////////////////
    // CREATE A CONNECTION
    // https://man7.org/linux/man-pages/man2/connect.2.html
    if (connect(create_socket,
                (struct sockaddr *)&address,
                sizeof(address)) == -1)
    {
        // https://man7.org/linux/man-pages/man3/perror.3.html
        perror("Connect error - no server available");
        return EXIT_FAILURE;
    }

    // ignore return value of printf
    printf("Connection with server (%s) established\n",
           inet_ntoa(address.sin_addr));
    fflush(stdout);

    ////////////////////////////////////////////////////////////////////////////
    // RECEIVE DATA
    // https://man7.org/linux/man-pages/man2/recv.2.html

    // Receive initial data (welcome msg)
    size = recv(create_socket, buffer, BUF - 1, 0);
    if (checkError(size))
    {
        buffer[size] = '\0';  // NULL terminal received from server
        printf("%s", buffer); // print received message from server
    }

    do
    {

        //////////////////////////////////////////////////////////////////////

        // Send command to server
        if (socketUserMsgSend(buffer, create_socket))
        {
            perror("send error");
            break;
        }

        // If user just pressed enter with no message then continue
        if (strlen(buffer) == 0) {
            continue;
        }

        //////////////////////////////////////////////////////////////////////
        // Check which command has been sent

        if (strcmp(buffer, "LOGIN") == 0)
        { // if user has entered LOGIN
            // LOGIN

            mailerLogin(create_socket, buffer);
        }
        else if (strcmp(buffer, "SEND") == 0)
        { // if user has entered SEND
            // SEND

            mailerSend(create_socket, buffer);
        }
        else if (strcmp(buffer, "LIST") == 0)
        {
            // LIST

            mailerList(create_socket, buffer);
        }
        else if (strcmp(buffer, "READ") == 0)
        {
            // READ

            mailerRead(create_socket, buffer);
        }
        else if (strcmp(buffer, "DEL") == 0)
        {
            // DEL

            mailerDel(create_socket, buffer);
        }
        // If entered string is QUIT then quit and close descriptors
        else if (strcmp(buffer, "QUIT") == 0)
        {
            isQuit = 1;
        }
        else
        {
            // Receive err for unrecognised command
            size = recv(create_socket, buffer, BUF - 1, 0);
            if (checkError(size))
            {
                buffer[size] = '\0';  // NULL terminal received from server
                printf("<< %s\n", buffer); // Probably ERR
            }
        }
    } while (!isQuit);

    ////////////////////////////////////////////////////////////////////////////
    // CLOSES THE DESCRIPTOR
    if (create_socket != -1)
    {
        if (shutdown(create_socket, SHUT_RDWR) == -1)
        {
            // could not shoutdown - server down
            perror("error on shutdown socket");
        }
        if (close(create_socket) == -1)
        {
            // could not close socket
            perror("error on close socket");
        }
        create_socket = -1;
    }

    return EXIT_SUCCESS;
}