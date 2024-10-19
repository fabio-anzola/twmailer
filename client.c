#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

///////////////////////////////////////////////////////////////////////////////

#define BUF 4096

char userInput(char buffer[BUF])
{
    printf(">> ");
    if (fgets(buffer, BUF, stdin) != NULL)
    {
        int size = strlen(buffer);
        // remove new-line signs from string at the end
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

int socketUserMsgSend(char buffer[BUF], int socket)
{
    userInput(buffer);
    int size = strlen(buffer);
    // printf("Sending: %s", buffer);
    return ((send(socket, buffer, size, 0)) == -1);
}

///////////////////////////////////////////////////////////////////////////////

int main(int argc, char *argv[])
{
    int create_socket;
    char buffer[BUF];
    struct sockaddr_in address;
    int size;
    int isQuit = 0;
    int PORT;

    ////////////////////////////////////////////////////////////////////////////

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

    size = recv(create_socket, buffer, BUF - 1, 0);
    if (checkError(size))
    {
        buffer[size] = '\0';  // NULL terminal received from server
        printf("%s", buffer); // print received message from server
    }

    do
    {

        //////////////////////////////////////////////////////////////////////

        // userInput(buffer);
        // size = strlen(buffer);
        // if ((send(create_socket, buffer, size, 0)) == -1)
        if (socketUserMsgSend(buffer, create_socket))
        {
            perror("send error");
            break;
        }

        //////////////////////////////////////////////////////////////////////

        if (strcmp(buffer, "SEND") == 0)
        { // if user has entered SEND
            // SEND
            int input_rows = 0;
            int msg_type_rows = 4;
            do
            {
                if (input_rows < msg_type_rows)
                {
                    size = recv(create_socket, buffer, BUF - 1, 0);
                    if (checkError(size))
                    {
                        buffer[size] = '\0';       // null terminate string
                        printf("<< %s\n", buffer); // OK or ERR expected here
                    }
                }

                // userInput(buffer);
                // size = strlen(buffer);
                // if ((send(create_socket, buffer, size, 0)) == -1)
                if (socketUserMsgSend(buffer, create_socket))
                {
                    perror("send error");
                    break; // break out of function wait for new user input
                }
                input_rows++;
                buffer[size] = '\0';
            } while ((buffer[0] != '.') && (strlen(buffer) != 1));

            size = recv(create_socket, buffer, BUF - 1, 0);
            if (checkError(size))
            {
                buffer[size] = '\0';       // null terminate string
                printf("<< %s\n", buffer); // OK or ERR expected here
            }
        }

        if (strcmp(buffer, "LIST") == 0)
        {
            // LIST

            size = recv(create_socket, buffer, BUF - 1, 0);
            if (checkError(size))
            {
                buffer[size] = '\0';
                printf("<< %s\n", buffer); // Ok or ERR
            }

            // userInput(buffer);
            // if ((send(create_socket, buffer, strlen(buffer), 0)) == -1)
            if (socketUserMsgSend(buffer, create_socket))
            {
                perror("send error");
                break;
            }

            size = recv(create_socket, buffer, BUF - 1, 0);
            if (checkError(size))
            {
                buffer[size] = '\0';
                printf("<< %s\n", buffer); // Msg Nrs & Subjects
            }
        }

        if (strcmp(buffer, "READ") == 0)
        {
            // READ
            size = recv(create_socket, buffer, BUF - 1, 0);
            if (checkError(size))
            {
                buffer[size] = '\0';
                printf("<< %s\n", buffer); // Ok or ERR
            }

            // userInput(buffer);
            // if ((send(create_socket, buffer, strlen(buffer), 0)) == -1)
            if (socketUserMsgSend(buffer, create_socket))
            {
                perror("send error");
                break;
            }

            size = recv(create_socket, buffer, BUF - 1, 0);
            if (checkError(size))
            {
                buffer[size] = '\0';
                printf("<< %s\n", buffer); // Ok or ERR
            }

            // userInput(buffer);
            // if ((send(create_socket, buffer, strlen(buffer), 0)) == -1)
            if (socketUserMsgSend(buffer, create_socket))
            {
                perror("send error");
                break;
            }

            size = recv(create_socket, buffer, BUF - 1, 0);
            if (checkError(size))
            {
                buffer[size] = '\0';
                printf("<< %s\n", buffer); // Ok or ERR
            }
        }

        if (strcmp(buffer, "DEL") == 0)
        {
            // DEL
            size = recv(create_socket, buffer, BUF - 1, 0);
            if (checkError(size))
            {
                buffer[size] = '\0';
                printf("<< %s\n", buffer); // Ok or ERR
            }

            // userInput(buffer);
            // if ((send(create_socket, buffer, strlen(buffer), 0)) == -1)
            if (socketUserMsgSend(buffer, create_socket))
            {
                perror("send error");
                break;
            }

            size = recv(create_socket, buffer, BUF - 1, 0);
            if (checkError(size))
            {
                buffer[size] = '\0';
                printf("<< %s\n", buffer); // Ok or ERR
            }

            // userInput(buffer);
            // if ((send(create_socket, buffer, strlen(buffer), 0)) == -1)
            if (socketUserMsgSend(buffer, create_socket))
            {
                perror("send error");
                break;
            }

            size = recv(create_socket, buffer, BUF - 1, 0);
            if (checkError(size))
            {
                buffer[size] = '\0';
                printf("<< %s\n", buffer); // Ok or ERR
            }
        }

        if (strcmp(buffer, "QUIT") == 0)
        {
            isQuit = 1;
        }
    } while (!isQuit);

    ////////////////////////////////////////////////////////////////////////////
    // CLOSES THE DESCRIPTOR
    if (create_socket != -1)
    {
        if (shutdown(create_socket, SHUT_RDWR) == -1)
        {
            // invalid in case the server is gone already
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