#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <regex.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>

#define NUMCONS     10      // how many pending connections queue will hold
#define SEGSIZE_est 1500    // size of response segments
//#define GETREQSIZE  1500

/** enum STATUS:
 *  contains status messages for various situations:
 *
 *  BAD_MSG         A BAD word was found in either content or URL
 *  CONTENT_SEARCH  The present response has text and will be searched for bad words
 *  ERROR           NOT USED
 *  DEFAULT         Indicates that a message is ok and ready to send
 */
typedef enum {
    BAD_MSG,
    CONTENT_SEARCH,
    ERROR,
    DEFAULT
} STATUS;

char *REDIRECT_MSG_URL      = "HTTP/1.1 302 Found\r\nLocation: http://www.ida.liu.se/~TDTS04/labs/2011/ass2/error1.html\r\nContent-Length: 173\r\nConnection: close\r\nContent-Type: text/html; charset=iso-8859-1\r\n\r\n<!DOCTYPE HTML PUBLIC '-//IETF//DTD HTML 2.0//EN'>\n<html><head>\n<title>URL NOT approved!</title>\n</head><body>\n<h1>The URL you have requested is VERY BAD.</h1>\n</body></html>\n";

char *REDIRECT_MSG_CONTENT  = "HTTP/1.1 302 Found\r\nLocation: http://www.ida.liu.se/~TDTS04/labs/2011/ass2/error2.html\r\nContent-Length: 188\r\nConnection: close\r\nContent-Type: text/html; charset=iso-8859-1\r\n\r\n<!DOCTYPE HTML PUBLIC '-//IETF//DTD HTML 2.0//EN'>\n<html><head>\n<title>Content NOT approved!</title>\n</head><body>\n<h1>You have requested a site with VERY BAD content.</h1>\n</body></html>\n";

const int REDIRECT_URL_SIZE = 350;

const int REDIRECT_CONTENT_SIZE = 363;

char *not_allowed = "[N|n]orrk.*ping|[S|s]ponge[B|b]ob|([B|b]ritney.[S|s]pears)|([P|p]aris.[H|h]ilton)";

int receive_msg(int sock, int dir, char **buf, STATUS *status);

void sock_process(int sock_id);

STATUS process_msg(char *buf, char **fixed_req, int *msg_size, int connection, int dir, STATUS status);

int get_server_URL(char **addr, char *buf, int *buf_size);

int server_connect(char **URL, int *URL_SIZE);

void request_remake(char **req, int *req_size, char *URL, int URL_size);

/** struct segNode
 *  This structure is used for a singly linked list
 *  A node will hold a http message segment and its size
 *
 */
struct segNode {
    char buf[SEGSIZE_est];
    int SEGSIZE;
    struct segNode *next;
};

/** sigchld_handler()
 *  used to kill Zombie processes
 *  
 *
 * @param s
 */
void sigchld_handler(int s)
{
    // waitpid() might overwrite errno, so we save and restore it:
    int saved_errno = errno;

    while(waitpid(-1, NULL, WNOHANG) > 0);

    errno = saved_errno;
}

int main(void) {

    /** KILL ZOMBIE PROCESSES */
    struct sigaction sa;
    sa.sa_handler = sigchld_handler; // reap all dead processes
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }


    int status = 1;
    struct sockaddr_storage their_addr;
    socklen_t addr_size;
    struct addrinfo hints, *result;
    int sockfd, new_fd;


    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char *node = "127.0.0.1";
    char myPort[5];

    printf("\nWelcome to Net Ninny proxy.\n");

    // user enters proxy port
    while (status) {
        printf("\nPlease enter proxy port below:\n");
        fgets(myPort, sizeof(myPort), stdin);

        if ((status = getaddrinfo(node, myPort, &hints, &result)) != 0) {
            fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        } else
            printf("Proxy port is now set to %s.\n", myPort);
    }
    // servinfo now points to a linked list of 1 or more addrinfos

    // make a socket, bind it, and listen to it
    sockfd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    bind(sockfd, result->ai_addr, result->ai_addrlen);
    freeaddrinfo(result);
    listen(sockfd, NUMCONS);

    addr_size = sizeof(their_addr);

    while (1) {
        new_fd = accept(sockfd, (struct sockaddr *) &their_addr, &addr_size);

        pid_t sock_handler;

        sock_handler = fork();
        if (!sock_handler) {

            printf("\nNew pid!!!!\n");

            sock_process(new_fd);

            printf("\nSITE IS FINISHED!!!\n");

            close(new_fd);

            exit(0);
        }
    }
}


/**I/O Handler
 * Handles GET Requests and Responses
 *
 * @param sock_id
 */
void sock_process(int sock_id) {
    int servSock, sent_bytes, msgSize;
    char *message;
    STATUS status;

    // IN_OUT = 0: Proxy is processing a message from client
    // IN_OUT = 1: ---------------- | | ------------- server
    int IN_OUT;

    // Main loop
    while(1) {
        printf("SOCK ID: %i\n", sock_id);

        char *buf;

        // Receive request from browser
        IN_OUT = 0;
        msgSize = receive_msg(sock_id, IN_OUT, &buf, &status);

        printf("SOCKET: %i GET request Message size: %i\n\n%s", sock_id, msgSize, buf);

        // Terminate process if browser close connection
        if(msgSize == 0 || msgSize == -1) {
            printf("\n\nBrowser closed connection on socket: %i\n\n\n", sock_id);
            free(buf);

            return;
        }

        /*  Check if requested URL contains a "not allowed" word
            Change to Connection: close if need be
            URL REDIRECT if URL is bad and continue to loop end     */
        status = process_msg(buf, &message, &msgSize, 0, IN_OUT, status);

        // Content in "buf" no longer needed. The data now lies in "request"
        free(buf);

        // String to store requested URL
        char *server_URL;

        // if no BAD URL was found, communicate with requested server
        if(status == DEFAULT) {

            /** get requested server URL                                    */
            int URL_SIZE = get_server_URL(&server_URL, message, &msgSize);

            printf("%s\n", server_URL);

            if (URL_SIZE == -1)
                printf("URL could not be found. Very strange!\n");

            /** Connect to requested URL                                */
            if ((servSock = server_connect(&server_URL, &URL_SIZE)) == -1) {
                printf("getaddrinfo ERROR to %s\n", server_URL);

                status = ERROR;
                //SEND ERROR RESPONSE

            } else if (servSock == -2) {
                printf("Connection ERROR\n");
            }

            printf("Server socket ID: %i, URL: %s\n", servSock, server_URL);


            // Send request to server
            sent_bytes = send(servSock, message, msgSize, 0);
            printf("%i\n", sent_bytes);

            free(message);
            // We might need the GET Request
            //free(message);


            // Receive response from server
            IN_OUT = 1;
            msgSize = receive_msg(servSock, IN_OUT, &buf, &status);

            // We don't need server socket (servSock) anymore since the response is collected
            close(servSock);


            printf("RESPONSE SIZE from URL: %s, %i bytes\n\n", server_URL, msgSize);
            printf("UNFIXED Response:\n%s\n", buf);


            /*  Check if requested URL contains a "not allowed" word
                Change to Connection: keep-alive if need be
                CONTENT REDIRECT if CONTENT is bad and continue to loop end     */
            status = process_msg(buf, &message, &msgSize, 1, IN_OUT, status);

            // buf is no longer needed. Now using "response" instead
            free(buf);


#if 0
            if(status == CODE_30X_RESP) {
                free(server_URL);

                server_URL = (char *) malloc(rspSize);
                memcpy(server_URL, response_or_URL, rspSize);

                request_remake(&request, &reqSize, server_URL, rspSize);

                IN_OUT = 0;
                status = process_msg(buf, &request, &reqSize, 0, IN_OUT);
            }
#endif


        }

        // Send response to client (browser)
        sent_bytes = send(sock_id, message, msgSize, 0);


        // We don't need the response or request anymore
        free(message);

        printf("\nSent %i bytes to broauser!\n\n", sent_bytes);
    }
    //close(sock_id);
    //close(servSock);

    // when we don't need result(X) anymore
    //freeaddrinfo(result);
}

/** Receive whatever message. Larger messages will be collected with many segments
 *
 * @param sock
 * @param dir
 * @param buf
 * @return
 */
int receive_msg(int sock, int dir, char **buf, STATUS *status)
{
    int full_size = 0, offset = 0, regresp;
    struct segNode *List = (struct segNode *) malloc(sizeof(struct segNode));
    struct segNode *deleteNode;
    List->next = NULL;
    regex_t find[1];
    regmatch_t match[1];

    printf("IN DA RECV FUNC\n");

    struct segNode *iter = List;
    while((iter->SEGSIZE = recv(sock, iter->buf, SEGSIZE_est, 0)) > 0) {
        full_size += iter->SEGSIZE;

        printf("IN segment loop\n");

        if(dir == 0) {
            regcomp(find, "\r\n\r\n", REG_ICASE | REG_EXTENDED);
            if(!regexec(find, iter->buf, 1, match, 0)) {
                break;
            }
        }
        struct segNode *newNode = (struct segNode *) malloc(sizeof(struct segNode));
        newNode->next = NULL;
        iter->next = newNode;
        iter = iter->next;
    }

    if(iter->SEGSIZE < 0) {
        iter = List;
        while(iter != NULL) {
            deleteNode = iter;
            iter = iter->next;
            free(deleteNode);
        }
        return -1;
    }

    *buf = (char *) malloc(full_size);

    iter = List;

    char *temp = *buf;

    // Load all segments into "buf"
    while(iter != NULL) {

        memcpy(&temp[offset], iter->buf, iter->SEGSIZE);
        offset += iter->SEGSIZE;
        deleteNode = iter;
        iter = iter->next;
        free(deleteNode);
    }

    printf("RAW DATA:\n%s\n\n", *buf);

    // If buf contains a Redirect response, eventually fix weird "Location:" line
    if(dir == 1) {
        int start_offset, end_offset;
        //char tmp[full_size];

        regcomp(find, "Location:.http://", REG_ICASE | REG_EXTENDED);

        if(!regexec(find, *buf, 1, match, 0)) {

            start_offset = match->rm_eo;

            regcomp(find, "\r\n", REG_ICASE | REG_EXTENDED);

            if (!regexec(find, *buf + start_offset, 1, match, 0)) {

                end_offset = start_offset + match->rm_so;

                regcomp(find, "http://", REG_ICASE | REG_EXTENDED);

                if(!regexec(find, *buf + start_offset, 1, match, 0)) {

                    int new_end = start_offset + match->rm_so;

                    if((new_end > start_offset) && (new_end < end_offset)) {

                        memmove(*buf + new_end, *buf + end_offset, full_size - end_offset);

                        regcomp(find, "\r\n\r\n", REG_ICASE | REG_EXTENDED);

                        if(!regexec(find, *buf + start_offset, 1, match, 0)) {
                            char *temp = *buf;
                            temp[match->rm_eo] = '\0';
                        }

                        //memmove(tmp, *buf, full_size);
                        //free(*buf);
                        //*buf = (char *) malloc(full_size - (end_offset - new_end));

                        //char *tmp2 = *buf;

                        //memmove(*buf, tmp, new_end);
                        //tmp2[new_end] = '/';
                        //memmove(*buf + new_end, tmp + end_offset, full_size - end_offset);

                        //full_size -= (end_offset - new_end);
                        //full_size += 1;
                    }
                }
            }
        } else {
            regcomp(find, "\r\n\r\n", REG_ICASE | REG_EXTENDED);

            if(!regexec(find, *buf, 1, match, 0)) {
                int temp_size = match->rm_eo;
                char tmp[temp_size + 1];

                memcpy(tmp, *buf, temp_size);

                tmp[temp_size] = '\0';
                printf("\nInnan REGCOMP\n\n");
                regcomp(find, "(([C|c]ontent.[T|t]ype:.).*(text).*(\r\n))", REG_ICASE | REG_EXTENDED);
                printf("\nInnan REGEXEC\n\n");
                if(!regexec(find, tmp, 0, NULL, 0)) {
                    printf("\nCONTENT_SEARCH Active\n\n");
                    status = CONTENT_SEARCH;
                }
            }
        }
    }

    return full_size;
}



/**
 * Checks if a string contain any BAD words.
 * dir = 0 handles "buf" like a request
 * dir = 1 handles "buf" like a response
 * Eventually changes connection type:
 * Connection = 0 will change to close, = 1 will change to keep-alive.
 * Returns STATUS = DEFAULT if the message is ok.
 * Returns STATUS = BAD_MSG if it was a bad msg.
 *
 * @param buf
 * @param fixed_msg
 * @param msg_size
 * @param connection
 * @param dir
 * @param status
 * @return
 */

STATUS process_msg(char *buf, char **fixed_msg, int *msg_size, int connection, int dir, STATUS status)
{
    int j, k;

    char *temp1;
    char *temp2;
    int start_offset, end_offset;

    regex_t find[1];
    regmatch_t match[1];

    int regresp;


    if (dir == 0) {
        // Check for bad URL
        // Return STATUS = BAD_MSG if found
        regcomp(find, not_allowed, REG_ICASE|REG_EXTENDED);

        if(!regexec(find, buf, 0, NULL, 0)) {

            *msg_size = REDIRECT_URL_SIZE;

            *fixed_msg = (char *) malloc(*msg_size);

            memmove(*fixed_msg, REDIRECT_MSG_URL, *msg_size);

            return BAD_MSG;
        }
    // Check for bad content only if the Content-Type is text/html and dir = 1
    // Return status = BAD_MSG if bad word found
    } else if(dir == 1 && status == CONTENT_SEARCH) {

        regcomp(find, not_allowed, REG_ICASE|REG_EXTENDED);

        if(!regexec(find, buf, 0, NULL, 0)) {

            *msg_size = REDIRECT_CONTENT_SIZE;

            *fixed_msg = (char *) malloc(*msg_size);

            memmove(*fixed_msg, REDIRECT_MSG_CONTENT, *msg_size);

            return BAD_MSG;
        }
    }


    // Search for Connection: keep-alive in message. If found, change to close
    if(connection == 0) {
        regcomp(find, "[K|k]eep.[A|a]live", REG_ICASE|REG_EXTENDED);
        regresp = regexec(find, buf, 1, match, 0);

        if (regresp == 0) {
            *fixed_msg = (char *) malloc(*msg_size - 5);
            temp1 = *fixed_msg;
            temp2 = buf;
            //*fixed_msg[msg_size - 5] = '\0';

            k = match->rm_so;

            memmove(*fixed_msg, buf, k);
            memmove(*fixed_msg + k, "close", 5);

            k += 5;

            memmove(*fixed_msg + k, buf + match->rm_eo, *msg_size - match->rm_eo);
            *msg_size -= 5;

        } else {
            *fixed_msg = (char *) malloc(*msg_size);
            memmove(*fixed_msg, buf, *msg_size);
        }
    }
    // Search for "Connection: close" in message. If found, change to "keep-alive"
    else if(connection == 1) {
        regcomp(find, "Connection..[C|c]lose", REG_ICASE|REG_EXTENDED);

        regresp = regexec(find, buf, 1, match, 0);

        if (regresp == 0) {
            printf("\nClose hittades!\n\n");
            k = match->rm_eo - 5;

            *fixed_msg = (char *) malloc(*msg_size + 5);
            temp1 = *fixed_msg;
            temp2 = buf;
            //*fixed_msg[msg_size + 5] = '\0';
            memmove(temp1, temp2, k);

            memmove(temp1 + k, "keep-alive", 10);

            memmove(temp1 + k + 10, temp2 + k + 5, *msg_size - k - 5);

            *msg_size += 5;
        } else {
            *fixed_msg = (char *) malloc(*msg_size);
            temp1 = *fixed_msg;
            temp2 = buf;
            memmove(temp1, temp2, *msg_size);
        }
    }


    printf("%s\n", *fixed_msg);

    // The message was ok! Return STATUS = DEFAULT
    return DEFAULT;
}

/** Finds the URL for a HTTP GET request and passes it through "**addr"
 *
 * @param addr
 * @param buf
 * @param buf_size
 * @return
 */
int get_server_URL(char **addr, char *buf, int *buf_size)
{
    regex_t find[1];
    regmatch_t match[1];
    int regresp;
    int start_offset, end_offset;

    char *tmp;

    regcomp(find, "Host:.", REG_ICASE|REG_EXTENDED);
    regresp = regexec(find, buf, 1, match, 0);

    if(regresp == 0) {
        start_offset = match->rm_eo;

        printf("START OFFSET: %i\n", start_offset);

        //ifall URL är fucked up kan något behövas här!

        regcomp(find, "\r\n", REG_ICASE|REG_EXTENDED);
        regresp = regexec(find, buf + start_offset, 1, match, 0);

        if(regresp == 0) {
            end_offset = start_offset + match->rm_so;

            printf("END OFFSET: %i\n", end_offset);

        } else { return -1; }
    } else { return -1; }

    // Allocate precise memory for URL.
    *addr = (char *) malloc(end_offset - start_offset + 1);

    // Fetch the URL into *addr
    memmove(*addr, buf + start_offset, end_offset - start_offset);

    // Add NULL termination at the end of *addr
    tmp = *addr;
    tmp[end_offset - start_offset] = '\0';

    printf("num chars: %i\n", end_offset - start_offset);
    printf("SERVER URL: %s\n", *addr);

    // Return the size of the URL
    return (end_offset - start_offset);
}


/**Establishes connection to requested server:
 * Performes getaddrinfo
 * Creating new socket to requested URL
 * Connecting to requested URL
 *
 * @param URL
 * @param URL_SIZE
 * @return
 */
int server_connect(char **URL, int *URL_SIZE)
{
    struct addrinfo *pServInfo, *pIt, hints;
    int server_socket;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    //hints.ai_flags = AI_PASSIVE;

    int status;

    if((status = getaddrinfo(*URL, "http", &hints, &pServInfo)) != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));

        // Retry getaddrinfo() if URL does not start with "www."

        char *tmp_r = *URL;

        if(!(tmp_r[0] == 'w' && tmp_r[1] == 'w' && tmp_r[2] == 'w' && tmp_r[3] == '.')) {
            int size = *URL_SIZE;
            char tmp[size + 4];
            memmove(tmp + 4, *URL, *URL_SIZE);
            free(*URL);
            *URL = (char *) malloc(*URL_SIZE + 4);

            memmove(*URL, "www.", 4);
            memmove(*URL + 4, tmp + 4, *URL_SIZE);

            if((status = getaddrinfo(*URL, "http", &hints, &pServInfo)) != 0) {
                fprintf(stderr, "getaddrinfo error (%s): %s\n", *URL, gai_strerror(status));
                return -1;
            }
        } else {
            return -1;
        }
    }

    // Try to create socket to server, and then connect to it
    for(pIt = pServInfo; pIt != NULL; pIt->ai_next) {
        // create socket to requested server
        if ((server_socket = socket(pServInfo->ai_family, pServInfo->ai_socktype, pServInfo->ai_protocol)) == -1) {
            printf("Error creating socket to %s\n", *URL);

            continue;
        }

        // Establish connection to server, if no error, send request packet
        if (connect(server_socket, pServInfo->ai_addr, pServInfo->ai_addrlen) == -1) {
            printf("Connection to %s failed.\n", *URL);

            close(server_socket);

            continue;
        }
        break;
    }

    if(pIt == NULL)
        return -2;

    // We don't need "pServInfo anymore
    freeaddrinfo(pServInfo);

    // Return socket file descriptor
    return server_socket;
}
