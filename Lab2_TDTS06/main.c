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

typedef enum {
    BAD_WORD,
    CODE_30X_RESP,
    DEFAULT
} STATUS;

char *REDIRECT_MSG_URL      = "HTTP/1.1 302 Found\r\nLocation: http://www.ida.liu.se/~TDTS04/labs/2011/ass2/error1.html\r\nContent-Length: 173\r\nConnection: close\r\nContent-Type: text/html; charset=iso-8859-1\r\n\r\n<!DOCTYPE HTML PUBLIC '-//IETF//DTD HTML 2.0//EN'>\n<html><head>\n<title>URL NOT approved!</title>\n</head><body>\n<h1>The URL you have requested is VERY BAD.</h1>\n</body></html>\n";

char *REDIRECT_MSG_CONTENT  = "HTTP/1.1 302 Found\r\nLocation: http://www.ida.liu.se/~TDTS04/labs/2011/ass2/error2.html\r\nContent-Length: 188\r\nConnection: close\r\nContent-Type: text/html; charset=iso-8859-1\r\n\r\n<!DOCTYPE HTML PUBLIC '-//IETF//DTD HTML 2.0//EN'>\n<html><head>\n<title>Content NOT approved!</title>\n</head><body>\n<h1>You have requested a site with VERY BAD content.</h1>\n</body></html>\n";

const int REDIRECT_URL_SIZE = 350;

const int REDIRECT_CONTENT_SIZE = 363;

char *not_allowed = "[N|n]orrk.*ping|[S|s]ponge[B|b]ob|(Britney Spears)|(Paris Hilton)";

int receive_msg(int sock, int dir, char **buf);

void sock_process(int sock_id);

STATUS process_msg(char *buf, char **fixed_req, int *msg_size, int connection, int dir);

int get_server_URL(char **addr, char *buf, int *buf_size);

int server_connect(char **URL, int *URL_SIZE);

void request_remake(char **req, int *req_size, char *URL, int URL_size);

// Response segment list structure
struct segNode {
    char buf[SEGSIZE_est];
    int SEGSIZE;
    struct segNode *next;
};

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
    struct addrinfo hints, hints1, *result;
    int sockfd, new_fd, servSock;


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
    //printf("\n%s", result->ai_addr->sa_data);
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
    /** Används aldrig??? */
    //close(sockfd);
}

    //printf("%d\n", new_fd);

    // buf: dummy
    //get_buf_t buf = (get_buf_t) malloc(sizeof(get_buf_t));

//typedef char* not_allowed[4] = {"SpongeBob", "Britney Spears", "Paris Hilton", "Norrk.ping"};

void sock_process(int sock_id) {
    int servSock, sent_bytes;
    char *request, *response_or_URL;
    STATUS status;

    // IN_OUT = 0: Proxy is processing a message from client
    // IN_OUT = 1: ---------------- | | ------------- server
    int IN_OUT;

    //char *node = "127.0.0.1";

    //getaddrinfo(node, port, &hints, &result);

    while(1) {
        printf("SOCK ID: %i\n", sock_id);

        char *buf;

        int reqSize, rspSize;

        int moved_flag = 0;

        IN_OUT = 0;
        reqSize = receive_msg(sock_id, IN_OUT, &buf, &moved_flag);

        // If URL has a BAD word, redirect accordingly
#if 0
        if(msgSize == -2) {
            send(sock_id, REDIRECT_MSG_URL, sizeof(REDIRECT_MSG_URL), 0);
            free(buf);
            free(request);
            continue;
        }
#endif
        //msgSize = recv(sock_id, buf, sizeof(buf), 0);

        printf("SOCKET: %i GET request Message size: %i\n\n%s", sock_id, reqSize, buf);

        if(reqSize == 0 || reqSize == -1) {
            printf("\n\n\nYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAS\n\n\n");
            free(buf);

            return;
        }

        /** Check if requested URL contains a "not allowed" word    */
        /** Change to Connection: close if need be                  */
        /** URL REDIRECT if URL is bad and continue to loop end     */
        status = process_msg(buf, &request, &reqSize, 0, IN_OUT);



        /*amount = send(sock_id, REDIRECT_MSG_URL, sizeof(REDIRECT_MSG_URL), 0);
            free(buf);
            free(request);
            continue;
        */

        free(buf);

        char *server_URL;

        // if no BAD URL was found, communicate with requested server
        if(status == DEFAULT) {

            /** get requested server URL                                    */
            int URL_SIZE = get_server_URL(&server_URL, request, &reqSize);

            printf("%s\n", server_URL);

            if (URL_SIZE == -1)
                printf("URL could not be found. Very strange!\n");

            do {
                /** Connect to requested URL                                */
                if ((servSock = server_connect(&server_URL, &URL_SIZE)) == -1) {
                    printf("getaddrinfo ERROR to %s\n", server_URL);
                } else if (servSock == -2) {
                    printf("Connection ERROR\n");
                }

                printf("Server socket ID: %i, URL: %s\n", servSock, server_URL);


                sent_bytes = send(servSock, request, reqSize, 0);
                printf("%i\n", sent_bytes);

                // We might need the GET Request anymore
                //free(message);


                /** Receive response from server */
                IN_OUT = 1;
                rspSize = receive_msg(servSock, IN_OUT, &buf);

#if 0
                // If CONTENT has a BAD word, redirect accordingly
                if (msgSize == -3) {
                    send(sock_id, REDIRECT_MSG_CONTENT, sizeof(REDIRECT_MSG_CONTENT), 0);
                    free(buf);
                    free(response);
                    continue;
                }
#endif
                printf("RESPONSE SIZE from URL: %s, %i bytes\n\n", server_URL, rspSize);
                printf("UNFIXED Response:\n%s\n", buf);
                close(servSock);


                //printf("Recvd Response: %i bytes\n%s", msgSize, buf);


                /** Check if requested URL contains a "not allowed" word            */
                /** Change to Connection: keep-alive if need be                     */
                /** CONTENT REDIRECT if CONTENT is bad and continue to loop end     */
                /** Check if the response has status code 30x (Redirect)            */
                status = process_msg(buf, &response_or_URL, &rspSize, 1, IN_OUT);
                free(buf);

                if(status == CODE_30X_RESP) {
                    free(server_URL);

                    server_URL = (char *) malloc(rspSize);
                    memcpy(server_URL, response_or_URL, rspSize);

                    request_remake(&request, &reqSize, server_URL, rspSize);

                }



                /*amount = send(sock_id, REDIRECT_MSG_CONTENT, sizeof(REDIRECT_MSG_CONTENT), 0);
                free(buf);
                free(response);
                continue;
            */



                //if(!status)
                //printf("Fixed Response from %s:\n%s\n", server_URL, message);
            }while(status == CODE_30X_RESP);
        }
#if 0
        if(moved_flag) {
            //close(sock_id);
            send(sock_id, buf, msgSize, 0);
            free(buf);
            break;
        }
#endif
        switch(status) {
            case 0:
                sent_bytes = send(sock_id, response_or_URL, msgSize, 0);
                free(response_or_URL);
                break;

            case 1:
                sent_bytes = send(sock_id, request, msgSize, 0);
                free(request);
                break;
        }



        printf("\nSent %i bytes to broauser!\n\n", sent_bytes);




        /*regex_t find[1];
        regmatch_t match[1];
        char *serverAddr;

        int i, found = 0;
        for(i = 0; (i < 5) && !found; i++) {
            regcomp(find, not_allowed[i], 0);
            int regresp = regexec(find, buf, 1, match, 0);

            if(regresp == 0) {
                found = 1;
            }
        }*/

        /*printf("Packet size: %d\n%s", msgSize, buf);

        int j, start;

        /*regex_t mem_start[1];
        regmatch_t pmatch[1];
        char *close_word = "close";
        char *accurBuf;*/



        //char *errpage = "http://www.ida.liu.se/~TDTS04/labs/2011/ass2/error1.html";

        /*if(found) {
            //accurBuf = (char *) malloc(sizeof(REDIRECT_MSG_URL));
            //memcpy(accurBuf, REDIRECT_MSG_URL, sizeof(REDIRECT_MSG_URL));
            amount = send(sock_id, REDIRECT_MSG_URL, sizeof(REDIRECT_MSG_URL), 0);
            free(accurBuf);
            printf("Sent %d redirection Bytes!\n", amount);
            //close(sock_id);

            continue;
        }

        int i;

        i = 1;
        while (buf[i - 1] != '\n')
            i++;
        start = i + 7;
        i = start;
        while (buf[i] != '\r')
            i++;

        server_URL = (char *) malloc(i - start + 2);

        for (j = start - 1; j < i; j++)
            server_URL[j - start + 1] = buf[j];

        server_URL[i - start + 1] = '\0';

        regcomp(mem_start, "keep.alive", 0);

        int resp = regexec(mem_start, buf, 1, pmatch, 0);

        if (resp == 0) {
            accurBuf = (char *) malloc(msgSize - 5);

            int k = pmatch->rm_so;

            memcpy(accurBuf, buf, k);
            memcpy(accurBuf + k, close_word, 5);

            k += 5;

            j = k;
            while (buf[j] != '\r')
                j++;

            memcpy(accurBuf + k, buf + j, msgSize - j);
        }


        printf("%d\n", i - start);*/

        //result->ai_next = new_res;

        /*struct addrinfo *new_res;

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        //hints.ai_flags = AI_PASSIVE;

        int status;

        if ((status = getaddrinfo(server_URL, "http", &hints, &new_res)) != 0) {
            fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
            //close(sock_id);
            freeaddrinfo(new_res);
            free(request);
            continue;
        }

        struct sockaddr_in *x;
        struct sockaddr_in6 *y;
        char ipv4[INET_ADDRSTRLEN];
        char ipv6[INET6_ADDRSTRLEN];

        if (new_res->ai_family == AF_INET) {
            x = (struct sockaddr_in *) new_res->ai_addr;
            inet_ntop(AF_INET, &(x->sin_addr), ipv4, INET_ADDRSTRLEN);
            printf("IPv4 Address: %s.\n", ipv4);
        } else if (result->ai_family == AF_INET6) {
            y = (struct sockaddr_in6 *) new_res->ai_addr;
            inet_ntop(AF_INET6, &(y->sin6_addr), ipv6, INET6_ADDRSTRLEN);
            printf("IPv6 Address: %s.\n", ipv6);
        }

        // create socket to requested server
        if ((servSock = socket(new_res->ai_family, new_res->ai_socktype, new_res->ai_protocol)) == -1) {
            printf("Error creating socket to %s\n", server_URL);
            free(new_res);
            free(server_URL);
            free(request);
            continue;
        }

        int conStatus;
        int bytes_sent;

        // establish connection to server, if no error, send request packet
        if ((conStatus = connect(servSock, new_res->ai_addr, new_res->ai_addrlen)) == -1) {
            printf("Connection to %s failed.\n", server_URL);
            free(request);
            free(new_res);
            free(server_URL);
            continue;
        }*//** else {
            bytes_sent = send(servSock, request, msgSize, 0);
            free(request);

            //freeaddrinfo(new_res);
            //break;
        }*/


        //printf("\nSent packet of %d bytes to %s.\n\n", bytes_sent, serverAddr);

        // wait for response
#if 0
        int response_size = 0;
        //int segment_size;

        // segList: dummy node
        struct segNode *segList = (struct segNode *) malloc(sizeof(struct segNode));
        struct segNode *it = segList;

        int stop = 0, num_segs = 0;

        /** Gather response in segments, dynamically                    **/
        /** Stop looping after receiving the final segment              **/
        while (!stop) {
            struct segNode *newNode = (struct segNode *) malloc(sizeof(struct segNode));
            /**  **/
            if ((newNode->SEGSIZE = recv(servSock, newNode->buf, SEGSIZE_est, 0)) == 0) {
                printf("Connection to %s closed!\n\n", server_URL);
                stop = 1;
                free(newNode);
            } else if (newNode->SEGSIZE == -1) {
                printf("Error receiving data from %s.\n\n", server_URL);
                free(newNode);
                stop = 1;
            } else {
                response_size += newNode->SEGSIZE;
                it->next = newNode;
                it = it->next;
                num_segs++;
            }
        }

        int byte_it = 0;

        char *full_resp = (char *) malloc(response_size);

        int i;
        for (i = 0; i < num_segs; i++) {
            it = segList->next;
            printf("Segment %d: %d bytes\n", i, it->SEGSIZE);

            memcpy(full_resp + byte_it, it->buf, it->SEGSIZE);
            byte_it += it->SEGSIZE;

            // free current segment
            segList->next = it->next;
            free(it);
        }

        free(segList);

        char *response;
        if(process_msg(response, full_resp, response_size, 1)) {
            free(response);
            send(sock_id, REDIRECT_MSG_CONTENT, sizeof(REDIRECT_MSG_CONTENT), 0);
            freeaddrinfo(new_res);
            free(server_URL);
            continue;
        }

        freeaddrinfo(new_res);
        free(server_URL);
        free(full_resp);

        bytes_sent = send(sock_id, full_resp, response_size, 0);
#endif
        /** END */
        /*found = 0;
        for(i = 0; (i < 5) && !found; i++) {
            regcomp(find, not_allowed[i], 0);
            int regresp = regexec(find, full_resp, 1, match, 0);

            if(regresp == 0) {
                found = 1;
            }
        }
        if(found) {
            free(full_resp);
            //response_size = sizeof(REDIRECT_MSG_CONTENT);
            //full_resp = (char *) malloc(response_size);
            send(sock_id, REDIRECT_MSG_CONTENT, sizeof(REDIRECT_MSG_CONTENT), 0);
            //send(sock_id, full_resp, sizeof(REDIRECT_MSG_CONTENT), 0);
            freeaddrinfo(new_res);
            free(server_URL);
            continue;
        } else {

            response_size += 5;

            regcomp(mem_start, "Connection..close", 0);
            int regresp = regexec(mem_start, full_resp, 1, pmatch, 0);

            if (regresp == 0) {
                int k = pmatch->rm_eo;

                char *keep_alive = "keep-alive";
                char *temp_buf = (char *) malloc(response_size - k - 5);

                memcpy(temp_buf, full_resp + k, response_size - k - 5);
                memcpy(full_resp + k - 5, keep_alive, 10);
                memcpy(full_resp + k + 5, temp_buf, response_size - k - 5);

                free(temp_buf);
            }*/

            //printf("Response size: %d\n\n", response_size);
            //printf("%s\n", full_resp);

            //bytes_sent = send(sock_id, full_resp, response_size, 0);

            //printf("Bytes sent to browser: %d\n", bytes_sent);
            /*freeaddrinfo(new_res);
            free(server_URL);
            free(full_resp);
        }*/
    }
    //close(sock_id);
    //close(servSock);

    // when we don't need result(X) anymore
    //freeaddrinfo(result);
}

/** Receive whatever message */
int receive_msg(int sock, int dir, char **buf)
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
            regcomp(find, "\r\n\r\n", 0);
            regresp = regexec(find, iter->buf, 1, match, REG_ICASE | REG_EXTENDED);

            if(regresp == 0) {
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

    while(iter != NULL) {
        // LOAD INTO BUF UNTIL SEGSIZE = 0
        memcpy(&temp[offset], iter->buf, iter->SEGSIZE);
        offset += iter->SEGSIZE;
        deleteNode = iter;
        iter = iter->next;
        free(deleteNode);
    }

    /*if(dir == 0) {
        regcomp(find, not_allowed, 0);
        regresp = regexec(find, *buf, 1, match, REG_ICASE|REG_EXTENDED);

        if(regresp == 0) {
            printf("NEJNEJNEJNEJNEJ\n");
            free(*buf);
            full_size = sizeof(REDIRECT_MSG_URL);
            *buf = (char *) malloc(full_size);
            memcpy(*buf, REDIRECT_MSG_URL, full_size);
            return -2;
        }
    }*/

    if(dir == 1) {
        int start_offset, end_offset;
        char tmp[full_size];

        // Check if there is any BAD CONTENT in the response
        /*regcomp(find, not_allowed, REG_ICASE | REG_EXTENDED);
        regresp = regexec(find, *buf, 1, match, 0);

        if(regresp == 0) {
            printf("NEJNEJNEJNEJNEJ\n");
            free(*buf);
            full_size = sizeof(REDIRECT_MSG_CONTENT);
            *buf = (char *) malloc(full_size);
            memcpy(*buf, REDIRECT_MSG_CONTENT, full_size);
            return -2;
        }*/


        regcomp(find, "Location:.http://", REG_ICASE | REG_EXTENDED);
        regresp = regexec(find, *buf, 1, match, 0);

        if(regresp == 0) {
            start_offset = match->rm_eo;
            printf("HEJ\n");
            regcomp(find, "\r\n", REG_ICASE | REG_EXTENDED);
            regresp = regexec(find, *buf + start_offset, 1, match, 0);

            if (regresp == 0) {
                end_offset = start_offset + match->rm_so;
                printf("HEJ2\n");
                regcomp(find, "http://", REG_ICASE | REG_EXTENDED);
                regresp = regexec(find, *buf + start_offset, 1, match, 0);

                if(regresp == 0) {
                    int new_end = start_offset + match->rm_so;
                    if((new_end > start_offset) && (new_end < end_offset)) {
                        printf("HEJ3\n");
                        memcpy(tmp, *buf, full_size);
                        free(*buf);
                        *buf = (char *) malloc(full_size - (end_offset - new_end + 1));

                        char *tmp2 = *buf;

                        memcpy(*buf, tmp, new_end);
                        tmp2[new_end] = '/';
                        memcpy(*buf + new_end + 1, tmp + end_offset, full_size - end_offset);

                        full_size -= (end_offset - new_end);
                        full_size += 1;
                        // EVENTUELLT ÄNDRA TILL CLOSE???????
                    }
                }
#if 0
                if (!((end_offset - start_offset) % 2)) {
                    int start_off2 = start_offset + 4;
                    int i;
                    int mid = (end_offset - start_off2) / 2;

                    printf("YAS\n");
                    printf("Mid: %i\n%s\n\n\n%s\n\n", mid, *buf + start_off2, *buf + start_off2 + mid);

                    for (i = 0; i < mid; i++) {
                        if (tmp[start_off2 + i] != tmp[start_off2 + mid + i])
                            break;
                    }

                    printf("FUCK\n");

                    if (i == mid - 1) {
                        char temp[full_size];
                        memcpy(temp, *buf, full_size);
                        free(*buf);
                        *buf = (char *) malloc(full_size - mid);
                        memcpy(*buf, temp, start_off2 + mid);
                        memcpy(*buf + start_off2 + mid, temp + end_offset, full_size - end_offset);

                        end_offset = start_off2 + mid;
                        full_size -= mid;
                    }
                }
#endif
            }
        }
    }

    //temp[full_size] = '\0';

    // if inc msg is a request
    /*if (dir == 0) {
        regcomp(find, "\r\n\r\n", 0);
        regresp = regexec(find, List->buf, 1, match, REG_ICASE | REG_EXTENDED);

        if (regresp == 0) {
            header_end = match->rm_eo;
            *buf = (char *) malloc(header_end);
            memcpy(*buf, List->buf, header_end);
            printf("found Header end!\n");
        }
    }*/
    // if inc msg is a request
    /* } else {
        if((full_size = recv(sock, List->buf, SEGSIZE_est, 0)) > 0) {
            regcomp(find, "\r\n\r\n", 0);
            regresp = regexec(find, List->buf, 1, match, REG_ICASE|REG_EXTENDED);

            if(regresp == 0) {
                header_end = match->rm_eo;
                *buf = (char *) malloc(header_end);
                memcpy(*buf, List->buf, header_end);
            }

            free(List);
        }
        else if(full_size == 0)
            return -2;*/


    return full_size;
}

/** Checks if a string contain any not allowed words.
    Eventually changes connection type.
    Connection = 0 will change to close, = 1 will change to keep-alive.
    Returns 1 if it was a bad msg.    */
STATUS process_msg(char *buf, char **fixed_msg, int *msg_size, int connection, int dir)
{
    int j, k;

    char *temp1;
    char *temp2;
    int start_offset, end_offset;

    regex_t find[1];
    regmatch_t match[1];
    //printf("%s\n", buf);

    //regcomp(find, not_allowed, 0);
    int regresp;// = regexec(find, buf, 1, match, REG_ICASE|REG_EXTENDED);

    regcomp(find, "HTTP/1.[1|0] 30.", REG_ICASE | REG_EXTENDED);

    if(!regexec(find, buf, 0, NULL, 0)) {

        regcomp(find, "Location:.http://", REG_ICASE | REG_EXTENDED);

        if(!regexec(find, buf, 1, match, 0)) {
            start_offset = match->rm_eo;

            regcomp(find, "\r\n", REG_ICASE | REG_EXTENDED);

            if (!regexec(find, buf + start_offset, 1, match, 0)) {
                end_offset = match->rm_so;

                *msg_size = end_offset - start_offset;
                *fixed_msg = (char *) malloc(*msg_size);
                memcpy(*fixed_msg, buf + start_offset, *msg_size);

                return CODE_30X_RESP;
            }
        }
    }

    regcomp(find, not_allowed, REG_ICASE|REG_EXTENDED);
    regresp = regexec(find, buf, 0, NULL, 0);

    if(regresp == 0) {
        if (dir == 0) {
            *msg_size = REDIRECT_URL_SIZE;
            *fixed_msg = (char *) malloc(*msg_size);
            memcpy(*fixed_msg, REDIRECT_MSG_URL, *msg_size);

            return BAD_WORD;
        } else {
            *msg_size = REDIRECT_CONTENT_SIZE;
            *fixed_msg = (char *) malloc(*msg_size);
            memcpy(*fixed_msg, REDIRECT_MSG_CONTENT, *msg_size);

            return BAD_WORD;
        }
    }

#if 0
    if(regresp == 0) {
        printf("NEJNEJNEJNEJNEJ\n");
        return -1;
    }
#endif
    // if change connection to close:
    if(connection == 0) {
        regcomp(find, "[K|k]eep.[A|a]live", REG_ICASE|REG_EXTENDED);
        regresp = regexec(find, buf, 1, match, 0);

        if (regresp == 0) {
            *fixed_msg = (char *) malloc(*msg_size - 5);
            temp1 = *fixed_msg;
            temp2 = buf;
            //*fixed_msg[msg_size - 5] = '\0';

            k = match->rm_so;

            memcpy(*fixed_msg, buf, k);
            memcpy(*fixed_msg + k, "close", 5);

            k += 5;

            memcpy(*fixed_msg + k, buf + match->rm_eo, *msg_size - match->rm_eo);
            *msg_size -= 5;
            //printf("%s\n", *fixed_msg);
        } else {
            *fixed_msg = (char *) malloc(*msg_size);
            memcpy(*fixed_msg, buf, *msg_size);
        }
    }
    // if change connection to keep-alive:
    else if(connection == 1) {
        regcomp(find, "Connection..[C|c]lose", REG_ICASE|REG_EXTENDED);
        /** KOLLA UPP REG_ICASE OCH REG_EXTENDED!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
        regresp = regexec(find, buf, 1, match, 0);

        if (regresp == 0) {
            printf("\nClose hittades!\n\n");
            k = match->rm_eo - 5;

            *fixed_msg = (char *) malloc(*msg_size + 5);
            temp1 = *fixed_msg;
            temp2 = buf;
            //*fixed_msg[msg_size + 5] = '\0';
            memcpy(temp1, temp2, k);

            memcpy(temp1 + k, "keep-alive", 10);

            memcpy(temp1 + k + 10, temp2 + k + 5, *msg_size - k - 5);

#if 0
            memcpy(*fixed_msg, buf, k);
            memcpy(*fixed_msg + k, "keep-alive", 10);
            memcpy(*fixed_msg + k + 10, buf + k + 5, *msg_size - k - 10);
#endif
            *msg_size += 5;
        } else {
            *fixed_msg = (char *) malloc(*msg_size);
            temp1 = *fixed_msg;
            temp2 = buf;
            memcpy(temp1, temp2, *msg_size);
            //memcpy(*fixed_msg, buf, *msg_size);
        }
    }


    printf("%s\n", *fixed_msg);


    return DEFAULT;
}

/** Finds the URL for a HTTP GET request            */
int get_server_URL(char **addr, char *buf, int *buf_size)
{
    //printf("%s\n", buf);
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
#if 0
            if(!((end_offset - start_offset) % 2)) {
                int start_off2 = start_offset + 4;
                int i;
                int mid = (end_offset - start_off2) / 2;

                printf("YAS\n");
                printf("Mid: %i\n%s\n\n\n%s\n\n", mid, *buf + start_off2, *buf + start_off2 + mid);

                for(i = 0; i < mid; i++) {
                    if(tmp[start_off2 + i] != tmp[start_off2 + mid + i])
                        break;
                }

                printf("FUCK\n");

                if(i == mid - 1) {
                    char temp[*buf_size];
                    memcpy(temp, *buf, *buf_size);
                    free(*buf);
                    *buf = (char *) malloc(*buf_size - mid);
                    memcpy(*buf, temp, start_off2 + mid);
                    memcpy(*buf + start_off2 + mid, temp + end_offset, *buf_size - end_offset);

                    end_offset = start_off2 + mid;
                    *buf_size -= mid;
                }
            }
#endif
        } else { return -1; }
    } else { return -1; }

    //if(tmp[end_offset - 1] == '/')
    //    end_offset -= 1;

    //int i = start_offset;

    //if(tmp[i] == 'w' && tmp[i + 1] == 'w' && tmp[i + 2] == 'w' && tmp[i + 3] == '.') {
        *addr = (char *) malloc(end_offset - start_offset + 1);

        memcpy(*addr, buf + start_offset, end_offset - start_offset);
        tmp = *addr;
        tmp[end_offset - start_offset] = '\0';
    //}


#if 0
    int i = 1, j, start;

    while (buf[i - 1] != '\n')
        i++;
    start = i + 7;
    i = start;
    while (buf[i] != '\r')
        i++;

    *addr = (char *) malloc(i - start + 1);

    char temp[i - start + 1];

    for (j = start - 1; j < i; j++)
        temp[j - start + 1] = buf[j];

    memcpy(*addr, temp, i - start + 1);

    //*addr[i - start + 1] = '\0';
#endif

    printf("num chars: %i\n", end_offset - start_offset);
    printf("SERVER URL: %s\n", *addr);
    return (end_offset - start_offset);
}


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
            memcpy(tmp + 4, *URL, *URL_SIZE);
            free(*URL);
            *URL = (char *) malloc(*URL_SIZE + 4);

            memcpy(*URL, "www.", 4);
            memcpy(*URL + 4, tmp + 4, *URL_SIZE);

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

        // establish connection to server, if no error, send request packet
        if (connect(server_socket, pServInfo->ai_addr, pServInfo->ai_addrlen) == -1) {
            printf("Connection to %s failed.\n", *URL);

            close(server_socket);

            continue;
        }
        break;
    }

    if(pIt == NULL)
        return -2;

    freeaddrinfo(pServInfo);
    // Return socket file descriptor
    return server_socket;
}

void request_remake(char **req, int *req_size, char *URL, int URL_size)
{
    regex_t find[1];
    regmatch_t match[1];
    int regresp, Gline_so, Gline_eo, Hline_so, Hline_eo;

    char temp[*req_size];
    memcpy(temp, *req, *req_size);

    regcomp(find, "GET.http://", REG_ICASE | REG_EXTENDED);

    if(!regexec(find, *req, 1, match, 0)) {
        Gline_so = match->rm_eo;
        regcomp(find, ".HTTP/1.[0|1]", REG_ICASE | REG_EXTENDED);

        if(!regexec(find, *req, 1, match, 0)) {
            Gline_eo = match->rm_so;
        }
    }

    regcomp(find, "Host:.", REG_ICASE | REG_EXTENDED);

    if(!regexec(find, *req, 1, match, 0)) {
        Hline_so = match->rm_eo;
        regcomp(find, "\r\n", REG_ICASE | REG_EXTENDED);

        if(!regexec(find, *req, 1, match, 0)) {
            Hline_eo = match->rm_so;

            free(*req);

            *req = (char *) malloc(*req_size - (Gline_eo - Gline_so + URL_size) - (Hline_eo - Hline_so + URL_size));

            memcpy(*req + Gline_so, URL, URL_size);
            memcpy(*req + Gline_so + URL_size, temp + Gline_eo, Hline_so - Gline_eo);
            memcpy(*req + Gline_so + URL_size + (Hline_so - Gline_eo), URL, URL_size);
            memcpy(*req + Gline_so + URL_size + (Hline_so - Gline_eo) + URL_size, temp + Hline_eo, *req_size - Hline_eo);

            *req_size = *req_size - (Gline_eo - Gline_so + URL_size) - (Hline_eo - Hline_so + URL_size);
        } else
            printf("Hittade inte \ r \ n\n");
    } else
        printf("Hittade inte Host:\n");
}