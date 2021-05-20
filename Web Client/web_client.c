#include <stdio.h>      /* printf, sprintf */
#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include "helpers.h"
#include "requests.h"
#include "parson.h"

#define HOST "ec2-3-8-116-10.eu-west-2.compute.amazonaws.com"
#define PORT 8080

// gets the IP of the host using DNS
char* get_ip(char* name) {
	struct addrinfo hints, *result, *p;
	memset (&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC;
	hints.ai_protocol = IPPROTO_TCP;

	getaddrinfo(name, NULL, &hints, &result);

	for (p = result; p != NULL; p = p->ai_next) {
		 if (p->ai_family == AF_INET) {
		 	char* ip = malloc(INET_ADDRSTRLEN);
		 	struct sockaddr_in* addr = (struct sockaddr_in*) p->ai_addr;
		 	if (inet_ntop(p->ai_family, &(addr->sin_addr), ip, INET_ADDRSTRLEN) != NULL) {
		 		freeaddrinfo(result);
		 		return ip;
		 	}
		 }
	}
	return NULL;
}

int main(int argc, char *argv[])
{
    char *message;
    char *response;
    int sockfd;

    // Gets the host IP
    char* host_ip = get_ip(HOST);

    // Command read from stdin
    char* cmd = malloc(20);

    char * cookie = calloc(BUFLEN, sizeof(char));
    char* token = calloc(BUFLEN, sizeof(char));

    while(1) {
    	memset(cmd, 0, 20);
    	scanf("%s", cmd);

        // frees everything(I hope) and exits
    	if(strcmp(cmd, "exit") == 0) {
    		free(host_ip);
    		free(cmd);
    		free(cookie);
    		free(token);
            printf("Shutting down...\n");
    		return 0;
    	}
    	else if(strcmp(cmd, "register") == 0) {
    		sockfd = open_connection(host_ip, PORT, AF_INET, SOCK_STREAM, 0);

    		char* user = calloc(100, sizeof(char));
    		char* pass = calloc(100, sizeof(char));
    		printf("username=");
    		getchar();
    		fgets(user, 100, stdin);
    		printf("password=");
    		fgets(pass, 100, stdin);
    		user[strlen(user) - 1] = 0;
    		pass[strlen(pass) - 1] = 0;

    		JSON_Value *root_value = json_value_init_object();
    		JSON_Object *root_object = json_value_get_object(root_value);
    		char *serialized_string = NULL;
    		json_object_set_string(root_object, "username", user);
    		json_object_set_string(root_object, "password", pass);
    		serialized_string = json_serialize_to_string_pretty(root_value);

    		message = compute_post_request(host_ip, "/api/v1/tema/auth/register", "application/json", serialized_string, NULL, 0, NULL, 0);
    		send_to_server(sockfd, message);
    		response = receive_from_server(sockfd);

    		if(strstr(response, "400 Bad Request")) {
    			printf("Username already taken. Please try another one.\n");
    		}
            else {
                printf("Registration succesful.\n");
            }

    		json_free_serialized_string(serialized_string);
    		json_value_free(root_value);
    		free(user);
    		free(pass);

    		close_connection(sockfd);
    	}
    	else if(strcmp(cmd, "login") == 0) {

    		sockfd = open_connection(host_ip, PORT, AF_INET, SOCK_STREAM, 0);

    		char* user = calloc(100, sizeof(char));
    		char* pass = calloc(100, sizeof(char));
    		printf("username=");
    		getchar();
    		fgets(user, 100, stdin);
    		printf("password=");
    		fgets(pass, 100, stdin);
    		user[strlen(user) - 1] = 0;
    		pass[strlen(pass) - 1] = 0;

    		JSON_Value *root_value = json_value_init_object();
    		JSON_Object *root_object = json_value_get_object(root_value);
    		char *serialized_string = NULL;
    		json_object_set_string(root_object, "username", user);
    		json_object_set_string(root_object, "password", pass);
    		serialized_string = json_serialize_to_string_pretty(root_value);

    		message = compute_post_request(host_ip, "/api/v1/tema/auth/login", "application/json", serialized_string, NULL, 0, NULL, 0);
    		send_to_server(sockfd, message);
    		response = receive_from_server(sockfd);

    		if(strstr(response, "400 Bad Request")) {
                printf("Wrong credentials. Please try again.\n");
    		}
    		else {
                printf("Logged in.\n");
    			memset(cookie, 0 , BUFLEN);
    			strncpy(cookie, strstr(response, "Set-Cookie") + 4, strstr(strstr(response, "Set-Cookie"), "\n") - strstr(response, "Set-Cookie") - 5);
    		}
    		json_free_serialized_string(serialized_string);
    		json_value_free(root_value);
    		free(user);
    		free(pass);

    		close_connection(sockfd);
    	}
    	else if(strcmp(cmd, "enter_library") == 0) {
    		sockfd = open_connection(host_ip, PORT, AF_INET, SOCK_STREAM, 0);

    		message = compute_get_request(host_ip, "/api/v1/tema/library/access", NULL, &cookie, 1, NULL, 0);
    		send_to_server(sockfd, message);
    		response = receive_from_server(sockfd);

    		if(strstr(response, "401 Unauthorized")) {
                printf("You are not logged in.\n");
    		}
    		else {
                printf("Acces to the library granted.\n");
    			memset(token, 0 , BUFLEN);
    			sprintf(token, "Authorization: Bearer ");
    			strncat(token, basic_extract_json_response(response)+10, strlen(basic_extract_json_response(response))-12);
    		}

    		close_connection(sockfd);
    	}
    	else if(strcmp(cmd, "get_books") == 0) {
    		sockfd = open_connection(host_ip, PORT, AF_INET, SOCK_STREAM, 0);

    		message = compute_get_request(host_ip, "/api/v1/tema/library/books", NULL, NULL, 0, &token, 1);
    		send_to_server(sockfd, message);
    		response = receive_from_server(sockfd);

    		if(strstr(response, "200 OK")) {
                printf("Books:\n");
                printf("%s\n", strstr(response, "["));
    		}
    		else {
                printf("Unauthorized\n");
    		}

    		close_connection(sockfd);
    	}
    	else if(strcmp(cmd, "add_book") == 0) {
    		sockfd = open_connection(host_ip, PORT, AF_INET, SOCK_STREAM, 0);

    		char* title = calloc(200, sizeof(char));
    		char* author = calloc(200, sizeof(char));
    		char* genre = calloc(200, sizeof(char));
    		char* publisher = calloc(200, sizeof(char));
    		char* page_count = calloc(5, sizeof(char));

    		getchar();
    		printf("title=");
    		fgets(title, 200, stdin);
    		printf("author=");
    		fgets(author, 200, stdin);
    		printf("genre=");
    		fgets(genre, 200, stdin);
    		printf("publisher=");
    		fgets(publisher, 200, stdin);
    		printf("page_count=");
    		fgets(page_count, 5, stdin);

    		title[strlen(title) - 1] = 0;
    		author[strlen(author) - 1] = 0;
    		genre[strlen(genre) - 1] = 0;
    		publisher[strlen(publisher) - 1] = 0;
    		page_count[strlen(page_count) - 1] = 0;

    		JSON_Value *root_value = json_value_init_object();
    		JSON_Object *root_object = json_value_get_object(root_value);
    		char *serialized_string = NULL;
    		json_object_set_string(root_object, "title", title);
    		json_object_set_string(root_object, "author", author);
    		json_object_set_string(root_object, "genre", genre);
    		json_object_set_string(root_object, "page_count", page_count);
    		json_object_set_string(root_object, "publisher", publisher);
    		serialized_string = json_serialize_to_string_pretty(root_value);

    		message = compute_post_request(host_ip, "/api/v1/tema/library/books", "application/json", serialized_string, NULL, 0, &token, 1);
    		send_to_server(sockfd, message);
    		response = receive_from_server(sockfd);

            if(strstr(response, "200 OK")) {
                printf("Book added.\n");
            }
            else if(strstr(response, "500 Internal")){
                printf("Wrong format.\n");
            }
            else {
                printf("Unauthorized\n");
            }

    		json_free_serialized_string(serialized_string);
    		json_value_free(root_value);
    		free(title);
    		free(author);
    		free(genre);
    		free(publisher);
    		free(page_count);

    		close_connection(sockfd);
    	}
    	else if(strcmp(cmd, "get_book") == 0) {
    		sockfd = open_connection(host_ip, PORT, AF_INET, SOCK_STREAM, 0);

    		int id;
    		printf("id=");
    		scanf("%d", &id);

    		char* url = calloc(50, sizeof(char));
    		sprintf(url, "/api/v1/tema/library/books/%d", id);

    		message = compute_get_request(host_ip, url, NULL, NULL, 0, &token, 1);
    		send_to_server(sockfd, message);
    		response = receive_from_server(sockfd);

            if(strstr(response, "200 OK")) {
                printf("%s\n", basic_extract_json_response(response));
            }
            else if(strstr(response, "404 Not Found")) {
                printf("Book not found.\n");
            }
            else {
                printf("Unauthorized.\n");
            }

    		free(url);
    		close_connection(sockfd);
    	}
    	else if(strcmp(cmd, "delete_book") == 0) {
    		sockfd = open_connection(host_ip, PORT, AF_INET, SOCK_STREAM, 0);

    		int id;
    		printf("id=");
    		scanf("%d", &id);

    		char* url = calloc(50, sizeof(char));
    		sprintf(url, "/api/v1/tema/library/books/%d", id);

    		message = compute_delete_request(host_ip, url, NULL, 0, &token, 1);
    		send_to_server(sockfd, message);
    		response = receive_from_server(sockfd);

            if(strstr(response, "200 OK")) {
                printf("Book deleted.\n");
            }
            else if(strstr(response, "404 Not Found")) {
                printf("Book not found.\n");
            }
            else {
                printf("Unauthorized.\n");
            }

    		free(url);
    		close_connection(sockfd);
    	}
    	else if(strcmp(cmd, "logout") == 0) {
    		sockfd = open_connection(host_ip, PORT, AF_INET, SOCK_STREAM, 0);
	
			message = compute_get_request(host_ip, "/api/v1/tema/auth/logout", NULL, &cookie, 1, NULL, 0);
    		send_to_server(sockfd, message);
    		response = receive_from_server(sockfd);
            memset(cookie, 0, BUFLEN);
            memset(token, 0, BUFLEN);

            if(strstr(response, "200 OK")) {
                printf("Logged out.\n");
            }
            else {
                printf("You are not logged in.\n");;
            }
			
			close_connection(sockfd);
    	}
        else {
            printf("Invalid command.\n"
                "Commands:\n"
                "\t-register\n"
                "\t-login\n"
                "\t-enter_library\n"
                "\t-get_books\n"
                "\t-add_book\n"
                "\t-get_book\n"
                "\t-delete_book\n"
                "\t-logout\n"
                "\t-exit\n");
        }
    }
    return 0;
}
