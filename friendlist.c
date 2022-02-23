/*
 * friendlist.c - [Starting code for] a web-based friend-graph manager.
 *
 * Based on:
 *  tiny.c - A simple, iterative HTTP/1.0 Web server that uses the 
 *      GET method to serve static and dynamic content.
 *   Tiny Web server
 *   Dave O'Hallaron
 *   Carnegie Mellon University
 *  Author: Devin Schwehr 
 */
#include "csapp.h"
#include "dictionary.h"
#include "more_string.h"

// static void doit(int fd);
static void *doit(void *fd);
static dictionary_t *read_requesthdrs(rio_t *rp);
static void read_postquery(rio_t *rp, dictionary_t *headers, dictionary_t *d);
static void clienterror(int fd, char *cause, char *errnum, 
                        char *shortmsg, char *longmsg);
static void print_stringdictionary(dictionary_t *d);
static void serve_request(int fd, dictionary_t *query);
static void serve_list(int fd, dictionary_t *query);
static void serve_befriend(int fd, dictionary_t *query);
static void serve_unfriend(int fd, dictionary_t *query);
static void serve_introduce(int fd, dictionary_t *query);
static void add_to_user_dict(const char *user, char *friend);
static void remove_from_user_dict(const char *user, char *friend);

//Create the dictionary that stores the users
dictionary_t *user_dict;
pthread_mutex_t mutex;

int main(int argc, char **argv) {
  int listenfd, connfd, *connfd_pointer;
  char hostname[MAXLINE], port[MAXLINE];
  socklen_t clientlen;
  struct sockaddr_storage clientaddr;

  pthread_mutex_t mutex;
  pthread_mutex_init(&mutex,NULL);
  user_dict = make_dictionary(0,NULL);


  /* Check command line args */
  if (argc != 2) {
    fprintf(stderr, "usage: %s <port>\n", argv[0]);
    exit(1);
  }

  listenfd = Open_listenfd(argv[1]);

  /* Don't kill the server if there's an error, because
     we want to survive errors due to a client. But we
     do want to report errors. */
  exit_on_error(0);

  /* Also, don't stop on broken connections: */
  Signal(SIGPIPE, SIG_IGN);

  while (1) {
    clientlen = sizeof(clientaddr);
    connfd = Accept(listenfd, (SA *)&clientaddr, &clientlen);
    if (connfd >= 0) {
      Getnameinfo((SA *) &clientaddr, clientlen, hostname, MAXLINE, 
                  port, MAXLINE, 0);
      printf("Accepted connection from (%s, %s)\n", hostname, port);
      //Here we will change from the original method and change to use concurrency
      pthread_t thread_id;
      connfd_pointer = malloc(sizeof(int));
      *connfd_pointer = connfd;
      Pthread_create(&thread_id,NULL, doit,connfd_pointer);
      Pthread_detach(thread_id);
    }
  }
}

/*
 * doit - handle one HTTP request/response transaction
 */
void *doit(void *fd_p) {
  int fd = *(int *) fd_p;
  char buf[MAXLINE], *method, *uri, *version;
  rio_t rio;
  dictionary_t *headers, *query;

  /* Read request line and headers */
  Rio_readinitb(&rio, fd);
  if (Rio_readlineb(&rio, buf, MAXLINE) <= 0)
    return NULL;
  printf("%s", buf);
  
  if (!parse_request_line(buf, &method, &uri, &version)) {
    clienterror(fd, method, "400", "Bad Request",
                "Friendlist did not recognize the request");
  } else {
    if (strcasecmp(version, "HTTP/1.0")
        && strcasecmp(version, "HTTP/1.1")) {
      clienterror(fd, version, "501", "Not Implemented",
                  "Friendlist does not implement that version");
    } else if (strcasecmp(method, "GET")
               && strcasecmp(method, "POST")) {
      clienterror(fd, method, "501", "Not Implemented",
                  "Friendlist does not implement that method");
    } else {
      headers = read_requesthdrs(&rio);

      /* Parse all query arguments into a dictionary */
      query = make_dictionary(COMPARE_CASE_SENS, free);
      parse_uriquery(uri, query);
      if (!strcasecmp(method, "POST"))
        read_postquery(&rio, headers, query);

      /* For debugging, print the dictionary */
      print_stringdictionary(query);

      //Where we decide what method to call
      if(starts_with("/friends",uri))
      {
        serve_list(fd, query);
      }
      else if(starts_with("/befriend",uri))
      {
        serve_befriend(fd, query);
      }
      else if(starts_with("/unfriend",uri))
      {
        serve_unfriend(fd, query);
      }
      else if(starts_with("/introduce",uri))
      {
        serve_introduce(fd, query);
      }
      else{
        serve_request(fd, query);
      }
      /* Clean up */
      free_dictionary(query);
      free_dictionary(headers);
    }

    /* Clean up status line */
    free(method);
    free(uri);
    free(version);
  }

  Close(fd);
  return NULL;
}

/*
 * read_requesthdrs - read HTTP request headers
 */
dictionary_t *read_requesthdrs(rio_t *rp) {
  char buf[MAXLINE];
  dictionary_t *d = make_dictionary(COMPARE_CASE_INSENS, free);

  Rio_readlineb(rp, buf, MAXLINE);
  printf("%s", buf);
  while(strcmp(buf, "\r\n")) {
    Rio_readlineb(rp, buf, MAXLINE);
    printf("%s", buf);
    parse_header_line(buf, d);
  }
  
  return d;
}

void read_postquery(rio_t *rp, dictionary_t *headers, dictionary_t *dest) {
  char *len_str, *type, *buffer;
  int len;
  
  len_str = dictionary_get(headers, "Content-Length");
  len = (len_str ? atoi(len_str) : 0);

  type = dictionary_get(headers, "Content-Type");
  
  buffer = malloc(len+1);
  Rio_readnb(rp, buffer, len);
  buffer[len] = 0;

  if (!strcasecmp(type, "application/x-www-form-urlencoded")) {
    parse_query(buffer, dest);
  }

  free(buffer);
}

static char *ok_header(size_t len, const char *content_type) {
  char *len_str, *header;
  
  header = append_strings("HTTP/1.0 200 OK\r\n",
                          "Server: Friendlist Web Server\r\n",
                          "Connection: close\r\n",
                          "Content-length: ", len_str = to_string(len), "\r\n",
                          "Content-type: ", content_type, "\r\n\r\n",
                          NULL);
  free(len_str);

  return header;
}

/*
 * serve_request - example request handler
 */
static void serve_request(int fd, dictionary_t *query) {
  size_t len;
  char *body, *header;

  body = strdup("alice\nbob");

  len = strlen(body);

  /* Send response headers to client */
  header = ok_header(len, "text/html; charset=utf-8");
  Rio_writen(fd, header, strlen(header));
  printf("Response headers:\n");
  printf("%s", header);

  free(header);

  /* Send response body to client */
  Rio_writen(fd, body, len);

  free(body);
}

/*
* Method that lists all friends of user
*/
static void serve_list(int fd, dictionary_t *query) {
  size_t len;
  char *body, *header;
  //Get the user from the query dictionary
  const char *user = dictionary_get(query,"user");

  pthread_mutex_lock(&mutex);
  if(dictionary_get(user_dict,user) == NULL)
  {
    body = strdup("");
  }
  else
  {
    body = strdup(join_strings(dictionary_keys(dictionary_get(user_dict,user)), '\n'));
  }
  pthread_mutex_unlock(&mutex);
  len = strlen(body);

  /* Send response headers to client */
  header = ok_header(len, "text/html; charset=utf-8");
  Rio_writen(fd, header, strlen(header));
  printf("Response headers:\n");
  printf("%s", header);

  free(header);

  /* Send response body to client */
  Rio_writen(fd, body, len);

  free(body);
}

static void serve_befriend(int fd, dictionary_t *query)
{
  size_t len;
  char *body, *header;

  //Get the user from the query dictionary
  const char *user = dictionary_get(query,"user");
  char **friends = split_string(dictionary_get(query,"friends"),'\n');

  int i;
  for(i = 0; friends[i] != NULL; i++)
  {
    //First add the friend to the user's friend_dict
    add_to_user_dict(user, friends[i]);
    //then do the reciprocal of that
    add_to_user_dict((const char *)friends[i], (char *)user);
  }
  pthread_mutex_lock(&mutex);
  body = strdup(join_strings(dictionary_keys(dictionary_get(user_dict,user)), '\n'));
  pthread_mutex_unlock(&mutex);
  len = strlen(body);

  /* Send response headers to client */
  header = ok_header(len, "text/html; charset=utf-8");
  Rio_writen(fd, header, strlen(header));
  printf("Response headers:\n");
  printf("%s", header);

  free(header);

  /* Send response body to client */
  Rio_writen(fd, body, len);

  free(body);
}

static void serve_unfriend(int fd, dictionary_t *query)
{
  size_t len;
  char *body, *header;

  //Get the user from the query dictionary
  const char *user = dictionary_get(query,"user");\
  char **friends = split_string(dictionary_get(query,"friends"),'\n');

  int i;
  for(i = 0; friends[i] != NULL; i++)
  {
    //First add the friend to the user's friend_dict
    remove_from_user_dict(user, friends[i]);
    //then do the reciprocal of that
    remove_from_user_dict((const char *)friends[i], (char *)user);
  }

  if(dictionary_get(user_dict,user) == NULL)
  {
    body = strdup("");
  }
  else
  {
    pthread_mutex_lock(&mutex);
    body = strdup(join_strings(dictionary_keys(dictionary_get(user_dict,user)), '\n'));
    pthread_mutex_unlock(&mutex);
  }
  len = strlen(body);

  /* Send response headers to client */
  header = ok_header(len, "text/html; charset=utf-8");
  Rio_writen(fd, header, strlen(header));
  printf("Response headers:\n");
  printf("%s", header);

  free(header);

  /* Send response body to client */
  Rio_writen(fd, body, len);

  free(body);
}

static void serve_introduce(int fd, dictionary_t *query)
{
  char *user = dictionary_get(query, "user"); 
  char *friend = dictionary_get(query, "friend"); 
  char *host = dictionary_get(query, "host"); 
  char *port = dictionary_get(query, "port");

  //Open a file descriptor to the client
  int file_descriptor = Open_clientfd(host, port); 

  char buf[MAXLINE];
  rio_t rio;

  //We will be using a lot of the same logic from doit
  char *url = append_strings("/friends?user=", friend, NULL);
  char *request = append_strings("GET ", url, " HTTP/1.1", "\r\n\r\n", NULL);

  Rio_writen(file_descriptor, request, strlen(request));
  Rio_readinitb(&rio, file_descriptor);
  Rio_readlineb(&rio, buf, MAXLINE); 

  char *status = split_string(buf, ' ')[1];

  //If we don't get a 200 response, back out
  if(strcmp("200", status))
  {
    return;
  }

  int working_through_header = 1;
  int content_length = 0;

  //Work through the header in order to get the lenth of the content
  while(working_through_header && Rio_readlineb(&rio, buf, MAXLINE) != 0)
  {
    if(starts_with("Content-length", buf))
    {
      content_length = atoi((char *)buf + 16);
      printf("CONTENT LEN: %d \n", content_length);
    }
    if(starts_with("\r\n", buf)) // Done reading header
    {
      working_through_header = 0;
      continue;
    }
  }
  //Now that we're through the header, we can get the friends.
  if(!working_through_header)
  {
    char *response = malloc(content_length + 1);
    response[content_length] = 0;
    Rio_readnb(&rio, response, content_length);

    char ** friends = split_string(response, '\n');
    //Add each of the friends in the list
    int i;
    for(i = 0; friends[i] != NULL; i++)
    {
      add_to_user_dict(user, friends[i]);
      add_to_user_dict(friends[i], user);
    }
  }

  //Finally, add the original friend
  add_to_user_dict(user, friend);
  add_to_user_dict(friend, user);

  //Lock the thread when getting the current dictionary list
  pthread_mutex_lock(&mutex);
  char *body = strdup(join_strings(dictionary_keys(dictionary_get(user_dict,user)), '\n'));
  pthread_mutex_unlock(&mutex);
  size_t len = strlen(body);

  /* Send response headers to client */
  char *header = ok_header(len, "text/html; charset=utf-8");
  Rio_writen(fd, header, strlen(header));
  printf("Response headers:\n");
  printf("%s", header);

  free(header);

  /* Send response body to client */
  Rio_writen(fd, body, len);

  free(body);
}

static void add_to_user_dict(const char *user, char *friend)
{
  //Lock!
  pthread_mutex_lock(&mutex);
  //Do not add a friend if the friend is the same as user
  if(strcasecmp(user,friend) != 0)
  {
    if(dictionary_get(user_dict,user) == NULL)
    {
      //Initialize friend dict
      dictionary_t *friend_dict = make_dictionary(0,NULL);
      //Add friend to dict
      dictionary_set(friend_dict,friend,NULL);
      //link together user and friend_dict in user_dict
      dictionary_set(user_dict,user,friend_dict);
    }
    //Otherwise the user exists in the dictionary
    else
    {
      //Insert the friend into the user's existing friend_dict
      dictionary_set(dictionary_get(user_dict,user),friend,NULL);
    }
  }
  //No matter what happens, don't forget to unlock
  pthread_mutex_unlock(&mutex);
}

static void remove_from_user_dict(const char *user, char *friend)
{
  //Same as with adding, don't forget to lock
  pthread_mutex_lock(&mutex);
  //First check that the user key is not null
  if(dictionary_get(user_dict,user) != NULL)
  {
    //Remove the friend from the user's friend dictionary
    dictionary_remove(dictionary_get(user_dict,user),friend);
    //If the user's friend dictionary is now empty, free that dictionary and remove the user
    if(dictionary_count(dictionary_get(user_dict,user)) == 0)
    {
      free_dictionary(dictionary_get(user_dict,user));
      dictionary_remove(user_dict,user);
    }
  }
  pthread_mutex_unlock(&mutex);
}

/*
 * clienterror - returns an error message to the client
 */
void clienterror(int fd, char *cause, char *errnum, 
		 char *shortmsg, char *longmsg) {
  size_t len;
  char *header, *body, *len_str;

  body = append_strings("<html><title>Friendlist Error</title>",
                        "<body bgcolor=""ffffff"">\r\n",
                        errnum, " ", shortmsg,
                        "<p>", longmsg, ": ", cause,
                        "<hr><em>Friendlist Server</em>\r\n",
                        NULL);
  len = strlen(body);

  /* Print the HTTP response */
  header = append_strings("HTTP/1.0 ", errnum, " ", shortmsg, "\r\n",
                          "Content-type: text/html; charset=utf-8\r\n",
                          "Content-length: ", len_str = to_string(len), "\r\n\r\n",
                          NULL);
  free(len_str);
  
  Rio_writen(fd, header, strlen(header));
  Rio_writen(fd, body, len);

  free(header);
  free(body);
}

static void print_stringdictionary(dictionary_t *d) {
  int i, count;

  count = dictionary_count(d);
  for (i = 0; i < count; i++) {
    printf("%s=%s\n",
           dictionary_key(d, i),
           (const char *)dictionary_value(d, i));
  }
  printf("\n");
}
