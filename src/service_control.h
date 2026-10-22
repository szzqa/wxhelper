#ifndef WXHELPER_SERVICE_CONTROL_H_
#define WXHELPER_SERVICE_CONTROL_H_
struct mg_connection;
struct mg_http_message;
// Called only by the server's Mongoose event loop.
bool HandleControlRequest(mg_connection*, mg_http_message*);
void HandleControlEvent(mg_connection*, int event);
#endif
