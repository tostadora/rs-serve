/*
 * rs-serve - (c) 2013 Niklas E. Cathor
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "rs-serve.h"

#include <jansson.h>
#include <security/pam_appl.h>

#define IS_READ(r) (r->method == htp_method_GET || r->method == htp_method_HEAD)

static int match_scope(struct rs_scope *scope, evhtp_request_t *req) {
  const char *file_path = REQUEST_GET_PATH(req);
  log_debug("checking scope, name: %s, write: %d", scope->name, scope->write);
  int scope_len = strlen(scope->name);
  // check path
  if( (strcmp(scope->name, "") == 0) || // root scope
      ((strncmp(file_path + 1, scope->name, scope_len) == 0) && // other scope
       file_path[1 + scope_len] == '/') ) {
    log_debug("path authorized");
    // check mode
    if(scope->write || IS_READ(req)) {
      log_debug("mode authorized");
      return 0;
    }
  }
  return -1;
}

int authorize_request(evhtp_request_t *req) {
  char *username = REQUEST_GET_USER(req);
  const char *auth_header = evhtp_header_find(req->headers_in, "Authorization");
  log_debug("Got auth header: %s", auth_header);
  const char *token;
  if(auth_header) {
    if(strncmp(auth_header, "Bearer ", 7) == 0) {
      token = auth_header + 7;
      log_debug("Got token: %s", token);
      struct rs_authorization *auth = lookup_authorization(username, token);
      if(auth == NULL) {
        log_debug("Authorization not found");
      } else {
        log_debug("Got authorization (%p, scopes: %d)", auth, auth->scopes.count);
        struct rs_scope *scope;
        int i;
        for(i=0;i<auth->scopes.count;i++) {
          scope = auth->scopes.ptr[i];
          log_debug("Compare scope %s", scope->name);
          if(match_scope(scope, req) == 0) {
            return 0;
          }
        }
      }
    }
  }
  // special case: public reads on files (not directories) are allowed.
  // nothing else though.
  if(strncmp(REQUEST_GET_PATH(req), "/public/", 8) == 0 && IS_READ(req) &&
     req->uri->path->file != NULL) {
    return 0;
  }
  return -1;
}

int null_conv(int n, const struct pam_message **msg, struct pam_response **resp, void *data) {

  *resp = (struct pam_response *) malloc(sizeof(struct pam_response));
  (*resp)->resp = (char *) data;
  (*resp)->resp_retcode = 0;
  return PAM_SUCCESS;
}

void add_cors(evhtp_request_t *req) {
  ADD_RESP_HEADER_CP(req, "Access-Control-Allow-Origin", "*");
  ADD_RESP_HEADER_CP(req, "Access-Control-Allow-Methods", "GET, PUT, DELETE");
  ADD_RESP_HEADER_CP(req, "Access-Control-Allow-Headers", "Content-Type, Origin");
}

void generate_token (unsigned char *buff) {
	*((int *)buff) = rand();
	*((int *)buff+sizeof(int)) = rand();
}

evhtp_res authenticate_handle_post(evhtp_request_t *req) {
  // Someone is trying to authenticate.
  // First, we need to extract the id data

  evbuf_t *requestBuffer = req->buffer_in;
  size_t requestBufferLenght = evbuffer_get_length(requestBuffer);

  char *body = (char *) malloc(sizeof(char) * requestBufferLenght);

  if(!body) {
    return EVHTP_RES_SERVERR;
  }

  memset(body, 0, requestBufferLenght);
  evbuffer_copyout(requestBuffer, body, requestBufferLenght);

  json_t *username, *password;
  json_error_t error;
  json_t *root = json_loadb(body, requestBufferLenght, 0, &error);
  free(body);

  if (!root) {
    return EVHTP_RES_BADREQ;
  }
  if (!json_is_object(root)) {
    json_decref(root);
    return EVHTP_RES_BADREQ;
  }

  username = json_object_get(root, "username");
  password = json_object_get(root, "password");

  if (!json_is_string(username) || !json_is_string(password)) {
    json_decref(root);
    return EVHTP_RES_BADREQ;
  }

  // Second, we go and check PAM for the user
  struct pam_conv conversation = { null_conv, (void *) json_string_value(password) };
  pam_handle_t *pamh = NULL;

  if (pam_start("remotestorage", json_string_value(username), &conversation, &pamh) != PAM_SUCCESS) {
	json_decref(root);
    return EVHTP_RES_SERVERR;
  }

  int retval = pam_authenticate(pamh, 0);
  pam_end(pamh, retval);

  switch (retval) {
	  case PAM_SUCCESS:
	    break;
	  case PAM_ABORT:
	  // TODO: reply with json { success: false } in case of error
	    json_decref(root);
	    return EVHTP_RES_SERVERR;
	    break;
	  case PAM_AUTH_ERR:
	  case PAM_CRED_INSUFFICIENT:
	  case PAM_AUTHINFO_UNAVAIL:
	  case PAM_MAXTRIES:
	  case PAM_USER_UNKNOWN:
	  default:
	    json_decref(root);
	    return EVHTP_RES_UNAUTH;
	    break;
  }

  // PAM auth was successful. Reply.
  // First, generate a random token
  unsigned char token[RS_TOKEN_SIZE];
  memset(token, 0, RS_TOKEN_SIZE);

  generate_token(token);

  // Save it for future references
  if (!sm_put(auth_sessions, json_string_value(username), token)) {
    json_decref(root);
    return EVHTP_RES_SERVERR;
  }

  // And send it back
  struct json *json = new_json(json_buf_writer, req->buffer_out);

  json_start_object(json);
  json_write_key_val(json, "success", "true");
  json_write_key_val(json, "token", token);
  json_end_object(json);


  ADD_RESP_HEADER_CP(req, "Content-Type", "application/json; charset=UTF-8");

  // Free resources and leave
  json_decref(root);
  free_json(json);
  return EVHTP_RES_ACCEPTED;
}

evhtp_res authenticate_handle_delete(evhtp_request_t *req) {
  // Someone is trying to logout
  evhtp_header_t *token = evhtp_kvs_find_kv(req->uri->query, "session_token");

  if (!sm_exists(auth_sessions, token->val)){
	  return EVHTP_RES_NOTFOUND;
  }
}

evhtp_res authorizations_handle_post(evhtp_request_t *req) {

}

evhtp_res authorizations_handle_get(evhtp_request_t *req) {

}

void handle_authenticate(evhtp_request_t *req, void *arg) {
	add_cors(req);

	switch(req->method) {
      case htp_method_POST:
        req->status = authenticate_handle_post(req);
        break;
      case htp_method_DELETE:
        req->status = authenticate_handle_delete(req);
        break;
      case htp_method_HEAD:
      case htp_method_PUT:
      case htp_method_GET:
      case htp_method_OPTIONS:
      default:
        req->status = EVHTP_RES_METHNALLOWED;
	}
}

void handle_authorizations(evhtp_request_t *req, void *arg) {
	switch(req->method) {
      case htp_method_POST:
        req->status = authorizations_handle_post(req);
        break;
      case htp_method_GET:
        req->status = authorizations_handle_get(req);
        break;
      case htp_method_HEAD:
      case htp_method_PUT:
      case htp_method_DELETE:
      case htp_method_OPTIONS:
      default:
        req->status = EVHTP_RES_METHNALLOWED;
	}
}

