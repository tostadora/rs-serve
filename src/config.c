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

static void print_help(const char *progname) {
  fprintf(stderr,
          "Usage: %s [options]\n"
          "\n"
          "Options:\n"
          "  -h        | --help            - Display this text and exit.\n"
          "  -v        | --version         - Print program version and exit.\n"
          "  -p <port> | --port=<port>     - Bind to given port (default: 80).\n"
          "  -n <name> | --hostname=<name> - Set hostname (defaults to local.dev).\n"
          "  -f <file> | --log-file=<file> - Log to given file (defaults to stdout)\n"
          "  -d        | --detach          - After starting the server, detach server\n"
          "                                  process and exit. If you don't use this in\n"
          "                                  combination with the --log-file option, all\n"
          "                                  future output will be lost.\n"
          "  --auth-port <port>            - Bind the auth server to given port (default: 8888).\n"
          "  --dir=<directory-name>        - Name of the directory relative to the user's\n"
          "                                  home directory to serve data from.\n"
          "                                  Defaults to: storage\n"
          "  --stop                        - Stop a running rs-serve process. The process\n"
          "                                  is identified by the PID file specified via\n"
          "                                  the --pid-file option. NOTE: the --stop option\n"
          "                                  MUST precede the --pid-file option on the\n"
          "                                  command line for this to work.\n"
          "  --pid-file=<file>             - Write PID to given file.\n"
          " --debug                        - Enable debug output.\n"
          " --auth-uri=<uri-template>      - URI of the OAuth2 endpoint. Required for webfinger.\n"
          " --ssl                          - Enable SSL.\n"
          " --cert-path=<path>             - Set path to SSL certificate file.\n"
          " --key-path=<path>              - Set path to SSL key file.\n"
          " --ca-path=<path>               - Set path to SSL CA file.\n"
          " --no-xattr                     - Don't store meta information in extended attributes.\n"
          "                                  They will be stored in a separate Berkeley Database\n"
          "                                  instead. Use this option if your filesystem does not\n"
          "                                  support extended attributes or you don't want to use\n"
          "                                  them. (NOT IMPLEMENTED)\n"
          "\n"
          "This program is distributed in the hope that it will be useful,\n"
          "but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
          "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
          "GNU Affero General Public License for more details.\n"
          "(c) 2013 Niklas E. Cathor\n\n"
          , progname);
}

static void print_version() {
  fprintf(stderr, "rs-serve %d.%d%s\n", RS_VERSION_MAJOR, RS_VERSION_MINOR, RS_VERSION_POSTFIX);
}

int rs_port = 80;
int rs_auth_port = 8888;
char *rs_scheme = "http";
char *rs_hostname = "local.dev";
int rs_detach = 0;
FILE *rs_log_file = NULL;
FILE *rs_pid_file = NULL;
char *rs_pid_file_path = NULL;
char *rs_home_serve_root = NULL;
int rs_home_serve_root_len = 0;
int rs_stop_other = 0;
char *rs_auth_uri = NULL;
int rs_auth_uri_len = 0;
int rs_webfinger_enabled = 1;
int rs_use_ssl = 0;
char *rs_ssl_cert_path = NULL;
char *rs_ssl_key_path = NULL;
char *rs_ssl_ca_path = NULL;
int rs_use_xattr = 1;

void (*current_log_debug)(const char *file, int line, char *format, ...) = NULL;

static struct option long_options[] = {
  { "port", required_argument, 0, 'p' },
  { "hostname", required_argument, 0, 'n' },
  { "dir", required_argument, 0, 0 },
  { "auth-port", no_argument, 0, 0 },
  { "pid-file", required_argument, 0, 0 },
  { "stop", no_argument, 0, 0 },
  { "log-file", required_argument, 0, 'f' },
  { "debug", no_argument, 0, 0 },
  { "detach", no_argument, 0, 'd' },
  { "help", no_argument, 0, 'h' },
  { "version", no_argument, 0, 'v' },
  { "auth-uri", required_argument, 0, 0 },
  { "ssl", no_argument, 0, 0 },
  { "cert-path", required_argument, 0, 0 },
  { "key-path", required_argument, 0, 0 },
  { "ca-path", required_argument, 0, 0 },
  { "no-xattr", no_argument, 0, 0 },
  { 0, 0, 0, 0 }
};

void close_pid_file() {
  fclose(RS_PID_FILE);
  unlink(RS_PID_FILE_PATH);
}

void init_config(int argc, char **argv) {
  int opt;
  for(;;) {
    int opt_index = 0;
    opt = getopt_long(argc, argv, "p:n:r:f:dhv", long_options, &opt_index);
    if(opt == '?') {
      // invalid option
      exit(EXIT_FAILURE);
    } else if(opt == -1) {
      // no more options
      break;
    } else if(opt == 'p') {
      rs_port = atoi(optarg);
    } else if(opt == 'n') {
      rs_hostname = optarg;
    } else if(opt == 'f') {
      rs_log_file = fopen(optarg, "a");
      if(rs_log_file == NULL) {
        perror("Failed to open log file");
        exit(EXIT_FAILURE);
      }
    } else if(opt == 'd') {
      rs_detach = 1;
    } else if(opt == 'h') {
      print_help(argv[0]);
      exit(127);
    } else if(opt == 'v') {
      print_version();
      exit(127);
    } else if(opt == 0) {

      const char *arg_name = long_options[opt_index].name;

      // long option with no short equivalent
      if(strcmp(arg_name, "pid-file") == 0) { // --pid-file
        rs_pid_file_path = optarg;

        // stop was requested, kill other process by pid-file
        if(rs_stop_other) {
          rs_pid_file = fopen(rs_pid_file_path, "r");
          if(rs_pid_file == NULL) {
            perror("Failed to open pid file for reading");
            exit(EXIT_FAILURE);
          }
          pid_t pid;
          fscanf(rs_pid_file, "%d", &pid);
          if(kill(pid, SIGTERM) == 0) {
            printf("Sent SIGTERM to process %d\n", pid);
            exit(EXIT_SUCCESS);
          } else {
            fprintf(stderr, "Sending SIGTERM to process %d failed: %s\n", pid, strerror(errno));
            exit(EXIT_FAILURE);
          }
        }

        // open pid file (process/main stores our pid there)
        rs_pid_file = fopen(rs_pid_file_path, "wx");
        if(rs_pid_file == NULL) {
          perror("Failed to open pid file");
          exit(EXIT_FAILURE);
        }
        atexit(close_pid_file);
      } else if(strcmp(arg_name, "stop") == 0) { // --stop
        rs_stop_other = 1;
      } else if(strcmp(arg_name, "debug") == 0) { // --debug
        current_log_debug = do_log_debug;
      } else if(strcmp(arg_name, "auth-port") == 0) { // --auth-port
        rs_auth_port = atoi(optarg);
      } else if(strcmp(arg_name, "dir") == 0) { // --dir=<dirname>
        rs_home_serve_root = optarg;
        int len = strlen(rs_home_serve_root);
        if(rs_home_serve_root[len - 1] == '/') {
          // strip trailing slash.
          rs_home_serve_root[--len] = 0;
        }
        rs_home_serve_root_len = len;
      } else if(strcmp(arg_name, "auth-uri") == 0) { // --auth-uri=<uri-template>
        rs_auth_uri = optarg;
        rs_auth_uri_len = strlen(rs_auth_uri);
      } else if(strcmp(arg_name, "ssl") == 0) { // --ssl
        rs_use_ssl = 1;
        rs_scheme = "https";
      } else if(strcmp(arg_name, "cert-path") == 0) { // --cert-path
        rs_ssl_cert_path = optarg;
      } else if(strcmp(arg_name, "key-path") == 0) { // --key-path
        rs_ssl_key_path = optarg;
      } else if(strcmp(arg_name, "ca-path") == 0) { // --ca-path
        rs_ssl_ca_path = optarg;
      } else if(strcmp(arg_name, "no-xattr") == 0) { // --no-xattr
        rs_use_xattr = 0;
      }
    }
  }

  if(rs_home_serve_root == NULL) {
    rs_home_serve_root = "storage";
    rs_home_serve_root_len = 7;
  }

  if(rs_stop_other) {
    fprintf(stderr, "ERROR: can't stop existing process without --pid-file option.\n");
    exit(EXIT_FAILURE);
  }

  if(current_log_debug == NULL) {
    current_log_debug = dont_log_debug;
  }

  if(rs_log_file == NULL) {
    rs_log_file = stdout;
  }

  if(RS_USE_SSL) {
    if(RS_SSL_CERT_PATH == NULL || RS_SSL_KEY_PATH == NULL) {
      log_error("You need to specify at least --cert-path and --key-path options to enable SSL");
      exit(EXIT_FAILURE);
    }

    if(rs_port == 80) {
      rs_port = 443;
    }
  }

  if(rs_auth_uri == NULL) {
    log_warn("No --auth-uri set, won't be able to do webfinger!");
    rs_webfinger_enabled = 0;
  }

}

void cleanup_config() {
  // XXX: remove this?
}
