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

#ifndef RS_AUTH_H
#define RS_AUTH_H

#define RS_TOKEN_SIZE 64

int authorize_request(evhtp_request_t *req);

void handle_authenticate(evhtp_request_t *req, void *arg);
void handle_authorizations(evhtp_request_t *req, void *arg);

#endif /* !RS_AUTH_H */

