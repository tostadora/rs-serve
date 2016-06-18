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

#ifndef RS_HANDLER_STORAGE_H
#define RS_HANDLER_STORAGE_H

evhtp_res storage_handle_head(evhtp_request_t *request);
evhtp_res storage_handle_get(evhtp_request_t *request);
evhtp_res storage_handle_put(evhtp_request_t *request);
evhtp_res storage_handle_delete(evhtp_request_t *request);

size_t json_buf_writer(char *buf, size_t count, void *arg);

#endif /* !RS_HANDLER_STORAGE_H */
