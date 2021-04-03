/*
 * iperf, Copyright (c) 2014-2021 The Regents of the University of
 * California, through Lawrence Berkeley National Laboratory (subject
 * to receipt of any required approvals from the U.S. Dept. of
 * Energy).  All rights reserved.
 *
 * If you have questions about your rights to use or distribute this
 * software, please contact Berkeley Lab's Technology Transfer
 * Department at TTD@lbl.gov.
 *
 * NOTICE.  This software is owned by the U.S. Department of Energy.
 * As such, the U.S. Government has been granted for itself and others
 * acting on its behalf a paid-up, nonexclusive, irrevocable,
 * worldwide license in the Software to reproduce, prepare derivative
 * works, and perform publicly and display publicly.  Beginning five
 * (5) years after the date permission to assert copyright is obtained
 * from the U.S. Department of Energy, and subject to any subsequent
 * five (5) year renewals, the U.S. Government is granted for itself
 * and others acting on its behalf a paid-up, nonexclusive,
 * irrevocable, worldwide license in the Software to reproduce,
 * prepare derivative works, distribute copies to the public, perform
 * publicly and display publicly, and to permit others to do so.
 *
 * This code is distributed under a BSD style license, see the LICENSE
 * file for complete information.
 */
/* iperf_server_api.c: Functions to be used by an iperf server
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include <sys/time.h>
#include <sys/resource.h>
#include <sched.h>
#include <setjmp.h>

#include "iperf.h"
#include "iperf_api.h"
#include "iperf_udp.h"
#include "iperf_tcp.h"
#include "iperf_util.h"
#include "timer.h"
#include "iperf_time.h"
#include "net.h"
#include "units.h"
#include "iperf_util.h"
#include "iperf_locale.h"

#if defined(HAVE_TCP_CONGESTION)
#if !defined(TCP_CA_NAME_MAX)
#define TCP_CA_NAME_MAX 16
#endif /* TCP_CA_NAME_MAX */
#endif /* HAVE_TCP_CONGESTION */

int
iperf_server_listen(struct iperf_test *test)
{
    retry:
    if((test->listener = netannounce(test->settings->domain, Ptcp, test->bind_address, test->bind_dev, test->server_port)) < 0) {
	if (errno == EAFNOSUPPORT && (test->settings->domain == AF_INET6 || test->settings->domain == AF_UNSPEC)) {
	    /* If we get "Address family not supported by protocol", that
	    ** probably means we were compiled with IPv6 but the running
	    ** kernel does not actually do IPv6.  This is not too unusual,
	    ** v6 support is and perhaps always will be spotty.
	    */
	    warning("this system does not seem to support IPv6 - trying IPv4");
	    test->settings->domain = AF_INET;
	    goto retry;
	} else {
	    i_errno = IELISTEN;
	    return -1;
	}
    }

    if (!test->json_output) {
        if (test->server_last_run_rc != 2)
            test->server_test_number +=1;
        if (test->debug || test->server_last_run_rc != 2) {
	    iperf_printf(test, "-----------------------------------------------------------\n");
	    iperf_printf(test, "Server listening on %d (test #%d)\n", test->server_port, test->server_test_number);
	    iperf_printf(test, "-----------------------------------------------------------\n");
	    if (test->forceflush)
	        iflush(test);
        }
    }

    FD_ZERO(&test->read_set);
    FD_ZERO(&test->write_set);
    FD_SET(test->listener, &test->read_set);
    if (test->listener > test->max_fd) test->max_fd = test->listener;

    return 0;
}

int
iperf_accept(struct iperf_test *test)
{
    int s;
    signed char rbuf = ACCESS_DENIED;
    socklen_t len;
    struct sockaddr_storage addr;

    fd_set read_set;
    int result, i, r, j;
    int sockets[MAX_SOCKETS_WAITING_FOR_COOKIE];
    int sockets_count = 0;
    int max_fd;
    struct timeval timeout;
    char cookies[MAX_SOCKETS_WAITING_FOR_COOKIE][COOKIE_SIZE];
    int cookies_sizes[MAX_SOCKETS_WAITING_FOR_COOKIE];
    struct iperf_time accept_time[MAX_SOCKETS_WAITING_FOR_COOKIE];
    struct iperf_time now, diff_time;
    int64_t cntl_msg_wait_us;

    if (test->verbose)
        iperf_printf(test, "First new connection is waiting\n");

    len = sizeof(addr);

    /* if test already active reject new connection */
    if (test->ctrl_sck != -1) {
        /* Not fail if send fails since socket may already be closed by the other end */
        if ((s = accept(test->listener, (struct sockaddr *) &addr, &len)) > 0) {
            /*
            * Don't try to read from the socket.  It could block an ongoing test. 
            * Just send ACCESS_DENIED.
            */
            if (test->verbose)
                 iperf_printf(test, "Rejecting new connection in busy running another test\n");
            Nwrite(s, (char*) &rbuf, sizeof(rbuf), Ptcp);
            close(s);
        }
        return 0;
    }

    /* Allow accepting more then one socket until valid cookie is received */
    if (setnonblocking(test->listener, 1) < 0) {
        i_errno = IESETBLOCKING;
        return -1;
    }

    /* Receive connections and get cookies until valid cookie is received.
     * Allows to overcome port scanning, etc. that create a session.
     */
    memset(cookies, 0, sizeof(cookies));
    memset(sockets, 0, sizeof(sockets));
    memset(cookies_sizes, 0, sizeof(cookies_sizes));
    cntl_msg_wait_us = (test->settings->cntl_msg_wait.secs * SEC_TO_US) + test->settings->cntl_msg_wait.usecs;
    while(test->ctrl_sck == -1) {

        /* Set timeout for next select to wait for short time */
        timeout.tv_sec = 0;
        timeout.tv_usec = 100000;

        memcpy(&read_set, &test->read_set, sizeof(fd_set));     // Listener FD
        for (max_fd = test->max_fd, j = 0; j < sockets_count; j++) {
            if (sockets[j] != 0) {
                FD_SET(sockets[j], &read_set);
                if (max_fd < sockets[j])
                    max_fd = sockets[j];
            }
        }
        result = select(max_fd + 1, &read_set, NULL, NULL, &timeout);
        if (result < 0 && errno != EINTR) {
            iperf_err(test, "Select while waiting for new connection or cookie failed on errno=%d\n", errno);
            i_errno = IESELECT;
            for (j = 0; j < sockets_count; j++) {
                if (sockets[j] != 0) {
                    Nwrite(sockets[j], (char*) &rbuf, sizeof(rbuf), Ptcp);
                    close(sockets[j]);
                }
            }
            return -1;

        } else if (result == 0) {
            /* If nothing was received for handling during the specified time
             * then make sure that there is at least one non-timedout active socket.
             */
            iperf_time_now(&now);
            for (i = 0, j = 0; j < sockets_count; j++) {
                if (sockets[j] != 0) {
                    iperf_time_diff(&now, &accept_time[j], &diff_time);
                    if (iperf_time_in_usecs(&diff_time) > cntl_msg_wait_us
                            || recv(sockets[j], NULL, 1, MSG_PEEK | MSG_DONTWAIT) == 0) {
                        if (test->verbose)
                            iperf_printf(test, "TCP socket %d is no longer active or timed out waiting for a cookie\n",
                                         sockets[j]);
                        close(sockets[j]);
                        sockets[j] = 0;
                    } else {
                        i++;    // Socket is still active
                    }
                }
            }
            if (i == 0) {   // No active socket
                if (test->verbose)
                    iperf_printf(test, "Terminating trying to connect to a client as no socket is active\n");
                return -1;
            }

        } else {    /* some action is required for listener */
            /* check if new connextion received */
            if ((s = accept(test->listener, (struct sockaddr *) &addr, &len)) < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    iperf_err(test, "Accept failed when checking if new connection request was received errno=%d\n", errno);
                    i_errno = IEACCEPT;
                    for (j = 0; j < sockets_count; j++) {
                        if (sockets[j] != 0) {
                            Nwrite(sockets[j], (char*) &rbuf, sizeof(rbuf), Ptcp);
                            close(sockets[j]);
                        }
                    }
                    return -1;
                }
            }

            if (s > 0) {
                if (test->verbose)
                    iperf_printf(test, "New connection was accepted with socket=%d\n", s);
                /* Ensure new socket is not already in the list */
                for (j = 0; j < sockets_count; j++) {
                    if (sockets[j] == s) {
                        sockets[j] = 0;
                        if (test->verbose)
                            iperf_printf(test, "New socket %d was erronously listed as already waiting for cookie\n", s);
                    }
                }

                if (sockets_count < MAX_SOCKETS_WAITING_FOR_COOKIE) {
                    /* Add socket and set to non-blocking to allow handling several sockets until getting valid cookie */
                    if (setnonblocking(s, 1) < 0) {
                        iperf_err(test, "Failed to set non-blocking for new accepted TCP connection with socket=%d\n", s);
                        close(s);
                    } else {
                        sockets[sockets_count] = s;
                        iperf_time_now(&accept_time[sockets_count]);
                        sockets_count++;
                        if (test->verbose)
                            iperf_printf(test, "Added Socket %d to list of sockets waiting for cookie; total sockets waiting for cookie=%d\n", s, sockets_count);
                    }
                } else {
                    /* Too many sockets waiting for cookie - probably something is wrong so close all */
                    if (test->verbose)
                        iperf_printf(test, "Too many sockets are in the waiting for cookie list. Closing all\n");
                    i_errno = IETOOMANYSOCKETS;
                    close(s);           
                    for (j = 0; j < sockets_count; j++) {
                        if (sockets[j] != 0) {
                            Nwrite(sockets[j], (char*) &rbuf, sizeof(rbuf), Ptcp);
                            close(sockets[j]);
                        }
                    }
                    return -1;
                }
            }

            /* Check if (some of) a cookie was rceived for any of the active sockets */
            for (i = 0; i < sockets_count && test->ctrl_sck == -1; i++) {
                if (sockets[i] > 0) {
                    if ((r = Nread(sockets[i], &cookies[i][cookies_sizes[i]], COOKIE_SIZE - cookies_sizes[i], Ptcp)) < 0) {
                        if (errno != EAGAIN && errno != EWOULDBLOCK) {
                            iperf_err(test, "Failed reading cookie - ignoring socket=%d, errno=%d\n", sockets[i], errno);
                            close(sockets[i]);
                            sockets[i] = 0;
                        }
                    } else {    // Received (some of) a cookie
                        cookies_sizes[i] += r;
                        if (test->verbose && r > 0)
                            iperf_printf(test, "(Partial) cookie read for socket=%d, len=%d\n", sockets[i], cookies_sizes[i]);
                        /* if full valid cookie was received set the socket as the control socket
                           * and reject all other sockets */
                        if (cookies_sizes[i] == COOKIE_SIZE) {
                            if (validate_cookie(cookies[i]) != 0) {
                                // Cookie is not valid - close the socket
                                if (test->verbose)
                                    iperf_printf(test, "Cookie is not valid, closing socket=%d, cookie=%s\n", sockets[i], cookies[i]);
                                close(sockets[i]);
                                sockets[i] = 0;
                            } else {
                                // Valid cookie - set its session as the control one
                                if (test->verbose)
                                    iperf_printf(test, "Valid cookie was received for socket=%d\n", sockets[i]);
                                for (j = 0; j < sockets_count; j++) {   // Close other active sockets
                                    if (j != i && sockets[j] != 0) {
                                        Nwrite(sockets[j], (char*) &rbuf, sizeof(rbuf), Ptcp);
                                        close(sockets[j]);
                                    }
                                }
                                if (setnonblocking(sockets[i], 0) < 0) {    // Reset socket to BLOCKING
                                    i_errno = IESETBLOCKING;
                                    close(sockets[i]);
                                    return -1;
                                }
                                if (test->verbose)
                                    iperf_printf(test, "Test control channel is set to socket=%d\n", sockets[i]);
                                test->ctrl_sck = sockets[i];
                                strncpy(test->cookie, cookies[i], COOKIE_SIZE);
                            }
                        }
                    }
                }
            }
        } // end else select
    } // end while

    if (test->verbose)
        iperf_printf(test, "Setting test control %d in test list of select FDs\n", test->ctrl_sck);
    FD_SET(test->ctrl_sck, &test->read_set);
    if (test->ctrl_sck > test->max_fd) test->max_fd = test->ctrl_sck;

    if (iperf_set_send_state(test, PARAM_EXCHANGE) != 0)
        return -1;
    if (iperf_exchange_parameters(test) < 0)
        return -1;
    if (test->server_affinity != -1) 
        if (iperf_setaffinity(test, test->server_affinity) != 0)
            return -1;
    if (test->on_connect)
        test->on_connect(test);

    return 0;
}


/**************************************************************************/
int
iperf_handle_message_server(struct iperf_test *test)
{
    int rval;
    struct iperf_stream *sp;

    // XXX: Need to rethink how this behaves to fit API
    if ((rval = Nread(test->ctrl_sck, (char*) &test->state, sizeof(signed char), Ptcp)) <= 0) {
        if (test->verbose)
            iperf_printf(test, "Failed reading state message from client - read return=%d, errno=%d\n", rval, errno);

        if (rval == 0) {
	    iperf_err(test, "the client has unexpectedly closed the connection");
            i_errno = IECTRLCLOSE;
            test->state = IPERF_DONE;
            return 0;
        } else {
            i_errno = IERECVMESSAGE;
            return -1;
        }
    }

    switch(test->state) {
        case TEST_START:
            break;
        case TEST_END:
	    test->done = 1;
            cpu_util(test->cpu_util);
            test->stats_callback(test);
            SLIST_FOREACH(sp, &test->streams, streams) {
                FD_CLR(sp->socket, &test->read_set);
                FD_CLR(sp->socket, &test->write_set);
                close(sp->socket);
            }
            test->reporter_callback(test);
	    if (iperf_set_send_state(test, EXCHANGE_RESULTS) != 0)
                return -1;
            if (iperf_exchange_results(test) < 0)
                return -1;
	    if (iperf_set_send_state(test, DISPLAY_RESULTS) != 0)
                return -1;
            if (test->on_test_finish)
                test->on_test_finish(test);
            break;
        case IPERF_DONE:
            break;
        case CLIENT_TERMINATE:
            i_errno = IECLIENTTERM;

	    // Temporarily be in DISPLAY_RESULTS phase so we can get
	    // ending summary statistics.
	    signed char oldstate = test->state;
	    cpu_util(test->cpu_util);
	    test->state = DISPLAY_RESULTS;
	    test->reporter_callback(test);
	    test->state = oldstate;

            // XXX: Remove this line below!
	    iperf_err(test, "the client has terminated");
            SLIST_FOREACH(sp, &test->streams, streams) {
                FD_CLR(sp->socket, &test->read_set);
                FD_CLR(sp->socket, &test->write_set);
                close(sp->socket);
            }
            test->state = IPERF_DONE;
            break;
        default:
            i_errno = IEMESSAGE;
            return -1;
    }

    return 0;
}

static void
server_timer_proc(TimerClientData client_data, struct iperf_time *nowP)
{
    struct iperf_test *test = client_data.p;
    struct iperf_stream *sp;

    test->timer = NULL;
    if (test->done)
        return;
    test->done = 1;
    /* Free streams */
    while (!SLIST_EMPTY(&test->streams)) {
        sp = SLIST_FIRST(&test->streams);
        SLIST_REMOVE_HEAD(&test->streams, streams);
        close(sp->socket);
        iperf_free_stream(sp);
    }
    close(test->ctrl_sck);
}

static void
server_stats_timer_proc(TimerClientData client_data, struct iperf_time *nowP)
{
    struct iperf_test *test = client_data.p;

    if (test->done)
        return;
    if (test->stats_callback)
	test->stats_callback(test);
}

static void
server_reporter_timer_proc(TimerClientData client_data, struct iperf_time *nowP)
{
    struct iperf_test *test = client_data.p;

    if (test->done)
        return;
    if (test->reporter_callback)
	test->reporter_callback(test);
}

static int
create_server_timers(struct iperf_test * test)
{
    struct iperf_time now;
    TimerClientData cd;
    int max_rtt = 4; /* seconds */
    int state_transitions = 10; /* number of state transitions in iperf3 */
    int grace_period = max_rtt * state_transitions;

    if (iperf_time_now(&now) < 0) {
	i_errno = IEINITTEST;
	return -1;
    }
    cd.p = test;
    test->timer = test->stats_timer = test->reporter_timer = NULL;
    if (test->duration != 0 ) {
        test->done = 0;
        test->timer = tmr_create(&now, server_timer_proc, cd, (test->duration + test->omit + grace_period) * SEC_TO_US, 0);
        if (test->timer == NULL) {
            i_errno = IEINITTEST;
            return -1;
        }
    }

    test->stats_timer = test->reporter_timer = NULL;
    if (test->stats_interval != 0) {
        test->stats_timer = tmr_create(&now, server_stats_timer_proc, cd, test->stats_interval * SEC_TO_US, 1);
        if (test->stats_timer == NULL) {
            i_errno = IEINITTEST;
            return -1;
	}
    }
    if (test->reporter_interval != 0) {
        test->reporter_timer = tmr_create(&now, server_reporter_timer_proc, cd, test->reporter_interval * SEC_TO_US, 1);
        if (test->reporter_timer == NULL) {
            i_errno = IEINITTEST;
            return -1;
	}
    }
    return 0;
}

static void
server_omit_timer_proc(TimerClientData client_data, struct iperf_time *nowP)
{   
    struct iperf_test *test = client_data.p;

    test->omit_timer = NULL;
    test->omitting = 0;
    iperf_reset_stats(test);
    if (test->verbose && !test->json_output && test->reporter_interval == 0)
	iperf_printf(test, "%s", report_omit_done);

    /* Reset the timers. */
    if (test->stats_timer != NULL)
	tmr_reset(nowP, test->stats_timer);
    if (test->reporter_timer != NULL)
	tmr_reset(nowP, test->reporter_timer);
}

static int
create_server_omit_timer(struct iperf_test * test)
{
    struct iperf_time now;
    TimerClientData cd; 

    if (test->omit == 0) {
	test->omit_timer = NULL;
	test->omitting = 0;
    } else {
	if (iperf_time_now(&now) < 0) {
	    i_errno = IEINITTEST;
	    return -1; 
	}
	test->omitting = 1;
	cd.p = test;
	test->omit_timer = tmr_create(&now, server_omit_timer_proc, cd, test->omit * SEC_TO_US, 0); 
	if (test->omit_timer == NULL) {
	    i_errno = IEINITTEST;
	    return -1;
	}
    }

    return 0;
}

static void
cleanup_server(struct iperf_test *test)
{
    struct iperf_stream *sp;

    /* Close open streams */
    SLIST_FOREACH(sp, &test->streams, streams) {
	FD_CLR(sp->socket, &test->read_set);
	FD_CLR(sp->socket, &test->write_set);
	close(sp->socket);
    }

    /* Close open test sockets */
    if (test->ctrl_sck > 0) {
	close(test->ctrl_sck);
    }
    if (test->listener) {
	close(test->listener);
    }
    if (test->prot_listener > -1) {     // May remain open if create socket failed
	close(test->prot_listener);
    }

    /* Cancel any remaining timers. */
    if (test->stats_timer != NULL) {
	tmr_cancel(test->stats_timer);
	test->stats_timer = NULL;
    }
    if (test->reporter_timer != NULL) {
	tmr_cancel(test->reporter_timer);
	test->reporter_timer = NULL;
    }
    if (test->omit_timer != NULL) {
	tmr_cancel(test->omit_timer);
	test->omit_timer = NULL;
    }
    if (test->congestion_used != NULL) {
        free(test->congestion_used);
	test->congestion_used = NULL;
    }
    if (test->timer != NULL) {
        tmr_cancel(test->timer);
        test->timer = NULL;
    }
}


int
iperf_run_server(struct iperf_test *test)
{
    int result, s;
    int send_streams_accepted, rec_streams_accepted;
    int streams_to_send = 0, streams_to_rec = 0;
#if defined(HAVE_TCP_CONGESTION)
    int saved_errno;
#endif /* HAVE_TCP_CONGESTION */
    fd_set read_set, write_set;
    struct iperf_stream *sp;
    struct iperf_time now;
    struct iperf_time last_receive_time;
    struct iperf_time diff_time;
    struct timeval* timeout;
    struct timeval used_timeout;
    int flag;
    int64_t t_usecs;
    int64_t timeout_us;
    int64_t rcv_timeout_us, cntl_msg_wait_us, current_data_rcv_timeout_us;
    int first_data_message_to_receive;

    if (test->logfile)
        if (iperf_open_logfile(test) < 0)
            return -1;

    if (test->affinity != -1) 
	if (iperf_setaffinity(test, test->affinity) != 0)
	    return -2;

    if (test->json_output)
	if (iperf_json_start(test) < 0)
	    return -2;

    if (test->json_output) {
	cJSON_AddItemToObject(test->json_start, "version", cJSON_CreateString(version));
	cJSON_AddItemToObject(test->json_start, "system_info", cJSON_CreateString(get_system_info()));
    } else if (test->verbose) {
	iperf_printf(test, "%s\n", version);
	iperf_printf(test, "%s", "");
	iperf_printf(test, "%s\n", get_system_info());
	iflush(test);
    }

    // Open socket and listen
    if (iperf_server_listen(test) < 0) {
        return -2;
    }

    iperf_time_now(&last_receive_time); // Initialize last time something was received

    test->state = IPERF_START;
    send_streams_accepted = 0;
    rec_streams_accepted = 0;
    rcv_timeout_us = (test->settings->rcv_timeout.secs * SEC_TO_US) + test->settings->rcv_timeout.usecs;
    cntl_msg_wait_us = (test->settings->cntl_msg_wait.secs * SEC_TO_US) + test->settings->cntl_msg_wait.usecs;

    current_data_rcv_timeout_us = cntl_msg_wait_us;
    first_data_message_to_receive = 2;

    while (test->state != IPERF_DONE) {

        // Check if average transfer rate was exceeded (condition set in the callback routines)
	if (test->bitrate_limit_exceeded) {
	    cleanup_server(test);
            i_errno = IETOTALRATE;
            return -1;	
	}

        memcpy(&read_set, &test->read_set, sizeof(fd_set));
        memcpy(&write_set, &test->write_set, sizeof(fd_set));

	iperf_time_now(&now);
	timeout = tmr_timeout(&now);

        // Ensure select() will timeout to allow handling error cases that require server restart
        if (test->state == IPERF_START) {  // While waiting for connection - do not let server get stack forever
            if (timeout == NULL && test->settings->idle_timeout > 0) {
                used_timeout.tv_sec = test->settings->idle_timeout;
                used_timeout.tv_usec = 0;
                timeout = &used_timeout;
            }
        } else if (test->state != TEST_RUNNING) { // While not yet in active test - do not let server get stack forever
            used_timeout.tv_sec = test->settings->cntl_msg_wait.secs;
            used_timeout.tv_usec = test->settings->cntl_msg_wait.usecs;
            timeout = &used_timeout;
        } else if (test->mode != SENDER) { // TEST_RUNNING - in non-reverse mode server ensures data is received
            timeout_us = -1;
            if (timeout != NULL) {
                used_timeout.tv_sec = timeout->tv_sec;
                used_timeout.tv_usec = timeout->tv_usec;
                timeout_us = (timeout->tv_sec * SEC_TO_US) + timeout->tv_usec;
            }
            if (timeout_us < 0 || timeout_us > rcv_timeout_us) {
                if (first_data_message_to_receive > 0) { // Timeout for first data message should be as for control message
                    if (timeout_us > cntl_msg_wait_us) {
                        used_timeout.tv_sec = test->settings->cntl_msg_wait.secs;
                        used_timeout.tv_usec = test->settings->cntl_msg_wait.usecs;
                        current_data_rcv_timeout_us = cntl_msg_wait_us;
                    }
                } else { // Timeout for non-first data messages are as defined for data messages 
                    used_timeout.tv_sec = test->settings->rcv_timeout.secs;
                    used_timeout.tv_usec = test->settings->rcv_timeout.usecs;
                    current_data_rcv_timeout_us = rcv_timeout_us;
                }
            }
            timeout = &used_timeout;
        }

        result = select(test->max_fd + 1, &read_set, &write_set, NULL, timeout);
        if (result < 0 && errno != EINTR) {
            cleanup_server(test);
            i_errno = IESELECT;
            return -1;
        } else if (result == 0) {
            // If nothing was received during the specified timeout (per state)
            // then probably something got stack either at the client, server or network,
            // and Test should be forced to end.
            iperf_time_now(&now);
            t_usecs = 0;
            if (iperf_time_diff(&now, &last_receive_time, &diff_time) == 0) {
                t_usecs = iperf_time_in_usecs(&diff_time);
                if (test->state == IPERF_START) {
                    if (test->settings->idle_timeout > 0 && t_usecs >= test->settings->idle_timeout * SEC_TO_US) {
                        test->server_forced_idle_restarts_count += 1;
                        if (test->debug)
                            printf("Server restart (#%d) in idle state as no connection request was received for %lld sec\n",
                                test->server_forced_idle_restarts_count, t_usecs/SEC_TO_US);
                        cleanup_server(test);
                        return 2;
                    }
                } else if (test->state != TEST_RUNNING) {
                    if (t_usecs >= cntl_msg_wait_us) {
                        test->server_forced_no_msg_restarts_count += 1;
                        i_errno = IENOCNTLMSG;
                        if (iperf_get_verbose(test))
                            printf("Server restart (#%d) while init a test since no message was received for %lld sec\n",
                                test->server_forced_idle_restarts_count, t_usecs/SEC_TO_US);
                        cleanup_server(test);
                        return -1;
                    }
                } else if (test->mode != SENDER && t_usecs >= current_data_rcv_timeout_us) { // TEST_RUNNING
                    test->server_forced_no_msg_restarts_count += 1;
                    i_errno = IENOMSG;
                    if (iperf_get_verbose(test))
                        iperf_err(test, "Server restart (#%d) during active test since no message was received for %ld ms\n",
                                  test->server_forced_no_msg_restarts_count, t_usecs/mS_TO_US);
                    cleanup_server(test);
                    return -1;
                }
            }    
        }

	if (result > 0) {
            iperf_time_now(&last_receive_time);
            if (FD_ISSET(test->listener, &read_set)) {
                if (test->state != CREATE_STREAMS) {
                    if (iperf_accept(test) < 0) {
                        cleanup_server(test);
                        return -1;
                    }
                    FD_CLR(test->listener, &read_set);

                    // Set streams number
                    if (test->mode == BIDIRECTIONAL) {
                        streams_to_send = test->num_streams;
                        streams_to_rec = test->num_streams;
                    } else if (test->mode == RECEIVER) {
                        streams_to_rec = test->num_streams;
                        streams_to_send = 0;
                    } else {
                        streams_to_send = test->num_streams;
                        streams_to_rec = 0;
                    }
                }
            }
            if (FD_ISSET(test->ctrl_sck, &read_set)) {
                if (iperf_handle_message_server(test) < 0) {
                    cleanup_server(test);
                    return -1;
		}
                FD_CLR(test->ctrl_sck, &read_set);                
            }

            if (test->state == CREATE_STREAMS) {
                if (FD_ISSET(test->prot_listener, &read_set)) {
    
                    if ((s = test->protocol->accept(test)) < 0) {
                        cleanup_server(test);
                        return -1;
                    }

                    if (!is_closed(s)) {

#if defined(HAVE_TCP_CONGESTION)
                        if (test->protocol->id == Ptcp) {
                            if (test->congestion) {
                                if (setsockopt(s, IPPROTO_TCP, TCP_CONGESTION, test->congestion, strlen(test->congestion)) < 0) {
                                    /*
                                    * ENOENT means we tried to set the
                                    * congestion algorithm but the algorithm
                                    * specified doesn't exist.  This can happen
                                    * if the client and server have different
                                    * congestion algorithms available.  In this
                                    * case, print a warning, but otherwise
                                    * continue.
                                    */
                                    if (errno == ENOENT) {
                                        warning("TCP congestion control algorithm not supported");
                                    }
                                    else {
                                        saved_errno = errno;
                                        close(s);
                                        cleanup_server(test);
                                        errno = saved_errno;
                                        i_errno = IESETCONGESTION;
                                        return -1;
                                    }
                                } 
                            }
                            {
                                socklen_t len = TCP_CA_NAME_MAX;
                                char ca[TCP_CA_NAME_MAX + 1];
                                if (getsockopt(s, IPPROTO_TCP, TCP_CONGESTION, ca, &len) < 0) {
                                    saved_errno = errno;
                                    close(s);
                                    cleanup_server(test);
                                    errno = saved_errno;
                                    i_errno = IESETCONGESTION;
                                    return -1;
                                }
                                /* 
                                * If not the first connection, discard prior
                                * congestion algorithm name so we don't leak
                                * duplicated strings.  We probably don't need
                                * the old string anyway.
                                */
                                if (test->congestion_used != NULL) {
                                    free(test->congestion_used);
                                }
                                test->congestion_used = strdup(ca);
                                if (test->debug) {
                                    printf("Congestion algorithm is %s\n", test->congestion_used);
                                }
                            }
                        }
#endif /* HAVE_TCP_CONGESTION */

                        if (rec_streams_accepted != streams_to_rec) {
                            flag = 0;
                            ++rec_streams_accepted;
                        } else if (send_streams_accepted != streams_to_send) {
                            flag = 1;
                            ++send_streams_accepted;
                        }

                        if (flag != -1) {
                            sp = iperf_new_stream(test, s, flag);
                            if (!sp) {
                                cleanup_server(test);
                                return -1;
                            }

                            if (sp->sender)
                                FD_SET(s, &test->write_set);
                            else
                                FD_SET(s, &test->read_set);

                            if (s > test->max_fd) test->max_fd = s;

                            /*
                             * If the protocol isn't UDP, or even if it is but
                             * we're the receiver, set nonblocking sockets.
                             * We need this to allow a server receiver to
                             * maintain interactivity with the control channel.
                             */
                            if (test->protocol->id != Pudp ||
                                !sp->sender) {
                                setnonblocking(s, 1);
                            }

                            if (test->on_new_stream)
                                test->on_new_stream(sp);

                            flag = -1;
                        }
                    }
                    FD_CLR(test->prot_listener, &read_set);
                }


                if (rec_streams_accepted == streams_to_rec && send_streams_accepted == streams_to_send) {
                    if (test->protocol->id != Ptcp) {
                        FD_CLR(test->prot_listener, &test->read_set);
                        close(test->prot_listener);
                    } else { 
                        if (test->no_delay || test->settings->mss || test->settings->socket_bufsize) {
                            FD_CLR(test->listener, &test->read_set);
                            close(test->listener);
			    test->listener = 0;
                            if ((s = netannounce(test->settings->domain, Ptcp, test->bind_address, test->bind_dev, test->server_port)) < 0) {
                                cleanup_server(test);
                                i_errno = IELISTEN;
                                return -1;
                            }
                            test->listener = s;
                            FD_SET(test->listener, &test->read_set);
			    if (test->listener > test->max_fd) test->max_fd = test->listener;
                        }
                    }
                    test->prot_listener = -1;

		    /* Ensure that total requested data rate is not above limit */
		    iperf_size_t total_requested_rate = test->num_streams * test->settings->rate * (test->mode == BIDIRECTIONAL? 2 : 1);
		    if (test->settings->bitrate_limit > 0 && total_requested_rate > test->settings->bitrate_limit) {
                        if (iperf_get_verbose(test))
                            iperf_err(test, "Client total requested throughput rate of %" PRIu64 " bps exceeded %" PRIu64 " bps limit",
                                      total_requested_rate, test->settings->bitrate_limit);
			cleanup_server(test);
			i_errno = IETOTALRATE;
			return -1;
		    }

		    // Begin calculating CPU utilization
		    cpu_util(NULL);

		    if (iperf_set_send_state(test, TEST_START) != 0) {
			cleanup_server(test);
                        return -1;
		    }
                    if (iperf_init_test(test) < 0) {
			cleanup_server(test);
                        return -1;
		    }
		    if (create_server_timers(test) < 0) {
			cleanup_server(test);
                        return -1;
		    }
		    if (create_server_omit_timer(test) < 0) {
			cleanup_server(test);
                        return -1;
		    }
		    if (test->mode != RECEIVER)
			if (iperf_create_send_timers(test) < 0) {
			    cleanup_server(test);
			    return -1;
			}
		    if (iperf_set_send_state(test, TEST_RUNNING) != 0) {
			cleanup_server(test);
                        return -1;
		    }
                    iperf_time_now(&last_receive_time); // Re-init last time something was received when test starts
                }
            }

            if (test->state == TEST_RUNNING) {
                if (first_data_message_to_receive > 0) {
                    first_data_message_to_receive--;
                }
                if (test->mode == BIDIRECTIONAL) {
                    if (iperf_recv(test, &read_set) < 0) {
                        cleanup_server(test);
                        return -1;
                    }
                    if (iperf_send(test, &write_set) < 0) {
                        cleanup_server(test);
                        return -1;
                    }
                } else if (test->mode == SENDER) {
                    // Reverse mode. Server sends.
                    if (iperf_send(test, &write_set) < 0) {
			cleanup_server(test);
                        return -1;
		    }
                } else {
                    // Regular mode. Server receives.
                    if (iperf_recv(test, &read_set) < 0) {
			cleanup_server(test);
                        return -1;
		    }
                }
	    }
        }

	if (result == 0 ||
	    (timeout != NULL && timeout->tv_sec == 0 && timeout->tv_usec == 0)) {
	    /* Run the timers. */
	    iperf_time_now(&now);
	    tmr_run(&now);
	}
    }

    cleanup_server(test);

    if (test->json_output) {
	if (iperf_json_finish(test) < 0)
	    return -1;
    } 

    iflush(test);

    if (test->server_affinity != -1) 
	if (iperf_clearaffinity(test) != 0)
	    return -1;

    return 0;
}
