/***
  This file is part of PulseAudio.

  Copyright 2013 João Paulo Rechi Vita

  PulseAudio is free software; you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation; either version 2.1 of the
  License, or (at your option) any later version.

  PulseAudio is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with PulseAudio; if not, see <http://www.gnu.org/licenses/>.
***/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <poll.h>

#include <pulsecore/core-util.h>
#include <pulsecore/dbus-shared.h>
#include <pulsecore/shared.h>
#include <pulsecore/core-error.h>

#include "bluez5-util.h"

#define HFP_AUDIO_CODEC_CVSD    0x01
#define HFP_AUDIO_CODEC_MSBC    0x02

#define OFONO_SERVICE "org.ofono"
#define HF_AUDIO_AGENT_INTERFACE OFONO_SERVICE ".HandsfreeAudioAgent"
#define HF_AUDIO_MANAGER_INTERFACE OFONO_SERVICE ".HandsfreeAudioManager"
#define HF_AUDIO_CARD_INTERFACE OFONO_SERVICE ".HandsfreeAudioCard"

#define HF_AUDIO_AGENT_PATH "/HandsfreeAudioAgent"

#define HF_AUDIO_AGENT_XML                                          \
    DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE                       \
    "<node>"                                                        \
    "  <interface name=\"org.freedesktop.DBus.Introspectable\">"    \
    "    <method name=\"Introspect\">"                              \
    "      <arg direction=\"out\" type=\"s\" />"                    \
    "    </method>"                                                 \
    "  </interface>"                                                \
    "  <interface name=\"org.ofono.HandsfreeAudioAgent\">"          \
    "    <method name=\"Release\">"                                 \
    "    </method>"                                                 \
    "    <method name=\"NewConnection\">"                           \
    "      <arg direction=\"in\"  type=\"o\" name=\"card_path\" />" \
    "      <arg direction=\"in\"  type=\"h\" name=\"sco_fd\" />"    \
    "      <arg direction=\"in\"  type=\"y\" name=\"codec\" />"     \
    "    </method>"                                                 \
    "  </interface>"                                                \
    "</node>"

struct hf_audio_card {
    pa_bluetooth_backend *backend;
    char *path;
    char *remote_address;
    char *local_address;

    int fd;
    uint8_t codec;

    pa_bluetooth_transport *transport;
};

struct pa_bluetooth_backend {
    pa_core *core;
    pa_bluetooth_discovery *discovery;
    pa_dbus_connection *connection;
    pa_hashmap *cards;
    char *ofono_bus_id;

    PA_LLIST_HEAD(pa_dbus_pending, pending);
};

static pa_dbus_pending* hf_dbus_send_and_add_to_pending(pa_bluetooth_backend *backend, DBusMessage *m,
                                                    DBusPendingCallNotifyFunction func, void *call_data) {
    pa_dbus_pending *p;
    DBusPendingCall *call;

    pa_assert(backend);
    pa_assert(m);

    pa_assert_se(dbus_connection_send_with_reply(pa_dbus_connection_get(backend->connection), m, &call, -1));

    p = pa_dbus_pending_new(pa_dbus_connection_get(backend->connection), m, call, backend, call_data);
    PA_LLIST_PREPEND(pa_dbus_pending, backend->pending, p);
    dbus_pending_call_set_notify(call, func, p, NULL);

    return p;
}

static struct hf_audio_card *hf_audio_card_new(pa_bluetooth_backend *backend, const char *path) {
    struct hf_audio_card *card = pa_xnew0(struct hf_audio_card, 1);

    card->path = pa_xstrdup(path);
    card->backend = backend;
    card->fd = -1;

    return card;
}

static void hf_audio_card_free(struct hf_audio_card *card) {
    pa_assert(card);

    if (card->transport)
        pa_bluetooth_transport_free(card->transport);

    pa_xfree(card->path);
    pa_xfree(card->remote_address);
    pa_xfree(card->local_address);
    pa_xfree(card);
}

static int socket_accept(int sock)
{
    char c;
    struct pollfd pfd;

    if (sock < 0)
        return -ENOTCONN;

    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = sock;
    pfd.events = POLLOUT;

    if (poll(&pfd, 1, 0) < 0)
        return -errno;

    /*
     * If socket already writable then it is not in defer setup state,
     * otherwise it needs to be read to authorize the connection.
     */
    if ((pfd.revents & POLLOUT))
        return 0;

    /* Enable socket by reading 1 byte */
    if (read(sock, &c, 1) < 0)
        return -errno;

    return 0;
}

static int hf_audio_agent_transport_acquire(pa_bluetooth_transport *t, bool optional, size_t *imtu, size_t *omtu) {
    struct hf_audio_card *card = t->userdata;
    struct linger l;
    int err;

    pa_assert(card);

    if (!optional) {
        DBusMessage *m, *r;
        DBusDispatchStatus dispatch_status = DBUS_DISPATCH_DATA_REMAINS;

        pa_log_debug("Acquiring transport from ofono for card %s",
                     card->path);

        pa_assert_se(m = dbus_message_new_method_call(t->owner, t->path, "org.ofono.HandsfreeAudioCard", "Connect"));

        /* We need to block here for the reply as otherwise we wouldn't fit
         * into the what is expected from us when we return. */
        r = dbus_connection_send_with_reply_and_block(pa_dbus_connection_get(card->backend->connection), m, -1, NULL);
        if (!r) {
            pa_log_error("Failed to connect remote handsfree audio card for transport at %s", t->path);
            return -1;
        }

        pa_log_debug("Handsfree audio card %s got connected", card->path);

        /* Dispatch all incoming messages as we should have received the
         * NewConnection one on our HandsfreeAgent interface already at
         * this point. */
        while (dispatch_status != DBUS_DISPATCH_COMPLETE) {
            pa_log_debug("Dispatching all outstanding dbus messages ...");

            dispatch_status = dbus_connection_dispatch(pa_dbus_connection_get(card->backend->connection));

            if (card->fd > 0)
                break;
        }

        if (card->fd < 0) {
            pa_log_warn("Didn't got a connection shared from ofono yet");
            return -1;
        }

        pa_log_debug("Setting up SCO connection (fd %u) for card %s",
                     card->fd, card->path);

        err = socket_accept(card->fd);
        if (err < 0) {
            pa_log_error("Deferred setup failed on fd %d: %s", card->fd, pa_cstrerror(-err));

            close(card->fd);
            card->fd = -1;

            return -1;
        }

        /* Set SO_LINGER in order to make sure the file descriptor is
         * closed directly and not some time after we called close on
         * it. This is necessary in order to keep control over the
         * point where we can setup the next audio connection to the
         * remote device. */
        l.l_onoff = 1;
        l.l_linger = 1;
        err = setsockopt(card->fd, SOL_SOCKET, SO_LINGER, &l, sizeof(l));
        if (err < 0)
            pa_log_error("Failed to set SO_LINGER for card %s fd %d", card->path, card->fd);

        return card->fd;
    }

    /* The correct block size should take into account the SCO MTU from
     * the Bluetooth adapter and (for adapters in the USB bus) the MxPS
     * value from the Isoc USB endpoint in use by btusb and should be
     * made available to userspace by the Bluetooth kernel subsystem.
     * Meanwhile the empiric value 48 will be used. */
    if (imtu)
        *imtu = 48;
    if (omtu)
        *omtu = 48;

    t->codec = card->codec;

    err = socket_accept(card->fd);
    if (err < 0) {
        pa_log_error("Deferred setup failed on fd %d: %s", card->fd, pa_cstrerror(-err));
        close(card->fd);
        card->fd = -1;
        return -1;
    }

    return card->fd;
}

static void hf_audio_agent_transport_release(pa_bluetooth_transport *t) {
    struct hf_audio_card *card = t->userdata;

    pa_assert(card);

    pa_log_debug("Trying to release transport for card %s (fd %d)",
                 card->path, card->fd);

    if (t->state <= PA_BLUETOOTH_TRANSPORT_STATE_IDLE) {
        pa_log_info("Transport %s already released", t->path);
        return;
    }

    if (card->fd > 0) {
        pa_log_debug("Transport available for card %s (fd %d), releasing now",
                 card->path, card->fd);

        /* shutdown to make sure connection is dropped immediately */
        shutdown(card->fd, SHUT_RDWR);
        close(card->fd);
        card->fd = -1;

        pa_log_debug("Successfully released transport for card %s", card->path);

        pa_bluetooth_transport_set_state(t, PA_BLUETOOTH_TRANSPORT_STATE_IDLE);
    }
}

static void set_property(pa_dbus_connection *conn, const char *bus, const char *path, const char *interface,
                         const char *prop_name, int prop_type, void *prop_value) {
    DBusMessage *m;
    DBusMessageIter i;

    pa_assert(conn);
    pa_assert(path);
    pa_assert(interface);
    pa_assert(prop_name);

    pa_assert_se(m = dbus_message_new_method_call(bus, path, interface, "SetProperty"));
    dbus_message_iter_init_append(m, &i);
    dbus_message_iter_append_basic(&i, DBUS_TYPE_STRING, &prop_name);
    pa_dbus_append_basic_variant(&i, prop_type, prop_value);

    dbus_message_set_no_reply(m, true);
    pa_assert_se(dbus_connection_send(pa_dbus_connection_get(conn), m, NULL));
    dbus_message_unref(m);
}

static void hf_audio_card_set_speaker_gain(pa_bluetooth_transport *t, uint16_t gain)
{
    struct hf_audio_card *card = t->userdata;

    pa_assert(card);

    pa_log_debug("Setting speaker gain for card %s to %u",
                 card->path, gain);

    set_property(card->backend->connection, OFONO_SERVICE, card->path,
                 HF_AUDIO_CARD_INTERFACE, "SpeakerGain", DBUS_TYPE_UINT16, &gain);
}

static void hf_audio_card_set_microphone_gain(pa_bluetooth_transport *t, uint16_t gain)
{
    struct hf_audio_card *card = t->userdata;

    pa_assert(card);

    pa_log_debug("Setting microphone gain for card %s to %u",
                 card->path, gain);

    set_property(card->backend->connection, OFONO_SERVICE, card->path,
                 HF_AUDIO_CARD_INTERFACE, "MicrophoneGain", DBUS_TYPE_UINT16, &gain);
}

static void hf_audio_agent_card_found(pa_bluetooth_backend *backend, const char *path, DBusMessageIter *props_i) {
    DBusMessageIter i, value_i;
    const char *key, *value;
    struct hf_audio_card *card;
    pa_bluetooth_device *d;
    pa_bluetooth_profile_t profile = PA_BLUETOOTH_PROFILE_HEADSET_AUDIO_GATEWAY;

    pa_assert(backend);
    pa_assert(path);
    pa_assert(props_i);

    pa_log_debug("New HF card found: %s", path);

    card = hf_audio_card_new(backend, path);

    while (dbus_message_iter_get_arg_type(props_i) != DBUS_TYPE_INVALID) {
        char c;

        dbus_message_iter_recurse(props_i, &i);

        dbus_message_iter_get_basic(&i, &key);
        dbus_message_iter_next(&i);
        dbus_message_iter_recurse(&i, &value_i);

        if ((c = dbus_message_iter_get_arg_type(&value_i)) == DBUS_TYPE_STRING) {
            dbus_message_iter_get_basic(&value_i, &value);

            if (pa_streq(key, "Type")) {
                if (pa_streq(value, "gateway"))
                    profile = PA_BLUETOOTH_PROFILE_HEADSET_HEAD_UNIT;
                else if (pa_streq(value, "handsfree"))
                    profile = PA_BLUETOOTH_PROFILE_HEADSET_AUDIO_GATEWAY;
            } else if (pa_streq(key, "RemoteAddress")) {
                pa_xfree(card->remote_address);
                card->remote_address = pa_xstrdup(value);
            } else if (pa_streq(key, "LocalAddress")) {
                pa_xfree(card->local_address);
                card->local_address = pa_xstrdup(value);
            }

            pa_log_debug("%s: %s", key, value);

        } else if ((c = dbus_message_iter_get_arg_type(&value_i)) == DBUS_TYPE_UINT16) {
            /* Ignore for now */
        } else {
            pa_log_error("Invalid properties for %s: expected 's' or 'q', received '%c'", path, c);
        }

        dbus_message_iter_next(props_i);
    }

    d = pa_bluetooth_discovery_get_device_by_address(backend->discovery, card->remote_address, card->local_address);
    if (!d) {
        pa_log_error("Device doesnt exist for %s", path);
        goto fail;
    }

    card->transport = pa_bluetooth_transport_new(d, backend->ofono_bus_id, path, profile, NULL, 0);
    card->transport->acquire = hf_audio_agent_transport_acquire;
    card->transport->release = hf_audio_agent_transport_release;
    card->transport->set_speaker_gain = hf_audio_card_set_speaker_gain;
    card->transport->set_microphone_gain = hf_audio_card_set_microphone_gain;
    card->transport->userdata = card;

    pa_bluetooth_transport_put(card->transport);
    pa_hashmap_put(backend->cards, card->path, card);

    return;

fail:
    hf_audio_card_free(card);
}

static void hf_audio_agent_card_removed(pa_bluetooth_backend *backend, const char *path) {
    struct hf_audio_card *card;

    pa_assert(backend);
    pa_assert(path);

    pa_log_debug("HF card removed: %s", path);

    card = pa_hashmap_remove(backend->cards, path);
    if (!card)
        return;

    hf_audio_card_free(card);
}

static void hf_audio_agent_get_cards_reply(DBusPendingCall *pending, void *userdata) {
    DBusMessage *r;
    pa_dbus_pending *p;
    pa_bluetooth_backend *backend;
    DBusMessageIter i, array_i, struct_i, props_i;

    pa_assert_se(p = userdata);
    pa_assert_se(backend = p->context_data);
    pa_assert_se(r = dbus_pending_call_steal_reply(pending));

    if (dbus_message_get_type(r) == DBUS_MESSAGE_TYPE_ERROR) {
        pa_log_error("Failed to get a list of handsfree audio cards from ofono: %s: %s",
                     dbus_message_get_error_name(r), pa_dbus_get_error_message(r));
        goto finish;
    }

    if (!dbus_message_iter_init(r, &i) || !pa_streq(dbus_message_get_signature(r), "a(oa{sv})")) {
        pa_log_error("Invalid arguments in GetCards() reply");
        goto finish;
    }

    dbus_message_iter_recurse(&i, &array_i);
    while (dbus_message_iter_get_arg_type(&array_i) != DBUS_TYPE_INVALID) {
        const char *path;

        dbus_message_iter_recurse(&array_i, &struct_i);
        dbus_message_iter_get_basic(&struct_i, &path);
        dbus_message_iter_next(&struct_i);

        dbus_message_iter_recurse(&struct_i, &props_i);

        hf_audio_agent_card_found(backend, path, &props_i);

        dbus_message_iter_next(&array_i);
    }

finish:
    dbus_message_unref(r);

    PA_LLIST_REMOVE(pa_dbus_pending, backend->pending, p);
    pa_dbus_pending_free(p);
}

static void hf_audio_agent_get_cards(pa_bluetooth_backend *hf) {
    DBusMessage *m;

    pa_assert(hf);

    pa_assert_se(m = dbus_message_new_method_call(OFONO_SERVICE, "/", HF_AUDIO_MANAGER_INTERFACE, "GetCards"));
    hf_dbus_send_and_add_to_pending(hf, m, hf_audio_agent_get_cards_reply, NULL);
}

static void ofono_bus_id_destroy(pa_bluetooth_backend *backend) {
    pa_hashmap_remove_all(backend->cards);

    if (backend->ofono_bus_id) {
        pa_xfree(backend->ofono_bus_id);
        backend->ofono_bus_id = NULL;
        pa_bluetooth_discovery_set_ofono_running(backend->discovery, false);
    }
}

static void hf_audio_agent_register_reply(DBusPendingCall *pending, void *userdata) {
    DBusMessage *r;
    pa_dbus_pending *p;
    pa_bluetooth_backend *backend;

    pa_assert_se(p = userdata);
    pa_assert_se(backend = p->context_data);
    pa_assert_se(r = dbus_pending_call_steal_reply(pending));

    if (dbus_message_get_type(r) == DBUS_MESSAGE_TYPE_ERROR) {
        pa_log_error("Failed to register as a handsfree audio agent with ofono: %s: %s",
                     dbus_message_get_error_name(r), pa_dbus_get_error_message(r));
        goto finish;
    }

    backend->ofono_bus_id = pa_xstrdup(dbus_message_get_sender(r));

    hf_audio_agent_get_cards(backend);

finish:
    dbus_message_unref(r);

    PA_LLIST_REMOVE(pa_dbus_pending, backend->pending, p);
    pa_dbus_pending_free(p);

    pa_bluetooth_discovery_set_ofono_running(backend->discovery, backend->ofono_bus_id != NULL);
}

static void hf_audio_agent_register(pa_bluetooth_backend *hf) {
    DBusMessage *m;
    uint8_t codecs[2];
    const uint8_t *pcodecs = codecs;
    int ncodecs = 0;
    const char *path = HF_AUDIO_AGENT_PATH;

    pa_assert(hf);

    pa_assert_se(m = dbus_message_new_method_call(OFONO_SERVICE, "/", HF_AUDIO_MANAGER_INTERFACE, "Register"));

    codecs[ncodecs++] = HFP_AUDIO_CODEC_CVSD;

    pa_assert_se(dbus_message_append_args(m, DBUS_TYPE_OBJECT_PATH, &path, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &pcodecs, ncodecs,
                                          DBUS_TYPE_INVALID));

    hf_dbus_send_and_add_to_pending(hf, m, hf_audio_agent_register_reply, NULL);
}

static void hf_audio_agent_unregister(pa_bluetooth_backend *backend) {
    DBusMessage *m;
    const char *path = HF_AUDIO_AGENT_PATH;

    pa_assert(backend);
    pa_assert(backend->connection);

    if (backend->ofono_bus_id) {
        pa_assert_se(m = dbus_message_new_method_call(backend->ofono_bus_id, "/", HF_AUDIO_MANAGER_INTERFACE, "Unregister"));
        pa_assert_se(dbus_message_append_args(m, DBUS_TYPE_OBJECT_PATH, &path, DBUS_TYPE_INVALID));
        pa_assert_se(dbus_connection_send(pa_dbus_connection_get(backend->connection), m, NULL));

        ofono_bus_id_destroy(backend);
    }
}

static DBusHandlerResult filter_cb(DBusConnection *bus, DBusMessage *m, void *data) {
    const char *sender;
    DBusError err;
    pa_bluetooth_backend *backend = data;

    pa_assert(bus);
    pa_assert(m);
    pa_assert(backend);

    sender = dbus_message_get_sender(m);
    if (!pa_safe_streq(backend->ofono_bus_id, sender) && !pa_streq("org.freedesktop.DBus", sender))
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

    dbus_error_init(&err);

    if (dbus_message_is_signal(m, "org.freedesktop.DBus", "NameOwnerChanged")) {
        const char *name, *old_owner, *new_owner;

        if (!dbus_message_get_args(m, &err,
                                   DBUS_TYPE_STRING, &name,
                                   DBUS_TYPE_STRING, &old_owner,
                                   DBUS_TYPE_STRING, &new_owner,
                                   DBUS_TYPE_INVALID)) {
            pa_log_error("Failed to parse org.freedesktop.DBus.NameOwnerChanged: %s", err.message);
            goto fail;
        }

        if (pa_streq(name, OFONO_SERVICE)) {

            if (old_owner && *old_owner) {
                pa_log_debug("oFono disappeared");
                ofono_bus_id_destroy(backend);
            }

            if (new_owner && *new_owner) {
                pa_log_debug("oFono appeared");
                hf_audio_agent_register(backend);
            }
        }

    } else if (dbus_message_is_signal(m, "org.ofono.HandsfreeAudioManager", "CardAdded")) {
        const char *p;
        DBusMessageIter arg_i, props_i;

        if (!dbus_message_iter_init(m, &arg_i) || !pa_streq(dbus_message_get_signature(m), "oa{sv}")) {
            pa_log_error("Failed to parse org.ofono.HandsfreeAudioManager.CardAdded");
            goto fail;
        }

        dbus_message_iter_get_basic(&arg_i, &p);

        pa_assert_se(dbus_message_iter_next(&arg_i));
        pa_assert(dbus_message_iter_get_arg_type(&arg_i) == DBUS_TYPE_ARRAY);

        dbus_message_iter_recurse(&arg_i, &props_i);

        hf_audio_agent_card_found(backend, p, &props_i);
    } else if (dbus_message_is_signal(m, "org.ofono.HandsfreeAudioManager", "CardRemoved")) {
        const char *p;

        if (!dbus_message_get_args(m, &err, DBUS_TYPE_OBJECT_PATH, &p, DBUS_TYPE_INVALID)) {
            pa_log_error("Failed to parse org.ofono.HandsfreeAudioManager.CardRemoved: %s", err.message);
            goto fail;
        }

        hf_audio_agent_card_removed(backend, p);
    }

fail:
    dbus_error_free(&err);
    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusMessage *hf_audio_agent_release(DBusConnection *c, DBusMessage *m, void *data) {
    DBusMessage *r;
    const char *sender;
    pa_bluetooth_backend *backend = data;

    pa_assert(backend);

    sender = dbus_message_get_sender(m);
    if (!pa_safe_streq(backend->ofono_bus_id, sender)) {
        pa_assert_se(r = dbus_message_new_error(m, "org.ofono.Error.NotAllowed", "Operation is not allowed by this sender"));
        return r;
    }

    pa_log_debug("HF audio agent has been unregistered by oFono (%s)", backend->ofono_bus_id);

    ofono_bus_id_destroy(backend);

    pa_assert_se(r = dbus_message_new_method_return(m));

    return r;
}

static DBusMessage *hf_audio_agent_new_connection(DBusConnection *c, DBusMessage *m, void *data) {
    DBusMessage *r;
    const char *sender, *path;
    int fd;
    uint8_t codec;
    struct hf_audio_card *card;
    pa_bluetooth_backend *backend = data;

    pa_assert(backend);

    sender = dbus_message_get_sender(m);
    if (!pa_safe_streq(backend->ofono_bus_id, sender)) {
        pa_assert_se(r = dbus_message_new_error(m, "org.ofono.Error.NotAllowed", "Operation is not allowed by this sender"));
        return r;
    }

    if (dbus_message_get_args(m, NULL,
                              DBUS_TYPE_OBJECT_PATH, &path,
                              DBUS_TYPE_UNIX_FD, &fd,
                              DBUS_TYPE_BYTE, &codec,
                              DBUS_TYPE_INVALID) == FALSE) {
        pa_assert_se(r = dbus_message_new_error(m, "org.ofono.Error.InvalidArguments", "Invalid arguments in method call"));
        return r;
    }

    card = pa_hashmap_get(backend->cards, path);

    if (!card || codec != HFP_AUDIO_CODEC_CVSD) {
        pa_log_warn("New audio connection invalid arguments (path=%s fd=%d, codec=%d, transport [state=%s, profile=%s])",
                    path, fd, codec,
                    card ? pa_bluetooth_transport_state_to_string(card->transport->state) : "unknown",
                    card ? pa_bluetooth_profile_to_string(card->transport->profile) : "unknown");
        pa_assert_se(r = dbus_message_new_error(m, "org.ofono.Error.InvalidArguments", "Invalid arguments in method call"));
        return r;
    }

    if (card->transport->state == PA_BLUETOOTH_TRANSPORT_STATE_PLAYING) {
        pa_log_warn("Could not activate new audio connection as it is already active!? "
                    "(path=%s fd=%d, codec=%d, transport [state=%s, profile=%s])",
                    path, fd, codec,
                    pa_bluetooth_transport_state_to_string(card->transport->state),
                    pa_bluetooth_profile_to_string(card->transport->profile));
        pa_assert_se(r = dbus_message_new_error(m, "org.ofono.Error.InvalidArguments", "Transport is already active"));
        return r;
    }

    pa_log_debug("New audio connection on card %s (fd=%d, codec=%d)", path, fd, codec);

    card->fd = fd;
    card->transport->codec = codec;

    pa_bluetooth_transport_set_state(card->transport, PA_BLUETOOTH_TRANSPORT_STATE_PLAYING);

    pa_assert_se(r = dbus_message_new_method_return(m));

    return r;
}

static DBusHandlerResult hf_audio_agent_handler(DBusConnection *c, DBusMessage *m, void *data) {
    pa_bluetooth_backend *backend = data;
    DBusMessage *r = NULL;
    const char *path, *interface, *member;

    pa_assert(backend);

    path = dbus_message_get_path(m);
    interface = dbus_message_get_interface(m);
    member = dbus_message_get_member(m);

    if (!pa_streq(path, HF_AUDIO_AGENT_PATH))
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

    pa_log_debug("dbus: path=%s, interface=%s, member=%s", path, interface, member);

    if (dbus_message_is_method_call(m, "org.freedesktop.DBus.Introspectable", "Introspect")) {
        const char *xml = HF_AUDIO_AGENT_XML;

        pa_assert_se(r = dbus_message_new_method_return(m));
        pa_assert_se(dbus_message_append_args(r, DBUS_TYPE_STRING, &xml, DBUS_TYPE_INVALID));

    } else if (dbus_message_is_method_call(m, HF_AUDIO_AGENT_INTERFACE, "NewConnection"))
        r = hf_audio_agent_new_connection(c, m, data);
    else if (dbus_message_is_method_call(m, HF_AUDIO_AGENT_INTERFACE, "Release"))
        r = hf_audio_agent_release(c, m, data);
    else
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

    if (r) {
        pa_assert_se(dbus_connection_send(pa_dbus_connection_get(backend->connection), r, NULL));
        dbus_message_unref(r);
    }

    return DBUS_HANDLER_RESULT_HANDLED;
}

pa_bluetooth_backend *pa_bluetooth_ofono_backend_new(pa_core *c, pa_bluetooth_discovery *y) {
    pa_bluetooth_backend *backend;
    DBusError err;
    static const DBusObjectPathVTable vtable_hf_audio_agent = {
        .message_function = hf_audio_agent_handler,
    };

    pa_assert(c);

    backend = pa_xnew0(pa_bluetooth_backend, 1);
    backend->core = c;
    backend->discovery = y;
    backend->cards = pa_hashmap_new_full(pa_idxset_string_hash_func, pa_idxset_string_compare_func, NULL,
                                         (pa_free_cb_t) hf_audio_card_free);

    dbus_error_init(&err);

    if (!(backend->connection = pa_dbus_bus_get(c, DBUS_BUS_SYSTEM, &err))) {
        pa_log("Failed to get D-Bus connection: %s", err.message);
        dbus_error_free(&err);
        pa_xfree(backend);
        return NULL;
    }

    /* dynamic detection of handsfree audio cards */
    if (!dbus_connection_add_filter(pa_dbus_connection_get(backend->connection), filter_cb, backend, NULL)) {
        pa_log_error("Failed to add filter function");
        pa_dbus_connection_unref(backend->connection);
        pa_xfree(backend);
        return NULL;
    }

    if (pa_dbus_add_matches(pa_dbus_connection_get(backend->connection), &err,
            "type='signal',sender='org.freedesktop.DBus',interface='org.freedesktop.DBus',member='NameOwnerChanged',"
            "arg0='" OFONO_SERVICE "'",
            "type='signal',sender='" OFONO_SERVICE "',interface='" HF_AUDIO_MANAGER_INTERFACE "',member='CardAdded'",
            "type='signal',sender='" OFONO_SERVICE "',interface='" HF_AUDIO_MANAGER_INTERFACE "',member='CardRemoved'",
            NULL) < 0) {
        pa_log("Failed to add oFono D-Bus matches: %s", err.message);
        dbus_connection_remove_filter(pa_dbus_connection_get(backend->connection), filter_cb, backend);
        pa_dbus_connection_unref(backend->connection);
        pa_xfree(backend);
        return NULL;
    }

    pa_assert_se(dbus_connection_register_object_path(pa_dbus_connection_get(backend->connection), HF_AUDIO_AGENT_PATH,
                                                      &vtable_hf_audio_agent, backend));

    hf_audio_agent_register(backend);

    return backend;
}

void pa_bluetooth_ofono_backend_free(pa_bluetooth_backend *backend) {
    pa_assert(backend);

    pa_dbus_free_pending_list(&backend->pending);

    hf_audio_agent_unregister(backend);

    dbus_connection_unregister_object_path(pa_dbus_connection_get(backend->connection), HF_AUDIO_AGENT_PATH);

    pa_dbus_remove_matches(pa_dbus_connection_get(backend->connection),
            "type='signal',sender='org.freedesktop.DBus',interface='org.freedesktop.DBus',member='NameOwnerChanged',"
            "arg0='" OFONO_SERVICE "'",
            "type='signal',sender='" OFONO_SERVICE "',interface='" HF_AUDIO_MANAGER_INTERFACE "',member='CardAdded'",
            "type='signal',sender='" OFONO_SERVICE "',interface='" HF_AUDIO_MANAGER_INTERFACE "',member='CardRemoved'",
            NULL);

    dbus_connection_remove_filter(pa_dbus_connection_get(backend->connection), filter_cb, backend);

    pa_dbus_connection_unref(backend->connection);

    pa_hashmap_free(backend->cards);

    pa_xfree(backend);
}
