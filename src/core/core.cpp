/*
    Copyright © 2013 by Maxim Biro <nurupo.contributions@gmail.com>
    Copyright © 2014-2019 by The qTox Project Contributors

    This file is part of qTox, a Qt-based graphical interface for Tox.

    qTox is libre software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    qTox is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with qTox.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "core.h"
#include "coreav.h"
#include "corefile.h"

#include "src/core/coreext.h"
#include "src/core/dhtserver.h"
#include "src/core/icoresettings.h"
#include "src/core/toxlogger.h"
#include "src/core/toxoptions.h"
#include "src/core/toxstring.h"
#include "src/model/groupinvite.h"
#include "src/model/status.h"
#include "src/model/ibootstraplistgenerator.h"
#include "src/persistence/profile.h"
#include "src/persistence/settings.h"
#include "src/widget/widget.h"
#include "util/strongtype.h"
#include "util/compatiblerecursivemutex.h"
#include "util/toxcoreerrorparser.h"

#include <QCoreApplication>
#include <QDateTime>
// zoff
#include <QFile>
#include <QDir>
#if QT_VERSION >= QT_VERSION_CHECK( 5, 10, 0 )
#include <QRandomGenerator>
#endif
// zoff
#include <QRegularExpression>
#include <QString>
#include <QStringBuilder>
#include <QTimer>

#include <tox/tox.h>

#include <sodium.h>

#include <algorithm>
#include <cassert>
#include <chrono>
#include <memory>
#include <random>

const QString Core::TOX_EXT = ".tox";

#define ASSERT_CORE_THREAD assert(QThread::currentThread() == coreThread.get())

namespace {

QList<DhtServer> shuffleBootstrapNodes(QList<DhtServer> bootstrapNodes)
{
    std::mt19937 rng(std::chrono::high_resolution_clock::now().time_since_epoch().count());
    std::shuffle(bootstrapNodes.begin(), bootstrapNodes.end(), rng);
    return bootstrapNodes;
}

} // namespace

Core::Core(QThread* coreThread_, IBootstrapListGenerator& bootstrapListGenerator_, ICoreSettings& settings_)
    : tox(nullptr)
    , toxTimer{new QTimer{this}}
    , coreThread(coreThread_)
    , bootstrapListGenerator(bootstrapListGenerator_)
    , settings(settings_)
{
    assert(toxTimer);
    // need to migrate Settings and History if this changes
    assert(ToxPk::size == tox_public_key_size());
    assert(GroupId::size == tox_conference_id_size());
    assert(ToxId::size == tox_address_size());
    toxTimer->setSingleShot(true);
    connect(toxTimer, &QTimer::timeout, this, &Core::process);
    connect(coreThread_, &QThread::finished, toxTimer, &QTimer::stop);
}

Core::~Core()
{
    /*
     * First stop the thread to stop the timer and avoid Core emitting callbacks
     * into an already destructed CoreAV.
     */
    coreThread->exit(0);
    coreThread->wait();

    tox.reset();
}

/**
 * @brief Registers all toxcore callbacks
 * @param tox Tox instance to register the callbacks on
 */
void Core::registerCallbacks(Tox* tox)
{
    tox_callback_self_connection_status(tox, onSelfConnectionStatusChanged);
    tox_callback_friend_request(tox, onFriendRequest);
    tox_callback_friend_message(tox, onFriendMessage);
    tox_callback_friend_name(tox, onFriendNameChange);
    tox_callback_friend_typing(tox, onFriendTypingChange);
    tox_callback_friend_status_message(tox, onStatusMessageChanged);
    tox_callback_friend_status(tox, onUserStatusChanged);
    tox_callback_friend_connection_status(tox, onConnectionStatusChanged);
    tox_callback_friend_read_receipt(tox, onReadReceiptCallback);
    tox_callback_conference_invite(tox, onGroupInvite);
    tox_callback_conference_message(tox, onGroupMessage);
    tox_callback_conference_peer_list_changed(tox, onGroupPeerListChange);
    tox_callback_conference_peer_name(tox, onGroupPeerNameChange);
    tox_callback_conference_title(tox, onGroupTitleChange);
    tox_callback_friend_lossless_packet(tox, onLosslessPacket);
    tox_callback_group_invite(tox, onNgcInvite);
    tox_callback_group_self_join(tox, onNgcSelfJoin);
    tox_callback_group_peer_join(tox, onNgcPeerJoin);
    tox_callback_group_peer_exit(tox, onNgcPeerExit);
    tox_callback_group_peer_name(tox, onNgcPeerName);
    tox_callback_group_message(tox, onNgcGroupMessage);
    tox_callback_group_private_message(tox, onNgcGroupPrivateMessage);
    tox_callback_group_custom_packet(tox, onNgcGroupCustomPacket);
    tox_callback_group_custom_private_packet(tox, onNgcGroupCustomPrivatePacket);

    // HINT: print Qt compiled and runtime versions
    qDebug() << "QT_COMPILE_VERSION:" << QT_VERSION_STR << "QT_RUNTIME_VERSION:" << qVersion();
}

/**
 * @brief Factory method for the Core object
 * @param savedata empty if new profile or saved data else
 * @param settings Settings specific to Core
 * @return nullptr or a Core object ready to start
 */
ToxCorePtr Core::makeToxCore(const QByteArray& savedata, ICoreSettings& settings,
                             IBootstrapListGenerator& bootstrapNodes, ToxCoreErrors* err)
{
    settings.setToxcore(nullptr);

    QThread* thread = new QThread();
    if (thread == nullptr) {
        qCritical() << "Could not allocate Core thread";
        return {};
    }
    thread->setObjectName("qTox Core");

    auto toxOptions = ToxOptions::makeToxOptions(savedata, settings);
    if (toxOptions == nullptr) {
        qCritical() << "Could not allocate ToxOptions data structure";
        if (err) {
            *err = ToxCoreErrors::ERROR_ALLOC;
        }
        return {};
    }

    ToxCorePtr core(new Core(thread, bootstrapNodes, settings));
    if (core == nullptr) {
        if (err) {
            *err = ToxCoreErrors::ERROR_ALLOC;
        }
        return {};
    }

    Tox_Err_New tox_err;
    core->tox = ToxPtr(tox_new(*toxOptions, &tox_err));

    switch (tox_err) {
    case TOX_ERR_NEW_OK:
        break;

    case TOX_ERR_NEW_LOAD_BAD_FORMAT:
        qCritical() << "Failed to parse Tox save data";
        if (err) {
            *err = ToxCoreErrors::BAD_PROXY;
        }
        return {};

    case TOX_ERR_NEW_PORT_ALLOC:
        if (toxOptions->getIPv6Enabled()) {
            toxOptions->setIPv6Enabled(false);
            core->tox = ToxPtr(tox_new(*toxOptions, &tox_err));
            if (tox_err == TOX_ERR_NEW_OK) {
                qWarning() << "Core failed to start with IPv6, falling back to IPv4. LAN discovery "
                              "may not work properly.";
                break;
            }
        }

        qCritical() << "Can't to bind the port";
        if (err) {
            *err = ToxCoreErrors::FAILED_TO_START;
        }
        return {};

    case TOX_ERR_NEW_PROXY_BAD_HOST:
    case TOX_ERR_NEW_PROXY_BAD_PORT:
    case TOX_ERR_NEW_PROXY_BAD_TYPE:
        qCritical() << "Bad proxy, error code:" << tox_err;
        if (err) {
            *err = ToxCoreErrors::BAD_PROXY;
        }
        return {};

    case TOX_ERR_NEW_PROXY_NOT_FOUND:
        qCritical() << "Proxy not found";
        if (err) {
            *err = ToxCoreErrors::BAD_PROXY;
        }
        return {};

    case TOX_ERR_NEW_LOAD_ENCRYPTED:
        qCritical() << "Attempted to load encrypted Tox save data";
        if (err) {
            *err = ToxCoreErrors::INVALID_SAVE;
        }
        return {};

    case TOX_ERR_NEW_MALLOC:
        qCritical() << "Memory allocation failed";
        if (err) {
            *err = ToxCoreErrors::ERROR_ALLOC;
        }
        return {};

    case TOX_ERR_NEW_NULL:
        qCritical() << "A parameter was null";
        if (err) {
            *err = ToxCoreErrors::FAILED_TO_START;
        }
        return {};

    default:
        qCritical() << "Toxcore failed to start, unknown error code:" << tox_err;
        if (err) {
            *err = ToxCoreErrors::FAILED_TO_START;
        }
        return {};
    }

    // tox should be valid by now
    assert(core->tox != nullptr);

    // create CoreFile
    core->file = CoreFile::makeCoreFile(core.get(), core->tox.get(), core->coreLoopLock);
    if (!core->file) {
        qCritical() << "CoreFile failed to start";
        if (err) {
            *err = ToxCoreErrors::FAILED_TO_START;
        }
        return {};
    }

    core->ext = CoreExt::makeCoreExt(core->tox.get());
    connect(core.get(), &Core::friendStatusChanged, core->ext.get(), &CoreExt::onFriendStatusChanged);

    registerCallbacks(core->tox.get());

    // connect the thread with the Core
    connect(thread, &QThread::started, core.get(), &Core::onStarted);
    core->moveToThread(thread);

    settings.setToxcore(core->tox.get());

    // when leaving this function 'core' should be ready for it's start() action or
    // a nullptr
    return core;
}

void Core::onStarted()
{
    ASSERT_CORE_THREAD;

    // One time initialization stuff
    QString name = getUsername();
    if (!name.isEmpty()) {
        emit usernameSet(name);
    }

    QString msg = getStatusMessage();
    if (!msg.isEmpty()) {
        emit statusMessageSet(msg);
    }

    ToxId id = getSelfId();
    // Id comes from toxcore, must be valid
    assert(id.isValid());
    emit idSet(id);

    loadFriends();
    loadGroups();

    process(); // starts its own timer
}

/**
 * @brief Starts toxcore and it's event loop, can be called from any thread
 */
void Core::start()
{
    coreThread->start();
}

const CoreAV* Core::getAv() const
{
    return av;
}

CoreAV* Core::getAv()
{
    return av;
}

void Core::setAv(CoreAV *coreAv)
{
    av = coreAv;
}

CoreFile* Core::getCoreFile() const
{
    return file.get();
}

Tox* Core::getTox() const
{
    return tox.get();
}

CompatibleRecursiveMutex &Core::getCoreLoopLock() const
{
    return coreLoopLock;
}

const CoreExt* Core::getExt() const
{
    return ext.get();
}

CoreExt* Core::getExt()
{
    return ext.get();
}

/**
 * @brief Processes toxcore events and ensure we stay connected, called by its own timer
 */
void Core::process()
{
    QMutexLocker ml{&coreLoopLock};

    ASSERT_CORE_THREAD;

    tox_iterate(tox.get(), this);
    ext->process();

#ifdef DEBUG
    // we want to see the debug messages immediately
    fflush(stdout);
#endif

    // HINT: checking the connection on every iteration is overkill and does lots of locking in toxcore
    //       sadly when fixing this, core_test keeps failing. meh.
    if (checkConnection()) {
        tolerance = CORE_DISCONNECT_TOLERANCE;
    } else if (!(--tolerance)) {
        bootstrapDht();
        tolerance = 3 * CORE_DISCONNECT_TOLERANCE;
    }

    unsigned sleeptime_file = getCoreFile()->corefileIterationInterval();
    unsigned sleeptime_toxcore = tox_iteration_interval(tox.get());
    unsigned sleeptime = qMin(sleeptime_toxcore, sleeptime_file);
    // qDebug() << "Core::process:sleeptime_file:" << sleeptime_file << "sleeptime_toxcore:" << sleeptime_toxcore << "sleeptime:" << sleeptime;
    // TODO: check for active AV calls and lower iteration interval only when calls are active
    toxTimer->start(sleeptime);
}

bool Core::checkConnection()
{
    ASSERT_CORE_THREAD;
    auto selfConnection = tox_self_get_connection_status(tox.get());
    QString connectionName;
    bool toxConnected = false;
    switch (selfConnection)
    {
        case TOX_CONNECTION_NONE:
            toxConnected = false;
            break;
        case TOX_CONNECTION_TCP:
            toxConnected = true;
            connectionName = "a TCP relay";
            break;
        case TOX_CONNECTION_UDP:
            toxConnected = true;
            connectionName = "the UDP DHT";
            break;
        qWarning() << "tox_self_get_connection_status returned unknown enum!";
    }

    if (toxConnected && !isConnected) {
        qDebug().noquote() << "Connected to" << connectionName;
        emit connected(static_cast<uint32_t>(selfConnection));
    } else if (!toxConnected && isConnected) {
        qDebug() << "Disconnected from the DHT";
        emit disconnected();
    }

    isConnected = toxConnected;
    return toxConnected;
}

/**
 * @brief Connects us to the Tox network
 */
void Core::bootstrapDht()
{
    ASSERT_CORE_THREAD;


    auto const shuffledBootstrapNodes = shuffleBootstrapNodes(bootstrapListGenerator.getBootstrapNodes());
    if (shuffledBootstrapNodes.empty()) {
        qWarning() << "No bootstrap node list";
        return;
    }

    // i think the more we bootstrap, the more we jitter because the more we overwrite nodes
    auto numNewNodes = 2;
    for (int i = 0; i < numNewNodes && i < shuffledBootstrapNodes.size(); ++i) {
        const auto& dhtServer = shuffledBootstrapNodes.at(i);
        QByteArray address;
        if (!dhtServer.ipv4.isEmpty()) {
            address = dhtServer.ipv4.toLatin1();
        } else if (!dhtServer.ipv6.isEmpty() && settings.getEnableIPv6()) {
            address = dhtServer.ipv6.toLatin1();
        } else {
            ++numNewNodes;
            continue;
        }

        ToxPk pk{dhtServer.publicKey};
        qDebug() << "Connecting to bootstrap node" << pk.toString();
        const uint8_t* pkPtr = pk.getData();

        Tox_Err_Bootstrap error;
        if (dhtServer.statusUdp) {
            tox_bootstrap(tox.get(), address.constData(), dhtServer.udpPort, pkPtr, &error);
            PARSE_ERR(error);
        }
        if (dhtServer.statusTcp) {
            const auto ports = dhtServer.tcpPorts.size();
            const auto tcpPort = dhtServer.tcpPorts[rand() % ports];
            tox_add_tcp_relay(tox.get(), address.constData(), tcpPort, pkPtr, &error);
            PARSE_ERR(error);
        }
    }
}

void Core::onFriendRequest(Tox* tox, const uint8_t* cFriendPk, const uint8_t* cMessage,
                           size_t cMessageSize, void* core)
{
    std::ignore = tox;
    ToxPk friendPk(cFriendPk);
    std::ignore = cMessage;
    std::ignore = cMessageSize;
    QString requestMessage = QString(""); // ToxString(cMessage, cMessageSize).getQString();
    emit static_cast<Core*>(core)->friendRequestReceived(friendPk, requestMessage);
}

static size_t xnet_pack_u16(uint8_t *bytes, uint16_t v)
{
    bytes[0] = (v >> 8) & 0xff;
    bytes[1] = v & 0xff;
    return sizeof(v);
}

static size_t xnet_pack_u32(uint8_t *bytes, uint32_t v)
{
    uint8_t *p = bytes;
    p += xnet_pack_u16(p, (v >> 16) & 0xffff);
    p += xnet_pack_u16(p, v & 0xffff);
    return p - bytes;
}

static size_t xnet_unpack_u16(const uint8_t *bytes, uint16_t *v)
{
    uint8_t hi = bytes[0];
    uint8_t lo = bytes[1];
    *v = (static_cast<uint16_t>(hi) << 8) | lo;
    return sizeof(*v);
}

static size_t xnet_unpack_u32(const uint8_t *bytes, uint32_t *v)
{
    const uint8_t *p = bytes;
    uint16_t hi;
    uint16_t lo;
    p += xnet_unpack_u16(p, &hi);
    p += xnet_unpack_u16(p, &lo);
    *v = (static_cast<uint32_t>(hi) << 16) | lo;
    return p - bytes;
}

static void send_highlevel_ack(Tox* tox, uint32_t friendId, QByteArray& hash_buffer_bytes)
{
    const uint8_t *hash_buffer_c = reinterpret_cast<const uint8_t*>(hash_buffer_bytes.constData());
    // HINT: ACK has a dummy text message with text "_" which das a length of "1" byte.
    const int dummy_message_size = 1;
    const uint8_t dummy_message = 95; // "_" char
    const uint8_t *dummy_message_buf = reinterpret_cast<const uint8_t*>(&dummy_message);

    uint8_t *message_str_v3 =
                    static_cast<uint8_t *>(calloc(1, (size_t)(
                    dummy_message_size + TOX_MSGV3_GUARD + TOX_MSGV3_MSGID_LENGTH + TOX_MSGV3_TIMESTAMP_LENGTH)));
    if (!message_str_v3)
    {
        return;
    }

    uint32_t timestamp_unix_buf;
    xnet_pack_u32(reinterpret_cast<uint8_t*>(&timestamp_unix_buf),
            static_cast<uint32_t>((QDateTime::currentDateTime().toMSecsSinceEpoch() / 1000)));

    uint8_t* position = message_str_v3;
    memcpy(position, dummy_message_buf, static_cast<size_t>(dummy_message_size));

    position = position + dummy_message_size + TOX_MSGV3_GUARD;
    memcpy(position, hash_buffer_c, static_cast<size_t>(TOX_MSGV3_MSGID_LENGTH));

    position = position + TOX_MSGV3_MSGID_LENGTH;
    memcpy(position, &timestamp_unix_buf, static_cast<size_t>(TOX_MSGV3_TIMESTAMP_LENGTH));

    const size_t new_len = dummy_message_size + TOX_MSGV3_GUARD + TOX_MSGV3_MSGID_LENGTH + TOX_MSGV3_TIMESTAMP_LENGTH;

    Tox_Err_Friend_Send_Message error;
    const uint32_t res = tox_friend_send_message(tox, friendId, TOX_MESSAGE_TYPE_HIGH_LEVEL_ACK, message_str_v3, new_len, &error);
    qDebug() << "sent high level ack, res:" << res << " errcode:" << error;
    free(message_str_v3);
}

void Core::onFriendMessage(Tox* tox, uint32_t friendId, Tox_Message_Type type, const uint8_t* cMessage,
                           size_t cMessageSize, void* core)
{
    std::ignore = tox;
    uint32_t msgV3_timestamp = 0;
    bool isAction = (type == TOX_MESSAGE_TYPE_ACTION);
    QString msg = ToxString(cMessage, cMessageSize).getQString();
    QByteArray msgv3hash;

    // HINT: check for msgV3 --------------
    bool has_msgv3 = false;
    if ((cMessage) && (cMessageSize > (TOX_MSGV3_MSGID_LENGTH + TOX_MSGV3_TIMESTAMP_LENGTH + TOX_MSGV3_GUARD))) {
        int pos = cMessageSize - (TOX_MSGV3_MSGID_LENGTH + TOX_MSGV3_TIMESTAMP_LENGTH + TOX_MSGV3_GUARD);
        uint8_t g1 = *(cMessage + pos);
        uint8_t g2 = *(cMessage + pos + 1);
        // check for the msgv3 guard
        if ((g1 == 0) && (g2 == 0)) {
            // we have msgV3 meta data
            const char *msgV3_hash_buffer_bin = reinterpret_cast<const char*>(cMessage + pos + 2);
            const uint8_t *p = static_cast<const uint8_t *>(cMessage + pos + 2);
            p = p + 32;
            p += xnet_unpack_u32(p, &msgV3_timestamp);
            msgv3hash = QByteArray(msgV3_hash_buffer_bin, 32);
            // qDebug() << "msgv3hash:" << QString::fromUtf8(msgv3hash.toHex()).toUpper();
            msg = QString::fromUtf8(msgv3hash.toHex()).toUpper().rightJustified(64, '0') + QString(":") + msg;
            has_msgv3 = true;

            if (type == TOX_MESSAGE_TYPE_HIGH_LEVEL_ACK) {
                // TODO: process high level ack here
                qDebug() << "high level ack received";
            }
        }
    }

    if (type == TOX_MESSAGE_TYPE_HIGH_LEVEL_ACK) {
        // high level ack is not a normal message, so return here
        return;
    }

    // HINT: check for msgV3 --------------
    if (has_msgv3) {
        emit static_cast<Core*>(core)->friendMessageReceived(friendId, msg, isAction,
            static_cast<int>(Widget::MessageHasIdType::MSGV3_ID));
        send_highlevel_ack(tox, friendId, msgv3hash);
    } else {
        emit static_cast<Core*>(core)->friendMessageReceived(friendId, msg, isAction);
    }
}

void Core::onFriendNameChange(Tox* tox, uint32_t friendId, const uint8_t* cName, size_t cNameSize, void* core)
{
    std::ignore = tox;
    QString newName = ToxString(cName, cNameSize).getQString();
    // no saveRequest, this callback is called on every connection, not just on name change
    emit static_cast<Core*>(core)->friendUsernameChanged(friendId, newName);
}

void Core::onFriendTypingChange(Tox* tox, uint32_t friendId, bool isTyping, void* core)
{
    std::ignore = tox;
    emit static_cast<Core*>(core)->friendTypingChanged(friendId, isTyping);
}

void Core::onStatusMessageChanged(Tox* tox, uint32_t friendId, const uint8_t* cMessage,
                                  size_t cMessageSize, void* core)
{
    std::ignore = tox;
    QString message = ToxString(cMessage, cMessageSize).getQString();
    // no saveRequest, this callback is called on every connection, not just on name change
    emit static_cast<Core*>(core)->friendStatusMessageChanged(friendId, message);
}

void Core::onUserStatusChanged(Tox* tox, uint32_t friendId, Tox_User_Status userstatus, void* core)
{
    std::ignore = tox;
    Status::Status status;
    switch (userstatus) {
    case TOX_USER_STATUS_AWAY:
        status = Status::Status::Away;
        break;

    case TOX_USER_STATUS_BUSY:
        status = Status::Status::Busy;
        break;

    default:
        status = Status::Status::Online;
        break;
    }

    // no saveRequest, this callback is called on every connection, not just on name change
    emit static_cast<Core*>(core)->friendStatusChanged(friendId, status);
}

void Core::onSelfConnectionStatusChanged(Tox* tox, Tox_Connection status, void* vCore)
{
    std::ignore = tox;
    Core* core = static_cast<Core*>(vCore);
    std::ignore = core;

    switch (status)
    {
        case TOX_CONNECTION_NONE:
            qDebug() << "Disconnected from Tox Network";
            break;
        case TOX_CONNECTION_TCP:
            qDebug() << "Connected to Tox Network through a TCP relay";
            break;
        case TOX_CONNECTION_UDP:
            qDebug() << "Connected to Tox Network directly with UDP";
            break;
        qWarning() << "tox_callback_self_connection_status returned unknown enum!";
    }
}

void Core::onConnectionStatusChanged(Tox* tox, uint32_t friendId, Tox_Connection status, void* vCore)
{
    std::ignore = tox;
    Core* core = static_cast<Core*>(vCore);
    Status::Status friendStatus = Status::Status::Offline;
    switch (status)
    {
        case TOX_CONNECTION_NONE:
            friendStatus = Status::Status::Offline;
            qDebug() << "Disconnected from friend" << friendId;
            break;
        case TOX_CONNECTION_TCP:
            friendStatus = Status::Status::Online;
            qDebug() << "Connected to friend" << friendId << "through a TCP relay";
            break;
        case TOX_CONNECTION_UDP:
            friendStatus = Status::Status::Online;
            qDebug() << "Connected to friend" << friendId << "directly with UDP";
            break;
        qWarning() << "tox_callback_friend_connection_status returned unknown enum!";
    }

    // Ignore Online because it will be emited from onUserStatusChanged
    bool isOffline = friendStatus == Status::Status::Offline;
    if (isOffline) {
        emit core->friendStatusChanged(friendId, friendStatus);
        core->checkLastOnline(friendId);
    }
    emit core->onFriendConnectionStatusFullChanged(friendId, static_cast<uint32_t>(status));
}

void Core::onGroupInvite(Tox* tox, uint32_t friendId, Tox_Conference_Type type,
                         const uint8_t* cookie, size_t length, void* vCore)
{
    std::ignore = tox;
    Core* core = static_cast<Core*>(vCore);
    const QByteArray data(reinterpret_cast<const char*>(cookie), length);
    const GroupInvite inviteInfo(friendId, type, data);
    switch (type) {
    case TOX_CONFERENCE_TYPE_TEXT:
        qDebug() << QString("Text group invite by %1").arg(friendId);
        emit core->groupInviteReceived(inviteInfo);
        break;

    case TOX_CONFERENCE_TYPE_AV:
        qDebug() << QString("AV group invite by %1").arg(friendId);
        emit core->groupInviteReceived(inviteInfo);
        break;

    default:
        qWarning() << "Group invite with unknown type " << type;
    }
}

QString Core::GetRandomString(int randomStringLength) const
{
   const QString possibleCharacters("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");

   QString randomString;
   for(int i=0; i<randomStringLength; ++i)
   {
#if QT_VERSION < QT_VERSION_CHECK( 5, 10, 0 )
       int index = qrand() % possibleCharacters.length();
#else
       int index = QRandomGenerator::global()->generate() % possibleCharacters.length();
#endif
       QChar nextChar = possibleCharacters.at(index);
       randomString.append(nextChar);
   }
   return randomString;
}

QString Core::GetRandomGroupusername() const
{
	static const std::vector<const char*> name0_list
    {
        // Source: http://www.babynamewizard.com/the-top-1000-baby-names-of-2013-united-states-of-america
        "Sophia", "Emma", "Olivia", "Isabella", "Ava", "Mia", "Emily", "Abigail", "Madison", "Elizabeth", "Charlotte", "Avery", "Sofia", "Chloe", "Ella", "Harper", "Amelia", "Aubrey", "Addison", "Evelyn", "Natalie", "Grace", "Hannah", "Zoey", "Victoria", "Lillian", "Lily", "Brooklyn", "Samantha", "Layla", "Zoe", "Audrey", "Leah", "Allison", "Anna", "Aaliyah", "Savannah", "Gabriella", "Camila", "Aria", "Kaylee", "Scarlett", "Hailey", "Arianna", "Riley", "Alexis", "Nevaeh", "Sarah", "Claire", "Sadie", "Peyton", "Aubree", "Serenity", "Ariana", "Genesis", "Penelope", "Alyssa", "Bella", "Taylor", "Alexa", "Kylie", "Mackenzie", "Caroline", "Kennedy", "Autumn", "Lucy", "Ashley", "Madelyn", "Violet", "Stella", "Brianna", "Maya", "Skylar", "Ellie", "Julia", "Sophie", "Katherine", "Mila", "Khloe", "Paisley", "Annabelle", "Alexandra", "Nora", "Melanie", "London", "Gianna", "Naomi", "Eva", "Faith", "Madeline", "Lauren", "Nicole", "Ruby", "Makayla", "Kayla", "Lydia", "Piper", "Sydney", "Jocelyn", "Morgan", "Kimberly", "Molly", "Jasmine", "Reagan", "Bailey", "Eleanor", "Alice", "Trinity", "Rylee", "Andrea", "Hadley", "Maria", "Brooke", "Mariah", "Isabelle", "Brielle", "Mya", "Quinn", "Vivian", "Natalia", "Mary", "Liliana", "Payton", "Lilly", "Eliana", "Jade", "Cora", "Paige", "Valentina", "Kendall", "Clara", "Elena", "Jordyn", "Kaitlyn", "Delilah", "Isabel", "Destiny", "Rachel", "Amy", "Mckenzie", "Gabrielle", "Brooklynn", "Katelyn", "Laila", "Aurora", "Ariel", "Angelina", "Aliyah", "Juliana", "Vanessa", "Adriana", "Ivy", "Lyla", "Sara", "Willow", "Reese", "Hazel", "Eden", "Elise", "Josephine", "Kinsley", "Ximena", "Jessica", "Londyn", "Makenzie", "Gracie", "Isla", "Michelle", "Valerie", "Kylee", "Melody", "Catherine", "Adalynn", "Jayla", "Alexia", "Valeria", "Adalyn", "Rebecca", "Izabella", "Alaina", "Margaret", "Alana", "Alivia", "Kate", "Luna", "Norah", "Kendra", "Summer", "Ryleigh", "Julianna", "Jennifer", "Lila", "Hayden", "Emery", "Stephanie", "Angela", "Fiona", "Daisy", "Presley", "Eliza", "Harmony", "Melissa", "Giselle", "Keira", "Kinley", "Alayna", "Alexandria", "Emilia", "Marley", "Arabella", "Emerson", "Adelyn", "Brynn", "Lola", "Leila", "Mckenna", "Aniyah", "Athena", "Genevieve", "Allie", "Gabriela", "Daniela", "Cecilia", "Rose", "Adrianna", "Callie", "Jenna", "Esther", "Haley", "Leilani", "Maggie", "Adeline", "Hope", "Jaylah", "Amaya", "Maci", "Ana", "Juliet", "Jacqueline", "Charlie", "Lucia", "Tessa", "Camille", "Katie", "Miranda", "Lexi", "Makenna", "Jada", "Delaney", "Cassidy", "Alina", "Georgia", "Iris", "Ashlyn", "Kenzie", "Megan", "Anastasia", "Paris", "Shelby", "Jordan", "Danielle", "Lilliana", "Sienna", "Teagan", "Josie", "Angel", "Parker", "Mikayla", "Brynlee", "Diana", "Chelsea", "Kathryn", "Erin", "Annabella", "Kaydence", "Lyric", "Arya", "Madeleine", "Kayleigh", "Vivienne", "Sabrina", "Cali", "Raelynn", "Leslie", "Kyleigh", "Ayla", "Nina", "Amber", "Daniella", "Finley", "Olive", "Miriam", "Dakota", "Elliana", "Juliette", "Noelle", "Alison", "Amanda", "Alessandra", "Evangeline", "Phoebe", "Bianca", "Christina", "Yaretzi", "Raegan", "Kelsey", "Lilah", "Fatima", "Kiara", "Elaina", "Cadence", "Nyla", "Addyson", "Giuliana", "Alondra", "Gemma", "Ashlynn", "Carly", "Kyla", "Alicia", "Adelaide", "Laura", "Allyson", "Charlee", "Nadia", "Mallory", "Heaven", "Cheyenne", "Ruth", "Tatum", "Lena", "Ainsley", "Amiyah", "Journey", "Malia", "Haylee", "Veronica", "Eloise", "Myla", "Mariana", "Jillian", "Joanna", "Madilyn", "Baylee", "Selena", "Briella", "Sierra", "Rosalie", "Gia", "Briana", "Talia", "Abby", "Heidi", "Annie", "Jane", "Maddison", "Kira", "Carmen", "Lucille", "Harley", "Macy", "Skyler", "Kali", "June", "Elsie", "Kamila", "Adelynn", "Arielle", "Kelly", "Scarlet", "Rylie", "Haven", "Marilyn", "Aubrie", "Kamryn", "Kara", "Hanna", "Averie", "Marissa", "Jayda", "Jazmine", "Camryn", "Everly", "Jazmin", "Lia", "Karina", "Maliyah", "Miley", "Bethany", "Mckinley", "Jayleen", "Esmeralda", "Macie", "Aleah", "Catalina", "Nayeli", "Daphne", "Janelle", "Camilla", "Madelynn", "Kyra", "Addisyn", "Aylin", "Julie", "Caitlyn", "Sloane", "Gracelyn", "Elle", "Helen", "Michaela", "Serena", "Lana", "Angelica", "Raelyn", "Nylah", "Karen", "Emely", "Bristol", "Sarai", "Alejandra", "Brittany", "Vera", "April", "Francesca", "Logan", "Rowan", "Skye", "Sasha", "Carolina", "Kassidy", "Miracle", "Ariella", "Tiffany", "Itzel", "Justice", "Ada", "Brylee", "Jazlyn", "Dahlia", "Julissa", "Kaelyn", "Savanna", "Kennedi", "Anya", "Viviana", "Cataleya", "Jayden", "Sawyer", "Holly", "Kaylie", "Blakely", "Kailey", "Jimena", "Melany", "Emmalyn", "Guadalupe", "Sage", "Annalise", "Cassandra", "Madisyn", "Anabelle", "Kaylin", "Amira", "Crystal", "Elisa", "Caitlin", "Lacey", "Rebekah", "Celeste", "Danna", "Marlee", "Gwendolyn", "Joselyn", "Karla", "Joy", "Audrina", "Janiyah", "Anaya", "Malaysia", "Annabel", "Kadence", "Zara", "Imani", "Maeve", "Priscilla", "Phoenix", "Aspen", "Katelynn", "Dylan", "Eve", "Jamie", "Lexie", "Jaliyah", "Kailyn", "Lilian", "Braelyn", "Angie", "Lauryn", "Cynthia", "Emersyn", "Lorelei", "Monica", "Alanna", "Brinley", "Sylvia", "Journee", "Nia", "Aniya", "Breanna", "Fernanda", "Lillie", "Amari", "Charley", "Lilyana", "Luciana", "Raven", "Kaliyah", "Emilee", "Anne", "Bailee", "Hallie", "Zariah", "Bridget", "Annika", "Gloria", "Zuri", "Madilynn", "Elsa", "Nova", "Kiley", "Johanna", "Liberty", "Rosemary", "Aleena", "Courtney", "Madalyn", "Aryanna", "Tatiana", "Angelique", "Harlow", "Leighton", "Hayley", "Skyla", "Kenley", "Tiana", "Dayana", "Evelynn", "Selah", "Helena", "Blake", "Virginia", "Cecelia", "Nathalie", "Jaycee", "Danica", "Dulce", "Gracelynn", "Ember", "Evie", "Anika", "Emilie", "Erica", "Tenley", "Anabella", "Liana", "Cameron", "Braylee", "Aisha", "Charleigh", "Hattie", "Leia", "Lindsey", "Marie", "Regina", "Isis", "Alyson", "Anahi", "Elyse", "Felicity", "Jaelyn", "Amara", "Natasha", "Samara", "Lainey", "Daleyza", "Miah", "Melina", "River", "Amani", "Aileen", "Jessie", "Whitney", "Beatrice", "Caylee", "Greta", "Jaelynn", "Milan", "Millie", "Lea", "Marina", "Kaylynn", "Kenya", "Mariam", "Amelie", "Kaia", "Maleah", "Ally", "Colette", "Elisabeth", "Dallas", "Erika", "Karlee", "Alayah", "Alani", "Farrah", "Bria", "Madalynn", "Mikaela", "Adelina", "Amina", "Cara", "Jaylynn", "Leyla", "Nataly", "Braelynn", "Kiera", "Laylah", "Paislee", "Desiree", "Malaya", "Azalea", "Kensley", "Shiloh", "Brenda", "Lylah", "Addilyn", "Amiya", "Amya", "Maia", "Irene", "Ryan", "Jasmin", "Linda", "Adele", "Matilda", "Emelia", "Emmy", "Juniper", "Saige", "Ciara", "Estrella", "Jaylee", "Jemma", "Meredith", "Myah", "Rosa", "Teresa", "Yareli", "Kimber", "Madyson", "Claudia", "Maryam", "Zoie", "Kathleen", "Mira", "Paityn", "Isabela", "Perla", "Sariah", "Sherlyn", "Paola", "Shayla", "Winter", "Mae", "Simone", "Laney", "Pearl", "Ansley", "Jazlynn", "Patricia", "Aliana", "Brenna", "Armani", "Giana", "Lindsay", "Natalee", "Lailah", "Siena", "Nancy", "Raquel", "Willa", "Lilianna", "Frances", "Halle", "Janessa", "Kynlee", "Tori", "Leanna", "Bryanna", "Ellen", "Alma", "Lizbeth", "Wendy", "Chaya", "Christine", "Elianna", "Mabel", "Clarissa", "Kassandra", "Mollie", "Charli", "Diamond", "Kristen", "Coraline", "Mckayla", "Ariah", "Arely", "Blair", "Edith", "Joslyn", "Hailee", "Jaylene", "Chanel", "Alia", "Reyna", "Casey", "Clare", "Dana", "Alena", "Averi", "Alissa", "Demi", "Aiyana", "Leona", "Kailee", "Karsyn", "Kallie", "Taryn", "Corinne", "Rayna", "Asia", "Jaylin", "Noemi", "Carlee", "Abbigail", "Aryana", "Ayleen", "Eileen", "Livia", "Lillianna", "Mara", "Danika", "Mina", "Aliya", "Paloma", "Aimee", "Kaya", "Kora", "Tabitha", "Denise", "Hadassah", "Kayden", "Monroe", "Briley", "Celia", "Sandra", "Elaine", "Hana", "Jolie", "Kristina", "Myra", "Milana", "Lisa", "Renata", "Zariyah", "Adrienne", "America", "Emmalee", "Zaniyah", "Celine", "Cherish", "Jaida", "Kimora", "Mariyah", "Avah", "Nola", "Iliana", "Chana", "Cindy", "Janiya", "Carolyn", "Marisol", "Maliah", "Galilea", "Kiana", "Milania", "Alaya", "Bryn", "Emory", "Lorelai", "Jocelynn", "Yamileth", "Martha", "Jenny", "Keyla", "Alyvia", "Wren", "Dorothy", "Jordynn", "Amirah", "Nathaly", "Taliyah", "Zaria", "Deborah", "Elin", "Rylan", "Aubrianna", "Yasmin", "Julianne", "Zion", "Roselyn", "Salma", "Ivanna", "Joyce", "Paulina", "Lilith", "Saniyah", "Janae", "Aubrielle", "Ayanna", "Henley", "Sutton", "Aurelia", "Lesly", "Remi", "Britney", "Heather", "Barbara", "Bryleigh", "Emmalynn", "Kaitlynn", "Elliot", "Milena", "Susan", "Ariyah", "Kyndall", "Paula", "Thalia", "Aubri", "Kaleigh", "Tegan", "Yaritza", "Angeline", "Mercy", "Kairi", "Kourtney", "Krystal", "Carla", "Carter", "Mercedes", "Alannah", "Lina", "Sonia", "Kenia", "Everleigh", "Ivory", "Sloan", "Abril", "Alisha", "Katalina", "Carlie", "Lara", "Laurel", "Scarlette", "Carley", "Dixie", "Miya", "Micah", "Regan", "Samiyah", "Charlize", "Sharon", "Rosie", "Aviana", "Aleigha", "Gwyneth", "Sky", "Estella", "Hadlee", "Luz", "Patience", "Temperance", "Ingrid", "Raina", "Libby", "Jurnee", "Zahra", "Belen", "Jewel", "Anabel", "Marianna", "Renee", "Rory", "Elliott", "Karlie", "Saylor", "Deanna", "Freya", "Lilia", "Marjorie", "Sidney", "Tara", "Azaria", "Campbell", "Kai", "Ann", "Destinee", "Ariya", "Lilyanna", "Avianna", "Macey", "Shannon", "Lennon", "Saniya", "Haleigh", "Jolene", "Liv", "Oakley", "Esme", "Hunter", "Aliza", "Amalia", "Annalee", "Evalyn", "Giavanna", "Karis", "Kaylen", "Rayne", "Audriana", "Emerie", "Giada", "Harlee", "Kori", "Margot", "Abrielle", "Ellison", "Gwen", "Moriah", "Wynter", "Alisson", "Belinda", "Cristina", "Lillyana", "Neriah", "Rihanna", "Tamia", "Rivka", "Annabell", "Araceli", "Ayana", "Emmaline", "Giovanna", "Kylah", "Kailani", "Karissa", "Nahla", "Zainab", "Devyn", "Karma", "Marleigh", "Meadow", "India", "Kaiya", "Sarahi", "Audrianna", "Natalya", "Bayleigh", "Estelle", "Kaidence", "Kaylyn", "Magnolia", "Princess", "Avalyn", "Ireland", "Jayde", "Roxanne", "Alaysia", "Amia", "Astrid", "Karly", "Dalilah", "Makena", "Penny", "Ryann", "Charity", "Judith", "Kenna", "Tess", "Tinley", "Collins", "Noah", "Liam", "Jacob", "Mason", "William", "Ethan", "Michael", "Alexander", "Jayden", "Daniel", "Elijah", "Aiden", "James", "Benjamin", "Matthew", "Jackson", "Logan", "David", "Anthony", "Joseph", "Joshua", "Andrew", "Lucas", "Gabriel", "Samuel", "Christopher", "John", "Dylan", "Isaac", "Ryan", "Nathan", "Carter", "Caleb", "Luke", "Christian", "Hunter", "Henry", "Owen", "Landon", "Jack", "Wyatt", "Jonathan", "Eli", "Isaiah", "Sebastian", "Jaxon", "Julian", "Brayden", "Gavin", "Levi", "Aaron", "Oliver", "Jordan", "Nicholas", "Evan", "Connor", "Charles", "Jeremiah", "Cameron", "Adrian", "Thomas", "Robert", "Tyler", "Colton", "Austin", "Jace", "Angel", "Dominic", "Josiah", "Brandon", "Ayden", "Kevin", "Zachary", "Parker", "Blake", "Jose", "Chase", "Grayson", "Jason", "Ian", "Bentley", "Adam", "Xavier", "Cooper", "Justin", "Nolan", "Hudson", "Easton", "Jase", "Carson", "Nathaniel", "Jaxson", "Kayden", "Brody", "Lincoln", "Luis", "Tristan", "Damian", "Camden", "Juan", "Vincent", "Bryson", "Ryder", "Asher", "Carlos", "Jesus", "Micah", "Maxwell", "Mateo", "Alex", "Max", "Leo", "Elias", "Cole", "Miles", "Silas", "Bryce", "Eric", "Brantley", "Sawyer", "Declan", "Braxton", "Kaiden", "Colin", "Timothy", "Santiago", "Antonio", "Giovanni", "Hayden", "Diego", "Leonardo", "Bryan", "Miguel", "Roman", "Jonah", "Steven", "Ivan", "Kaleb", "Wesley", "Richard", "Jaden", "Victor", "Ezra", "Joel", "Edward", "Jayce", "Aidan", "Preston", "Greyson", "Brian", "Kaden", "Ashton", "Alan", "Patrick", "Kyle", "Riley", "George", "Jesse", "Jeremy", "Marcus", "Harrison", "Jude", "Weston", "Ryker", "Alejandro", "Jake", "Axel", "Grant", "Maddox", "Theodore", "Emmanuel", "Cayden", "Emmett", "Brady", "Bradley", "Gael", "Malachi", "Oscar", "Abel", "Tucker", "Jameson", "Caden", "Abraham", "Mark", "Sean", "Ezekiel", "Kenneth", "Gage", "Everett", "Kingston", "Nicolas", "Zayden", "King", "Bennett", "Calvin", "Avery", "Tanner", "Paul", "Kai", "Maximus", "Rylan", "Luca", "Graham", "Omar", "Derek", "Jayceon", "Jorge", "Peter", "Peyton", "Devin", "Collin", "Andres", "Jaiden", "Cody", "Zane", "Amir", "Corbin", "Francisco", "Xander", "Eduardo", "Conner", "Javier", "Jax", "Myles", "Griffin", "Iker", "Garrett", "Damien", "Simon", "Zander", "Seth", "Travis", "Charlie", "Cristian", "Trevor", "Zion", "Lorenzo", "Dean", "Gunner", "Chance", "Elliot", "Lukas", "Cash", "Elliott", "Israel", "Manuel", "Josue", "Jasper", "Keegan", "Finn", "Spencer", "Stephen", "Fernando", "Ricardo", "Mario", "Jeffrey", "Shane", "Clayton", "Reid", "Erick", "Cesar", "Paxton", "Martin", "Raymond", "Judah", "Trenton", "Johnny", "Andre", "Tyson", "Beau", "Landen", "Caiden", "Maverick", "Dominick", "Troy", "Kyler", "Hector", "Cruz", "Beckett", "Johnathan", "Donovan", "Edwin", "Kameron", "Marco", "Drake", "Edgar", "Holden", "Rafael", "Dante", "Jaylen", "Emiliano", "Waylon", "Andy", "Alexis", "Rowan", "Felix", "Drew", "Emilio", "Gregory", "Karter", "Brooks", "Dallas", "Lane", "Anderson", "Jared", "Skyler", "Angelo", "Shawn", "Aden", "Erik", "Dalton", "Fabian", "Sergio", "Milo", "Louis", "Titus", "Kendrick", "Braylon", "August", "Dawson", "Reed", "Emanuel", "Arthur", "Jett", "Leon", "Brendan", "Frank", "Marshall", "Emerson", "Desmond", "Derrick", "Colt", "Karson", "Messiah", "Zaiden", "Braden", "Amari", "Roberto", "Romeo", "Joaquin", "Malik", "Walter", "Brennan", "Pedro", "Knox", "Nehemiah", "Julius", "Grady", "Allen", "Ali", "Archer", "Kamden", "Dakota", "Maximiliano", "Ruben", "Quinn", "Barrett", "Tate", "Corey", "Adan", "Braylen", "Marcos", "Remington", "Phillip", "Kason", "Major", "Kellan", "Cohen", "Walker", "Gideon", "Taylor", "River", "Jayson", "Brycen", "Abram", "Cade", "Matteo", "Dillon", "Damon", "Dexter", "Kolton", "Phoenix", "Noel", "Brock", "Porter", "Philip", "Enrique", "Leland", "Ty", "Esteban", "Danny", "Jay", "Gerardo", "Keith", "Kellen", "Gunnar", "Armando", "Zachariah", "Orion", "Ismael", "Colby", "Pablo", "Ronald", "Atticus", "Trey", "Quentin", "Ryland", "Kash", "Raul", "Enzo", "Julio", "Darius", "Rodrigo", "Landyn", "Donald", "Bruce", "Jakob", "Kade", "Ari", "Keaton", "Albert", "Muhammad", "Rocco", "Solomon", "Rhett", "Cason", "Jaime", "Scott", "Chandler", "Mathew", "Maximilian", "Russell", "Dustin", "Ronan", "Tony", "Cyrus", "Jensen", "Hugo", "Saul", "Trent", "Deacon", "Davis", "Colten", "Malcolm", "Mohamed", "Devon", "Izaiah", "Randy", "Ibrahim", "Jerry", "Prince", "Tristen", "Alec", "Chris", "Dennis", "Clark", "Gustavo", "Mitchell", "Rory", "Jamison", "Leonel", "Finnegan", "Pierce", "Nash", "Kasen", "Khalil", "Darren", "Moses", "Issac", "Adriel", "Lawrence", "Braydon", "Jaxton", "Alberto", "Justice", "Curtis", "Larry", "Warren", "Zayne", "Yahir", "Jimmy", "Uriel", "Finley", "Nico", "Thiago", "Armani", "Jacoby", "Jonas", "Rhys", "Casey", "Tobias", "Frederick", "Jaxen", "Kobe", "Franklin", "Ricky", "Talon", "Ace", "Marvin", "Alonzo", "Arjun", "Jalen", "Alfredo", "Moises", "Sullivan", "Francis", "Case", "Brayan", "Alijah", "Arturo", "Lawson", "Raylan", "Mekhi", "Nikolas", "Carmelo", "Byron", "Nasir", "Reece", "Royce", "Sylas", "Ahmed", "Mauricio", "Beckham", "Roy", "Payton", "Raiden", "Korbin", "Maurice", "Ellis", "Aarav", "Johan", "Gianni", "Kayson", "Aldo", "Arian", "Isaias", "Jamari", "Kristopher", "Uriah", "Douglas", "Kane", "Milan", "Skylar", "Dorian", "Tatum", "Wade", "Cannon", "Quinton", "Bryant", "Toby", "Dane", "Sam", "Moshe", "Asa", "Mohammed", "Joe", "Kieran", "Roger", "Channing", "Daxton", "Ezequiel", "Orlando", "Matias", "Malakai", "Nathanael", "Zackary", "Boston", "Ahmad", "Dominik", "Lance", "Alvin", "Conor", "Odin", "Cullen", "Mohammad", "Deandre", "Benson", "Gary", "Blaine", "Carl", "Sterling", "Nelson", "Kian", "Salvador", "Luka", "Nikolai", "Nixon", "Niko", "Bowen", "Kyrie", "Brenden", "Callen", "Vihaan", "Luciano", "Terry", "Demetrius", "Raphael", "Ramon", "Xzavier", "Amare", "Rohan", "Reese", "Quincy", "Eddie", "Noe", "Yusuf", "London", "Hayes", "Jefferson", "Matthias", "Kelvin", "Terrance", "Madden", "Bentlee", "Layne", "Harvey", "Sincere", "Kristian", "Julien", "Melvin", "Harley", "Emmitt", "Neil", "Rodney", "Winston", "Hank", "Ayaan", "Ernesto", "Jeffery", "Alessandro", "Lucian", "Rex", "Wilson", "Mathias", "Memphis", "Princeton", "Santino", "Jon", "Tripp", "Lewis", "Trace", "Dax", "Eden", "Joey", "Nickolas", "Neymar", "Bruno", "Marc", "Crosby", "Cory", "Kendall", "Abdullah", "Allan", "Davion", "Hamza", "Soren", "Brentley", "Jasiah", "Edison", "Harper", "Tommy", "Morgan", "Zain", "Flynn", "Roland", "Theo", "Chad", "Lee", "Bobby", "Rayan", "Samson", "Brett", "Kylan", "Branson", "Bronson", "Ray", "Arlo", "Lennox", "Stanley", "Zechariah", "Kareem", "Micheal", "Reginald", "Alonso", "Casen", "Guillermo", "Leonard", "Augustus", "Tomas", "Billy", "Conrad", "Aryan", "Makai", "Elisha", "Westin", "Otto", "Adonis", "Jagger", "Keagan", "Dayton", "Leonidas", "Kyson", "Brodie", "Alden", "Aydin", "Valentino", "Harry", "Willie", "Yosef", "Braeden", "Marlon", "Terrence", "Lamar", "Shaun", "Aron", "Blaze", "Layton", "Duke", "Legend", "Jessie", "Terrell", "Clay", "Dwayne", "Felipe", "Kamari", "Gerald", "Kody", "Kole", "Maxim", "Omari", "Chaim", "Crew", "Lionel", "Vicente", "Bo", "Sage", "Rogelio", "Jermaine", "Gauge", "Will", "Emery", "Giovani", "Ronnie", "Elian", "Hendrix", "Javon", "Rayden", "Alexzander", "Ben", "Camron", "Jamarion", "Kolby", "Remy", "Jamal", "Urijah", "Jaydon", "Kyree", "Ariel", "Braiden", "Cassius", "Triston", "Jerome", "Junior", "Landry", "Wayne", "Killian", "Jamie", "Davian", "Lennon", "Samir", "Oakley", "Rene", "Ronin", "Tristian", "Darian", "Giancarlo", "Jadiel", "Amos", "Eugene", "Mayson", "Vincenzo", "Alfonso", "Brent", "Cain", "Callan", "Leandro", "Callum", "Darrell", "Atlas", "Fletcher", "Jairo", "Jonathon", "Kenny", "Tyrone", "Adrien", "Markus", "Thaddeus", "Zavier", "Marcel", "Marquis", "Misael", "Abdiel", "Draven", "Ishaan", "Lyric", "Ulises", "Jamir", "Marcelo", "Davin", "Bodhi", "Justus", "Mack", "Rudy", "Cedric", "Craig", "Frankie", "Javion", "Maxton", "Deshawn", "Jair", "Duncan", "Hassan", "Gibson", "Isiah", "Cayson", "Darwin", "Kale", "Kolten", "Lucca", "Kase", "Konner", "Konnor", "Randall", "Azariah", "Stefan", "Enoch", "Kymani", "Dominique", "Maximo", "Van", "Forrest", "Alvaro", "Gannon", "Jordyn", "Rolando", "Sonny", "Brice", "Coleman", "Yousef", "Aydan", "Ean", "Johnathon", "Quintin", "Semaj", "Cristopher", "Harlan", "Vaughn", "Zeke", "Axton", "Damion", "Jovanni", "Fisher", "Heath", "Ramiro", "Seamus", "Vance", "Yael", "Jadon", "Kamdyn", "Rashad", "Camdyn", "Jedidiah", "Santos", "Steve", "Chace", "Marley", "Brecken", "Kamryn", "Valentin", "Dilan", "Mike", "Krish", "Salvatore", "Brantlee", "Gilbert", "Turner", "Camren", "Franco", "Hezekiah", "Zaid", "Anders", "Deangelo", "Harold", "Joziah", "Mustafa", "Emory", "Jamar", "Reuben", "Royal", "Zayn", "Arnav", "Bently", "Gavyn", "Ares", "Ameer", "Juelz", "Rodolfo", "Titan", "Bridger", "Briggs", "Cortez", "Blaise", "Demarcus", "Rey", "Hugh", "Benton", "Giovanny", "Tristin", "Aidyn", "Jovani", "Jaylin", "Jorden", "Kaeden", "Clinton", "Efrain", "Kingsley", "Makhi", "Aditya", "Teagan", "Jericho", "Kamron", "Xavi", "Ernest", "Kaysen", "Zaire", "Deon", "Foster", "Lochlan", "Gilberto", "Gino", "Izayah", "Maison", "Miller", "Antoine", "Garrison", "Rylee", "Cristiano", "Dangelo", "Keenan", "Stetson", "Truman", "Brysen", "Jaycob", "Kohen", "Augustine", "Castiel", "Langston", "Magnus", "Osvaldo", "Reagan", "Sidney", "Tyree", "Yair", "Deegan", "Kalel", "Todd", "Alfred", "Anson", "Apollo", "Rowen", "Santana", "Ephraim", "Houston", "Jayse", "Leroy", "Pierre", "Tyrell", "Camryn", "Grey", "Yadiel", "Aaden", "Corban", "Denzel", "Jordy", "Kannon", "Branden", "Brendon", "Brenton", "Dario", "Jakobe", "Lachlan", "Thatcher", "Immanuel", "Camilo", "Davon", "Graeme", "Rocky", "Broderick", "Clyde", "Darien",
	};

	static const std::vector<const char*> name1_list
    {
        // Source: http://names.mongabay.com/data/1000.html
        "Smith", "Johnson", "Williams", "Brown", "Jones", "Miller", "Davis", "Garcia", "Rodriguez", "Wilson", "Martinez", "Anderson", "Taylor", "Thomas", "Hernandez", "Moore", "Martin", "Jackson", "Thompson", "White", "Lopez", "Lee", "Gonzalez", "Harris", "Clark", "Lewis", "Robinson", "Walker", "Perez", "Hall", "Young", "Allen", "Sanchez", "Wright", "King", "Scott", "Green", "Baker", "Adams", "Nelson", "Hill", "Ramirez", "Campbell", "Mitchell", "Roberts", "Carter", "Phillips", "Evans", "Turner", "Torres", "Parker", "Collins", "Edwards", "Stewart", "Flores", "Morris", "Nguyen", "Murphy", "Rivera", "Cook", "Rogers", "Morgan", "Peterson", "Cooper", "Reed", "Bailey", "Bell", "Gomez", "Kelly", "Howard", "Ward", "Cox", "Diaz", "Richardson", "Wood", "Watson", "Brooks", "Bennett", "Gray", "James", "Reyes", "Cruz", "Hughes", "Price", "Myers", "Long", "Foster", "Sanders", "Ross", "Morales", "Powell", "Sullivan", "Russell", "Ortiz", "Jenkins", "Gutierrez", "Perry", "Butler", "Barnes", "Fisher", "Henderson", "Coleman", "Simmons", "Patterson", "Jordan", "Reynolds", "Hamilton", "Graham", "Kim", "Gonzales", "Alexander", "Ramos", "Wallace", "Griffin", "West", "Cole", "Hayes", "Chavez", "Gibson", "Bryant", "Ellis", "Stevens", "Murray", "Ford", "Marshall", "Owens", "Mcdonald", "Harrison", "Ruiz", "Kennedy", "Wells", "Alvarez", "Woods", "Mendoza", "Castillo", "Olson", "Webb", "Washington", "Tucker", "Freeman", "Burns", "Henry", "Vasquez", "Snyder", "Simpson", "Crawford", "Jimenez", "Porter", "Mason", "Shaw", "Gordon", "Wagner", "Hunter", "Romero", "Hicks", "Dixon", "Hunt", "Palmer", "Robertson", "Black", "Holmes", "Stone", "Meyer", "Boyd", "Mills", "Warren", "Fox", "Rose", "Rice", "Moreno", "Schmidt", "Patel", "Ferguson", "Nichols", "Herrera", "Medina", "Ryan", "Fernandez", "Weaver", "Daniels", "Stephens", "Gardner", "Payne", "Kelley", "Dunn", "Pierce", "Arnold", "Tran", "Spencer", "Peters", "Hawkins", "Grant", "Hansen", "Castro", "Hoffman", "Hart", "Elliott", "Cunningham", "Knight", "Bradley", "Carroll", "Hudson", "Duncan", "Armstrong", "Berry", "Andrews", "Johnston", "Ray", "Lane", "Riley", "Carpenter", "Perkins", "Aguilar", "Silva", "Richards", "Willis", "Matthews", "Chapman", "Lawrence", "Garza", "Vargas", "Watkins", "Wheeler", "Larson", "Carlson", "Harper", "George", "Greene", "Burke", "Guzman", "Morrison", "Munoz", "Jacobs", "Obrien", "Lawson", "Franklin", "Lynch", "Bishop", "Carr", "Salazar", "Austin", "Mendez", "Gilbert", "Jensen", "Williamson", "Montgomery", "Harvey", "Oliver", "Howell", "Dean", "Hanson", "Weber", "Garrett", "Sims", "Burton", "Fuller", "Soto", "Mccoy", "Welch", "Chen", "Schultz", "Walters", "Reid", "Fields", "Walsh", "Little", "Fowler", "Bowman", "Davidson", "May", "Day", "Schneider", "Newman", "Brewer", "Lucas", "Holland", "Wong", "Banks", "Santos", "Curtis", "Pearson", "Delgado", "Valdez", "Pena", "Rios", "Douglas", "Sandoval", "Barrett", "Hopkins", "Keller", "Guerrero", "Stanley", "Bates", "Alvarado", "Beck", "Ortega", "Wade", "Estrada", "Contreras", "Barnett", "Caldwell", "Santiago", "Lambert", "Powers", "Chambers", "Nunez", "Craig", "Leonard", "Lowe", "Rhodes", "Byrd", "Gregory", "Shelton", "Frazier", "Becker", "Maldonado", "Fleming", "Vega", "Sutton", "Cohen", "Jennings", "Parks", "Mcdaniel", "Watts", "Barker", "Norris", "Vaughn", "Vazquez", "Holt", "Schwartz", "Steele", "Benson", "Neal", "Dominguez", "Horton", "Terry", "Wolfe", "Hale", "Lyons", "Graves", "Haynes", "Miles", "Park", "Warner", "Padilla", "Bush", "Thornton", "Mccarthy", "Mann", "Zimmerman", "Erickson", "Fletcher", "Mckinney", "Page", "Dawson", "Joseph", "Marquez", "Reeves", "Klein", "Espinoza", "Baldwin", "Moran", "Love", "Robbins", "Higgins", "Ball", "Cortez", "Le", "Griffith", "Bowen", "Sharp", "Cummings", "Ramsey", "Hardy", "Swanson", "Barber", "Acosta", "Luna", "Chandler", "Blair", "Daniel", "Cross", "Simon", "Dennis", "Oconnor", "Quinn", "Gross", "Navarro", "Moss", "Fitzgerald", "Doyle", "Mclaughlin", "Rojas", "Rodgers", "Stevenson", "Singh", "Yang", "Figueroa", "Harmon", "Newton", "Paul", "Manning", "Garner", "Mcgee", "Reese", "Francis", "Burgess", "Adkins", "Goodman", "Curry", "Brady", "Christensen", "Potter", "Walton", "Goodwin", "Mullins", "Molina", "Webster", "Fischer", "Campos", "Avila", "Sherman", "Todd", "Chang", "Blake", "Malone", "Wolf", "Hodges", "Juarez", "Gill", "Farmer", "Hines", "Gallagher", "Duran", "Hubbard", "Cannon", "Miranda", "Wang", "Saunders", "Tate", "Mack", "Hammond", "Carrillo", "Townsend", "Wise", "Ingram", "Barton", "Mejia", "Ayala", "Schroeder", "Hampton", "Rowe", "Parsons", "Frank", "Waters", "Strickland", "Osborne", "Maxwell", "Chan", "Deleon", "Norman", "Harrington", "Casey", "Patton", "Logan", "Bowers", "Mueller", "Glover", "Floyd", "Hartman", "Buchanan", "Cobb", "French", "Kramer", "Mccormick", "Clarke", "Tyler", "Gibbs", "Moody", "Conner", "Sparks", "Mcguire", "Leon", "Bauer", "Norton", "Pope", "Flynn", "Hogan", "Robles", "Salinas", "Yates", "Lindsey", "Lloyd", "Marsh", "Mcbride", "Owen", "Solis", "Pham", "Lang", "Pratt", "Lara", "Brock", "Ballard", "Trujillo", "Shaffer", "Drake", "Roman", "Aguirre", "Morton", "Stokes", "Lamb", "Pacheco", "Patrick", "Cochran", "Shepherd", "Cain", "Burnett", "Hess", "Li", "Cervantes", "Olsen", "Briggs", "Ochoa", "Cabrera", "Velasquez", "Montoya", "Roth", "Meyers", "Cardenas", "Fuentes", "Weiss", "Hoover", "Wilkins", "Nicholson", "Underwood", "Short", "Carson", "Morrow", "Colon", "Holloway", "Summers", "Bryan", "Petersen", "Mckenzie", "Serrano", "Wilcox", "Carey", "Clayton", "Poole", "Calderon", "Gallegos", "Greer", "Rivas", "Guerra", "Decker", "Collier", "Wall", "Whitaker", "Bass", "Flowers", "Davenport", "Conley", "Houston", "Huff", "Copeland", "Hood", "Monroe", "Massey", "Roberson", "Combs", "Franco", "Larsen", "Pittman", "Randall", "Skinner", "Wilkinson", "Kirby", "Cameron", "Bridges", "Anthony", "Richard", "Kirk", "Bruce", "Singleton", "Mathis", "Bradford", "Boone", "Abbott", "Charles", "Allison", "Sweeney", "Atkinson", "Horn", "Jefferson", "Rosales", "York", "Christian", "Phelps", "Farrell", "Castaneda", "Nash", "Dickerson", "Bond", "Wyatt", "Foley", "Chase", "Gates", "Vincent", "Mathews", "Hodge", "Garrison", "Trevino", "Villarreal", "Heath", "Dalton", "Valencia", "Callahan", "Hensley", "Atkins", "Huffman", "Roy", "Boyer", "Shields", "Lin", "Hancock", "Grimes", "Glenn", "Cline", "Delacruz", "Camacho", "Dillon", "Parrish", "Oneill", "Melton", "Booth", "Kane", "Berg", "Harrell", "Pitts", "Savage", "Wiggins", "Brennan", "Salas", "Marks", "Russo", "Sawyer", "Baxter", "Golden", "Hutchinson", "Liu", "Walter", "Mcdowell", "Wiley", "Rich", "Humphrey", "Johns", "Koch", "Suarez", "Hobbs", "Beard", "Gilmore", "Ibarra", "Keith", "Macias", "Khan", "Andrade", "Ware", "Stephenson", "Henson", "Wilkerson", "Dyer", "Mcclure", "Blackwell", "Mercado", "Tanner", "Eaton", "Clay", "Barron", "Beasley", "Oneal", "Preston", "Small", "Wu", "Zamora", "Macdonald", "Vance", "Snow", "Mcclain", "Stafford", "Orozco", "Barry", "English", "Shannon", "Kline", "Jacobson", "Woodard", "Huang", "Kemp", "Mosley", "Prince", "Merritt", "Hurst", "Villanueva", "Roach", "Nolan", "Lam", "Yoder", "Mccullough", "Lester", "Santana", "Valenzuela", "Winters", "Barrera", "Leach", "Orr", "Berger", "Mckee", "Strong", "Conway", "Stein", "Whitehead", "Bullock", "Escobar", "Knox", "Meadows", "Solomon", "Velez", "Odonnell", "Kerr", "Stout", "Blankenship", "Browning", "Kent", "Lozano", "Bartlett", "Pruitt", "Buck", "Barr", "Gaines", "Durham", "Gentry", "Mcintyre", "Sloan", "Melendez", "Rocha", "Herman", "Sexton", "Moon", "Hendricks", "Rangel", "Stark", "Lowery", "Hardin", "Hull", "Sellers", "Ellison", "Calhoun", "Gillespie", "Mora", "Knapp", "Mccall", "Morse", "Dorsey", "Weeks", "Nielsen", "Livingston", "Leblanc", "Mclean", "Bradshaw", "Glass", "Middleton", "Buckley", "Schaefer", "Frost", "Howe", "House", "Mcintosh", "Ho", "Pennington", "Reilly", "Hebert", "Mcfarland", "Hickman", "Noble", "Spears", "Conrad", "Arias", "Galvan", "Velazquez", "Huynh", "Frederick", "Randolph", "Cantu", "Fitzpatrick", "Mahoney", "Peck", "Villa", "Michael", "Donovan", "Mcconnell", "Walls", "Boyle", "Mayer", "Zuniga", "Giles", "Pineda", "Pace", "Hurley", "Mays", "Mcmillan", "Crosby", "Ayers", "Case", "Bentley", "Shepard", "Everett", "Pugh", "David", "Mcmahon", "Dunlap", "Bender", "Hahn", "Harding", "Acevedo", "Raymond", "Blackburn", "Duffy", "Landry", "Dougherty", "Bautista", "Shah", "Potts", "Arroyo", "Valentine", "Meza", "Gould", "Vaughan", "Fry", "Rush", "Avery", "Herring", "Dodson", "Clements", "Sampson", "Tapia", "Bean", "Lynn", "Crane", "Farley", "Cisneros", "Benton", "Ashley", "Mckay", "Finley", "Best", "Blevins", "Friedman", "Moses", "Sosa", "Blanchard", "Huber", "Frye", "Krueger", "Bernard", "Rosario", "Rubio", "Mullen", "Benjamin", "Haley", "Chung", "Moyer", "Choi", "Horne", "Yu", "Woodward", "Ali", "Nixon", "Hayden", "Rivers", "Estes", "Mccarty", "Richmond", "Stuart", "Maynard", "Brandt", "Oconnell", "Hanna", "Sanford", "Sheppard", "Church", "Burch", "Levy", "Rasmussen", "Coffey", "Ponce", "Faulkner", "Donaldson", "Schmitt", "Novak", "Costa", "Montes", "Booker", "Cordova", "Waller", "Arellano", "Maddox", "Mata", "Bonilla", "Stanton", "Compton", "Kaufman", "Dudley", "Mcpherson", "Beltran", "Dickson", "Mccann", "Villegas", "Proctor", "Hester", "Cantrell", "Daugherty", "Cherry", "Bray", "Davila", "Rowland", "Levine", "Madden", "Spence", "Good", "Irwin", "Werner", "Krause", "Petty", "Whitney", "Baird", "Hooper", "Pollard", "Zavala", "Jarvis", "Holden", "Haas", "Hendrix", "Mcgrath", "Bird", "Lucero", "Terrell", "Riggs", "Joyce", "Mercer", "Rollins", "Galloway", "Duke", "Odom", "Andersen", "Downs", "Hatfield", "Benitez", "Archer", "Huerta", "Travis", "Mcneil", "Hinton", "Zhang", "Hays", "Mayo", "Fritz", "Branch", "Mooney", "Ewing", "Ritter", "Esparza", "Frey", "Braun", "Gay", "Riddle", "Haney", "Kaiser", "Holder", "Chaney", "Mcknight", "Gamble", "Vang", "Cooley", "Carney", "Cowan", "Forbes", "Ferrell", "Davies", "Barajas", "Shea", "Osborn", "Bright", "Cuevas", "Bolton", "Murillo", "Lutz", "Duarte", "Kidd", "Key", "Cooke",
	};

#if QT_VERSION < QT_VERSION_CHECK( 5, 10, 0 )
    auto index_first_name = randombytes_uniform(name0_list.size());
    auto index_last_name = randombytes_uniform(name1_list.size());
    // qDebug() << QString("GetRandomGroupusername:") << name0_list.size() << name1_list.size() << index_first_name << index_last_name;
#else
    int index_first_name = QRandomGenerator::global()->generate() % name0_list.size();
    int index_last_name = QRandomGenerator::global()->generate() % name1_list.size();
#endif

	return QString::fromStdString(name0_list[index_first_name])
        + QString(" ")
        + QString::fromStdString(name1_list[index_last_name]);
}

void Core::onNgcInvite(Tox* tox, uint32_t friendId, const uint8_t* invite_data, size_t length,
                       const uint8_t *group_name, size_t group_name_length, void* vCore)
{
    std::ignore = group_name;
    std::ignore = group_name_length;
    Core* core = static_cast<Core*>(vCore);
    qDebug() << QString("NGC group invite by %1").arg(friendId);

    auto user_name = core->GetRandomGroupusername();
    auto user_name_len = user_name.toUtf8().size();

    Tox_Err_Group_Invite_Accept error;
    uint32_t groupId = tox_group_invite_accept(
                        tox,
                        friendId,
                        invite_data,
                        length,
                        reinterpret_cast<const uint8_t*>(user_name.toUtf8().constData()),
                        user_name_len,
                        NULL, 0,  &error);
    if (groupId == UINT32_MAX) {
        qDebug() << QString("NGC group invite by %1: FAILED").arg(friendId);
    } else {
        qDebug() << QString("NGC group invite by %1: OK").arg(friendId);
        emit core->saveRequest();
        emit core->groupJoined((Settings::NGC_GROUPNUM_OFFSET + groupId), core->getGroupPersistentId(groupId, 1));
    }
}

void Core::onNgcSelfJoin(Tox* tox, uint32_t group_number, void* vCore)
{
    std::ignore = tox;
    Core* core = static_cast<Core*>(vCore);
    qDebug() << QString("onNgcSelfJoin:gn #%1").arg(group_number);
    Tox_Err_Group_State_Queries error;
    QString name;
    size_t titleSize = tox_group_get_name_size(tox, group_number, &error);
    const GroupId persistentId = core->getGroupPersistentId(group_number, 1);
    const QString defaultName = persistentId.toString().left(8);
    if (PARSE_ERR(error) || !titleSize) {
        std::vector<uint8_t> nameBuf(titleSize);
        tox_group_get_name(tox, group_number, nameBuf.data(), &error);
        if (PARSE_ERR(error)) {
            name = ToxString(nameBuf.data(), titleSize).getQString();
        } else {
            name = defaultName;
        }
    } else {
        name = defaultName;
    }
    emit core->NGCGroupSetTitle((Settings::NGC_GROUPNUM_OFFSET + group_number), persistentId, name);
    emit core->saveRequest();
}

void Core::onNgcPeerName(Tox *tox, uint32_t group_number, uint32_t peer_id, const uint8_t *name,
                                    size_t length, void *vCore)
{
    std::ignore = tox;
    std::ignore = name;
    std::ignore = length;
    Core* core = static_cast<Core*>(vCore);
    qDebug() << QString("onNgcPeerName:peer_id") << peer_id;
    emit core->groupPeerlistChanged(Settings::NGC_GROUPNUM_OFFSET + group_number);
    emit core->saveRequest();
}

void Core::onNgcPeerExit(Tox *tox, uint32_t group_number, uint32_t peer_id, Tox_Group_Exit_Type exit_type,
                                    const uint8_t *name, size_t name_length, const uint8_t *part_message, size_t length, void *vCore)
{
    std::ignore = tox;
    std::ignore = name;
    std::ignore = name_length;
    std::ignore = part_message;
    std::ignore = length;
    Core* core = static_cast<Core*>(vCore);
    qDebug() << QString("onNgcPeerExit:peer_id") << peer_id << "exit type" << exit_type;
    emit core->groupPeerlistChanged(Settings::NGC_GROUPNUM_OFFSET + group_number);
    emit core->saveRequest();
}

void Core::onNgcPeerJoin(Tox* tox, uint32_t group_number, uint32_t peer_id, void* vCore)
{
    std::ignore = tox;
    std::ignore = group_number;
    Core* core = static_cast<Core*>(vCore);

    auto peerPk = core->getGroupPeerPk((Settings::NGC_GROUPNUM_OFFSET + group_number), peer_id);

    Tox_Err_Group_Peer_Query error;
    size_t name_length = tox_group_peer_get_name_size(tox, group_number, peer_id, &error);
    if ((name_length > 0) && (name_length < 500)) {
        uint8_t *name = reinterpret_cast<uint8_t*>(calloc(1, name_length + 1));
        if (name) {
            bool res = tox_group_peer_get_name(tox, group_number, peer_id, name, &error);
            if (res) {
                const auto newName = ToxString(name, name_length).getQString();
                emit core->groupPeerlistChanged(Settings::NGC_GROUPNUM_OFFSET + group_number);
            }
            free(name);
        }
    }

    qDebug() << QString("onNgcPeerJoin:peer #%1").arg(peer_id);
    emit core->saveRequest();
}

void Core::onNgcGroupMessage(Tox* tox, uint32_t group_number, uint32_t peer_id, Tox_Message_Type type,
                             const uint8_t *message, size_t length, uint32_t message_id, void* vCore)
{
    std::ignore = tox;
    std::ignore = type;
    Core* core = static_cast<Core*>(vCore);
    QString msg = ToxString(message, length).getQString();
    uint32_t message_id_hostenc;
    const uint8_t *p = reinterpret_cast<const uint8_t *>(&message_id);
    xnet_unpack_u32(p, &message_id_hostenc);
    QByteArray msgIdhash = QByteArray(reinterpret_cast<const char*>(&message_id_hostenc), 4);
    // qDebug() << "msgIdhash:" << QString::fromUtf8(msgIdhash.toHex()).toUpper();
    msg = QString::fromUtf8(msgIdhash.toHex()).toUpper().rightJustified(8, '0') + QString(":") + msg;

    // const bool isGuiThread = QThread::currentThread() == QCoreApplication::instance()->thread();
    // qDebug() << QString("onNgcGroupMessage:THREAD:TOX:010:") << QThread::currentThreadId() << "isGuiThread" << isGuiThread;

    auto peerPk = core->getGroupPeerPk((Settings::NGC_GROUPNUM_OFFSET + group_number), peer_id);
    emit core->groupMessageReceived((Settings::NGC_GROUPNUM_OFFSET + group_number), peer_id, msg,
        false, false, static_cast<int>(Widget::MessageHasIdType::NGC_MSG_ID));
}

void Core::onNgcGroupPrivateMessage(Tox* tox, uint32_t group_number, uint32_t peer_id, Tox_Message_Type type,
        const uint8_t *message, size_t length, void* vCore)
{
    std::ignore = tox;
    Core* core = static_cast<Core*>(vCore);
    std::ignore = type;
    QString msg = ToxString(message, length).getQString();
    qDebug() << QString("onNgcGroupPrivateMessage:peer=") << peer_id;
    emit core->groupMessageReceived((Settings::NGC_GROUPNUM_OFFSET + group_number),
        peer_id, QString("________:Private Message:") + msg,
        false, true, static_cast<int>(Widget::MessageHasIdType::NGC_MSG_ID));
}

void Core::onNgcGroupCustomPacket(Tox* tox, uint32_t group_number, uint32_t peer_id, const uint8_t *data,
        size_t length, void* vCore)
{
    std::ignore = tox;
    Core* core = static_cast<Core*>(vCore);
    std::ignore = length;
    qDebug() << QString("onNgcGroupCustomPacket:peer=") << peer_id << QString("length=") << length;
    const bool isGuiThread = QThread::currentThread() == QCoreApplication::instance()->thread();
    qDebug() << QString("onNgcGroupCustomPacket:THREAD:TOX:011:") << QThread::currentThreadId() << "isGuiThread" << isGuiThread;

    size_t header_len = 6 + 1 + 1 + 32 + 4 + 255;
    if (length > header_len)
    {
        if (
            (data[0] == 0x66) &&
            (data[1] == 0x77) &&
            (data[2] == 0x88) &&
            (data[3] == 0x11) &&
            (data[4] == 0x34) &&
            (data[5] == 0x35))
        {
            if ((data[6] == 0x1) && (data[7] == 0x11))
            {
                // HINT: ok we have a group file
                auto peerPk = core->getGroupPeerPk((Settings::NGC_GROUPNUM_OFFSET + group_number), peer_id);
                QByteArray image_data_bytes = QByteArray(reinterpret_cast<const char*>(data + header_len), (length - header_len));
                emit core->groupMessageReceivedImage((Settings::NGC_GROUPNUM_OFFSET + group_number),
                    peer_id, image_data_bytes,
                    (length - header_len), false,
                    static_cast<int>(Widget::MessageHasIdType::NGC_MSG_ID));
            }
        }
    }
}

void Core::onNgcGroupCustomPrivatePacket(Tox* tox, uint32_t group_number, uint32_t peer_id, const uint8_t *data,
        size_t length, void* vCore)
{
    std::ignore = tox;
    Core* core = static_cast<Core*>(vCore);
    std::ignore = core;
    std::ignore = group_number;
    std::ignore = data;
    std::ignore = length;
    qDebug() << QString("onNgcGroupCustomPrivatePacket:group_number=") << group_number << "peer=" << peer_id << QString("length=") << length;


    Tox_Err_Group_Self_Query error;
    uint32_t res = tox_group_self_get_peer_id(tox, group_number, &error);

    if (error != TOX_ERR_GROUP_SELF_QUERY_OK)
    {
        qDebug() << QString("onNgcGroupCustomPrivatePacket:group_number=") << group_number
            << "peer=" << peer_id << QString("error=") << error;
        return;
    }

    if (res == peer_id)
    {
        // HINT: ignore own packets
        qDebug() << QString("onNgcGroupCustomPrivatePacket:group_number=") << group_number
            << "peer=" << peer_id << QString("ignoring own packet");
        return;
    }

    const size_t TOX_MAX_NGC_FILE_AND_HEADER_SIZE = 37000;
    const size_t header = 6 + 1 + 1;
    if ((length > TOX_MAX_NGC_FILE_AND_HEADER_SIZE) || (length < header))
    {
        qDebug() << QString("onNgcGroupCustomPrivatePacket: data length has wrong size:") << length;
        return;
    }

        if (
            (data[0] == 0x66) &&
            (data[1] == 0x77) &&
            (data[2] == 0x88) &&
            (data[3] == 0x11) &&
            (data[4] == 0x34) &&
            (data[5] == 0x35))
        {
            if ((data[6] == 0x1) && (data[7] == 0x1))
            {
                qDebug() << QString("onNgcGroupCustomPrivatePacket: got ngch_request");
                Tox_Err_Group_State_Queries error2;
                Tox_Group_Privacy_State privacy_state =
                    tox_group_get_privacy_state(tox, group_number, &error2);
                if (error2 != TOX_ERR_GROUP_STATE_QUERIES_OK)
                {
                    qDebug() << QString("onNgcGroupCustomPrivatePacket: tox_group_get_privacy_state: error=") << error2;
                    return;
                }

                if (privacy_state == TOX_GROUP_PRIVACY_STATE_PUBLIC)
                {
                    qDebug() << QString("onNgcGroupCustomPrivatePacket:sync_history:peer=") << peer_id;
                    auto peerPk = core->getGroupPeerPk((Settings::NGC_GROUPNUM_OFFSET + group_number), peer_id);
                    emit core->groupSyncHistoryReqReceived(
                        (Settings::NGC_GROUPNUM_OFFSET + group_number),
                        peer_id, peerPk);
                }
                else
                {
                    qDebug() << QString("onNgcGroupCustomPrivatePacket: only sync history for public groups!");
                }
            }
            else if ((data[6] == 0x1) && (data[7] == 0x2))
            {
                const int header_syncmsg = 6 + 1 + 1 + 4 + 32 + 4 + 25;
                if (length >= (header_syncmsg + 1))
                {
                    qDebug() << QString("onNgcGroupCustomPrivatePacket: got ngch_syncmsg");
                    // TODO: write me // handle_incoming_sync_group_message(group_number, peer_id, data, length);
                }
            }
            else if ((data[6] == 0x1) && (data[7] == 0x3))
            {
                qDebug() << QString("onNgcGroupCustomPrivatePacket: got ngch_syncfile:A");
                const int header_syncfile = 6 + 1 + 1 + 32 + 32 + 4 + 25 + 255;
                if (length >= (header_syncfile + 1))
                {
                    qDebug() << QString("onNgcGroupCustomPrivatePacket: got ngch_syncfile:B");
                    // TODO: write me // handle_incoming_sync_group_file(group_number, peer_id, data, length);
                }
            }
        }
}

void Core::onGroupMessage(Tox* tox, uint32_t groupId, uint32_t peerId, Tox_Message_Type type,
                          const uint8_t* cMessage, size_t length, void* vCore)
{
    std::ignore = tox;
    Core* core = static_cast<Core*>(vCore);
    bool isAction = type == TOX_MESSAGE_TYPE_ACTION;
    if (length > 9) {
        QString conf_msgid = ToxString(cMessage, 8).getQString();
        QString message_text = ToxString((cMessage + 9), (length - 9)).getQString();
        QString wrapped_message = conf_msgid.toUpper().rightJustified(8, '0') + QString(":") + message_text;
        // qDebug() << QString("onGroupMessage:wrapped_message:") << wrapped_message;
        emit core->groupMessageReceived(groupId, peerId, wrapped_message, isAction, false,
            static_cast<int>(Widget::MessageHasIdType::CONF_MSG_ID));
    } else {
        qWarning() << QString("onGroupMessage:group message length from tox less than 10. length:") << length;
    }
}

void Core::onGroupPeerListChange(Tox* tox, uint32_t groupId, void* vCore)
{
    std::ignore = tox;
    const auto core = static_cast<Core*>(vCore);
    qDebug() << QString("Group %1 peerlist changed").arg(groupId);
    // no saveRequest, this callback is called on every connection to group peer, not just on brand new peers
    emit core->groupPeerlistChanged(groupId);
}

void Core::onGroupPeerNameChange(Tox* tox, uint32_t groupId, uint32_t peerId, const uint8_t* name,
                                 size_t length, void* vCore)
{
    std::ignore = tox;
    const auto newName = ToxString(name, length).getQString();
    qDebug() << QString("Group %1, peer %2, name changed to %3").arg(groupId).arg(peerId).arg(newName);
    auto* core = static_cast<Core*>(vCore);
    auto peerPk = core->getGroupPeerPk(groupId, peerId);
    emit core->groupPeerNameChanged(groupId, peerPk, newName);
}

void Core::onGroupTitleChange(Tox* tox, uint32_t groupId, uint32_t peerId, const uint8_t* cTitle,
                              size_t length, void* vCore)
{
    std::ignore = tox;
    Core* core = static_cast<Core*>(vCore);
    QString author;
    // from tox.h: "If peer_number == UINT32_MAX, then author is unknown (e.g. initial joining the conference)."
    if (peerId != std::numeric_limits<uint32_t>::max()) {
        author = core->getGroupPeerName(groupId, peerId);
    }
    emit core->saveRequest();
    emit core->groupTitleChanged(groupId, author, ToxString(cTitle, length).getQString());
}

/**
 * @brief Handling of custom lossless packets received by toxcore. Currently only used to forward toxext packets to CoreExt
 */
void Core::onLosslessPacket(Tox* tox, uint32_t friendId,
                            const uint8_t* data, size_t length, void* vCore)
{
    std::ignore = tox;
    Core* core = static_cast<Core*>(vCore);
    //* disable toxext handling for now *// core->ext->onLosslessPacket(friendId, data, length);

    // zoff
    // qDebug() << "onLosslessPacket:fn=" << friendId << " data:" << (int)data[0] << (int)data[1] << (int)data[2];
    if (data[0] == 181) // HINT: pkt id for CONTROL_PROXY_MESSAGE_TYPE_PUSH_URL_FOR_FRIEND == 181
    {
        if (length > 5)
        {
            const uint8_t* data_str = data + 1;
            QString pushtoken = ToxString(data_str, (length - 1)).getQString();
            emit static_cast<Core*>(core)->friendPushtokenReceived(friendId, pushtoken);
        }
        else
        {
            qDebug() << "onLosslessPacket:DEL:Pushtoken";
            emit static_cast<Core*>(core)->friendPushtokenReceived(friendId, " ");
        }
    }
    // zoff
}

void Core::onReadReceiptCallback(Tox* tox, uint32_t friendId, uint32_t receipt, void* core)
{
    std::ignore = tox;
    emit static_cast<Core*>(core)->receiptRecieved(friendId, ReceiptNum{receipt});
}

void Core::acceptFriendRequest(const ToxPk& friendPk)
{
    QMutexLocker ml{&coreLoopLock};
    Tox_Err_Friend_Add error;
    uint32_t friendId = tox_friend_add_norequest(tox.get(), friendPk.getData(), &error);
    if (PARSE_ERR(error)) {
        emit saveRequest();
        emit friendAdded(friendId, friendPk);
    } else {
        emit failedToAddFriend(friendPk);
    }
}

/**
 * @brief Checks that sending friendship request is correct and returns error message accordingly
 * @param friendId Id of a friend which request is destined to
 * @param message Friendship request message
 * @return Returns empty string if sending request is correct, according error message otherwise
 */
QString Core::getFriendRequestErrorMessage(const ToxId& friendId, const QString& message) const
{
    QMutexLocker ml{&coreLoopLock};

    if (!friendId.isValid()) {
        return tr("Invalid Tox ID", "Error while sending friend request");
    }

    if (message.isEmpty()) {
        return tr("You need to write a message with your request",
                  "Error while sending friend request");
    }

    if (message.length() > static_cast<int>(tox_max_friend_request_length())) {
        return tr("Your message is too long!", "Error while sending friend request");
    }

    if (hasFriendWithPublicKey(friendId.getPublicKey())) {
        return tr("Friend is already added", "Error while sending friend request");
    }

    return QString{};
}

void Core::requestNgc(const QString& ngcId, const QString& message)
{
    QMutexLocker ml{&coreLoopLock};

    std::ignore = message;

    QByteArray ngcIdBytes = QByteArray::fromHex(ngcId.toLatin1());

    auto user_name = GetRandomGroupusername();
    auto user_name_len = user_name.toUtf8().size();
    qDebug() << QString("requestNgc join:1:my peer name=") << user_name << QString("user_name_len=") << user_name_len;

    Tox_Err_Group_Join error;
    // TODO: add password if needed
    uint32_t groupId = tox_group_join(tox.get(),
        reinterpret_cast<const uint8_t*>(ngcIdBytes.constData()),
        reinterpret_cast<const uint8_t*>(user_name.toUtf8().constData()),
        user_name_len,
        NULL,
        0,
        &error);

    if (groupId == UINT32_MAX) {
        qDebug() << "requestNgc join failed, error: " << error;
    } else {
        qDebug() << "requestNgc join OK, group num: " << groupId;
        emit saveRequest();
        emit groupJoined((Settings::NGC_GROUPNUM_OFFSET + groupId), getGroupPersistentId(groupId, 1));
    }
}

void Core::requestFriendship(const ToxId& friendId, const QString& message)
{
    QMutexLocker ml{&coreLoopLock};

    ToxPk friendPk = friendId.getPublicKey();
    QString errorMessage = getFriendRequestErrorMessage(friendId, message);
    if (!errorMessage.isNull()) {
        emit failedToAddFriend(friendPk, errorMessage);
        emit saveRequest();
        return;
    }

    ToxString cMessage(message);
    Tox_Err_Friend_Add error;
    uint32_t friendNumber =
        tox_friend_add(tox.get(), friendId.getBytes(), cMessage.data(), cMessage.size(), &error);
    if (PARSE_ERR(error)) {
        qDebug() << "Requested friendship from " << friendNumber;
        emit saveRequest();
        emit friendAdded(friendNumber, friendPk);
        emit requestSent(friendPk, message);
    } else {
        qDebug() << "Failed to send friend request";
        emit failedToAddFriend(friendPk);
    }
}

bool Core::sendMessageWithType(uint32_t friendId, const QString& message, const QString& id_or_hash, const QDateTime& timestamp,
                               Tox_Message_Type type, ReceiptNum& receipt)
{
    int size = message.toUtf8().size();
    auto maxSize = static_cast<int>(TOX_MSGV3_MAX_MESSAGE_LENGTH);
    if (size > maxSize) {
        assert(false);
        qCritical() << "Core::sendMessageWithType called with message of size:" << size
                    << "when max is:" << maxSize << ". Ignoring.";
        return false;
    }

    ToxString cMessage(message);

    uint8_t *message_str_v3 =
                    static_cast<uint8_t *>(calloc(1, (size_t)(
                    cMessage.size() + TOX_MSGV3_GUARD + TOX_MSGV3_MSGID_LENGTH + TOX_MSGV3_TIMESTAMP_LENGTH)));
    if (!message_str_v3)
    {
        return false;
    }

    uint32_t timestamp_unix = static_cast<uint32_t>((timestamp.toMSecsSinceEpoch() / 1000));
    uint32_t timestamp_unix_buf;
    xnet_pack_u32(reinterpret_cast<uint8_t*>(&timestamp_unix_buf), timestamp_unix);

    uint8_t* position = message_str_v3;
    memcpy(position, cMessage.data(), static_cast<size_t>(cMessage.size()));
    position = position + cMessage.size();
    position = position + TOX_MSGV3_GUARD;
    QByteArray hash_buffer_bytes = QByteArray::fromHex(id_or_hash.toLatin1());
    const uint8_t *hash_buffer_c = reinterpret_cast<const uint8_t*>(hash_buffer_bytes.constData());
    memcpy(position, hash_buffer_c, static_cast<size_t>(TOX_MSGV3_MSGID_LENGTH));
    position = position + TOX_MSGV3_MSGID_LENGTH;
    memcpy(position, &timestamp_unix_buf, static_cast<size_t>(TOX_MSGV3_TIMESTAMP_LENGTH));

    size_t new_len = cMessage.size() + TOX_MSGV3_GUARD + TOX_MSGV3_MSGID_LENGTH + TOX_MSGV3_TIMESTAMP_LENGTH;

    Tox_Err_Friend_Send_Message error;
    receipt = ReceiptNum{tox_friend_send_message(tox.get(), friendId, type, message_str_v3,
                                                 new_len, &error)};
    free(message_str_v3);

    if (PARSE_ERR(error)) {
        return true;
    }
    return false;
}

bool Core::sendMessage(uint32_t friendId, const QString& message, const QString& id_or_hash, const QDateTime& timestamp, ReceiptNum& receipt)
{
    QMutexLocker ml(&coreLoopLock);
    return sendMessageWithType(friendId, message, id_or_hash, timestamp, TOX_MESSAGE_TYPE_NORMAL, receipt);
}

bool Core::sendAction(uint32_t friendId, const QString& action, const QString& id_or_hash, const QDateTime& timestamp, ReceiptNum& receipt)
{
    QMutexLocker ml(&coreLoopLock);
    return sendMessageWithType(friendId, action, id_or_hash, timestamp, TOX_MESSAGE_TYPE_ACTION, receipt);
}

void Core::sendTyping(uint32_t friendId, bool typing)
{
    QMutexLocker ml{&coreLoopLock};

    Tox_Err_Set_Typing error;
    tox_self_set_typing(tox.get(), friendId, typing, &error);
    if (!PARSE_ERR(error)) {
        emit failedToSetTyping(typing);
    }
}

void Core::sendGroupMessageWithType(int groupId, const QString& message, Tox_Message_Type type)
{
    QMutexLocker ml{&coreLoopLock};

    if (groupId >= static_cast<int>(Settings::NGC_GROUPNUM_OFFSET)) {
        int size = message.toUtf8().size();
        auto maxSize = static_cast<int>(TOX_GROUP_MAX_MESSAGE_LENGTH);
        if (size > maxSize) {
            qCritical() << "Core::sendMessageWithType NGC called with message of size:" << size
                        << "when max is:" << maxSize << ". Ignoring.";
            return;
        }

        ToxString cMsg(message);
        Tox_Err_Group_Send_Message error;
        uint32_t message_id;
        tox_group_send_message(tox.get(), (groupId - Settings::NGC_GROUPNUM_OFFSET), type, cMsg.data(), cMsg.size(), &message_id, &error);
        if (!PARSE_ERR(error)) {
            emit groupSentFailed(groupId);
            return;
        }
    } else {
        int size = message.toUtf8().size();
        auto maxSize = static_cast<int>(getMaxMessageSize());
        if (size > maxSize) {
            qCritical() << "Core::sendMessageWithType called with message of size:" << size
                        << "when max is:" << maxSize << ". Ignoring.";
            return;
        }

        ToxString cMsg(message);
        Tox_Err_Conference_Send_Message error;
        tox_conference_send_message(tox.get(), groupId, type, cMsg.data(), cMsg.size(), &error);
        if (!PARSE_ERR(error)) {
            emit groupSentFailed(groupId);
            return;
        }
    }
}

void Core::sendGroupMessage(int groupId, const QString& message)
{
    QMutexLocker ml{&coreLoopLock};

    sendGroupMessageWithType(groupId, message, TOX_MESSAGE_TYPE_NORMAL);
}

void Core::sendGroupAction(int groupId, const QString& message)
{
    QMutexLocker ml{&coreLoopLock};

    sendGroupMessageWithType(groupId, message, TOX_MESSAGE_TYPE_ACTION);
}

void Core::changeGroupTitle(int groupId, const QString& title)
{
    QMutexLocker ml{&coreLoopLock};

    ToxString cTitle(title);
    Tox_Err_Conference_Title error;
    tox_conference_set_title(tox.get(), groupId, cTitle.data(), cTitle.size(), &error);
    if (PARSE_ERR(error)) {
        emit saveRequest();
        emit groupTitleChanged(groupId, getUsername(), title);
    }
}

void Core::removeFriend(uint32_t friendId)
{
    QMutexLocker ml{&coreLoopLock};

    Tox_Err_Friend_Delete error;
    tox_friend_delete(tox.get(), friendId, &error);
    if (!PARSE_ERR(error)) {
        emit failedToRemoveFriend(friendId);
        return;
    }

    emit saveRequest();
    emit friendRemoved(friendId);
}

void Core::removeGroup(int groupId)
{
    QMutexLocker ml{&coreLoopLock};

    if (groupId >= static_cast<int>(Settings::NGC_GROUPNUM_OFFSET)) {
        Tox_Err_Group_Leave error;
        tox_group_leave(tox.get(), (groupId - Settings::NGC_GROUPNUM_OFFSET), reinterpret_cast<const uint8_t*>("exit"), 4, &error);
        if (PARSE_ERR(error)) {
            emit saveRequest();
        }
    } else {
        Tox_Err_Conference_Delete error;
        tox_conference_delete(tox.get(), groupId, &error);
        if (PARSE_ERR(error)) {
            emit saveRequest();

            /*
             * TODO(sudden6): this is probably not (thread-)safe, but can be ignored for now since
             * we don't change av at runtime.
             */

            if (av) {
                av->leaveGroupCall(groupId);
            }
        }
    }
}

/**
 * @brief Returns our username, or an empty string on failure
 */
QString Core::getUsername() const
{
    QMutexLocker ml{&coreLoopLock};

    QString sname;
    if (!tox) {
        return sname;
    }

    int size = tox_self_get_name_size(tox.get());
    if (!size) {
        return {};
    }
    std::vector<uint8_t> nameBuf(size);
    tox_self_get_name(tox.get(), nameBuf.data());
    return ToxString(nameBuf.data(), size).getQString();
}

void Core::setUsername(const QString& username)
{
    QMutexLocker ml{&coreLoopLock};

    if (username == getUsername()) {
        return;
    }

    ToxString cUsername(username);
    Tox_Err_Set_Info error;
    tox_self_set_name(tox.get(), cUsername.data(), cUsername.size(), &error);
    if (!PARSE_ERR(error)) {
        emit failedToSetUsername(username);
        return;
    }

    emit usernameSet(username);
    emit saveRequest();
}

/**
 * @brief Returns our Tox ID
 */
ToxId Core::getSelfId() const
{
    QMutexLocker ml{&coreLoopLock};

    uint8_t friendId[TOX_ADDRESS_SIZE] = {0x00};
    tox_self_get_address(tox.get(), friendId);
    return ToxId(friendId, TOX_ADDRESS_SIZE);
}

/**
 * @brief Gets self public key
 * @return Self PK
 */
ToxPk Core::getSelfPublicKey() const
{
    QMutexLocker ml{&coreLoopLock};

    uint8_t selfPk[TOX_PUBLIC_KEY_SIZE] = {0x00};
    tox_self_get_public_key(tox.get(), selfPk);
    return ToxPk(selfPk);
}

QByteArray Core::getSelfDhtId() const
{
    QMutexLocker ml{&coreLoopLock};
    QByteArray dhtKey(TOX_PUBLIC_KEY_SIZE, 0x00);
    tox_self_get_dht_id(tox.get(), reinterpret_cast<uint8_t*>(dhtKey.data()));
    return dhtKey;
}

int Core::getSelfUdpPort() const
{
    QMutexLocker ml{&coreLoopLock};
    Tox_Err_Get_Port error;
    auto port = tox_self_get_udp_port(tox.get(), &error);
    if (!PARSE_ERR(error)) {
        return -1;
    }
    return port;
}

/**
 * @brief Returns our status message, or an empty string on failure
 */
QString Core::getStatusMessage() const
{
    QMutexLocker ml{&coreLoopLock};

    assert(tox != nullptr);

    size_t size = tox_self_get_status_message_size(tox.get());
    if (!size) {
        return {};
    }
    std::vector<uint8_t> nameBuf(size);
    tox_self_get_status_message(tox.get(), nameBuf.data());
    return ToxString(nameBuf.data(), size).getQString();
}

/**
 * @brief Returns our user status
 */
Status::Status Core::getStatus() const
{
    QMutexLocker ml{&coreLoopLock};

    return static_cast<Status::Status>(tox_self_get_status(tox.get()));
}

void Core::setStatusMessage(const QString& message)
{
    QMutexLocker ml{&coreLoopLock};

    if (message == getStatusMessage()) {
        return;
    }

    ToxString cMessage(message);
    Tox_Err_Set_Info error;
    tox_self_set_status_message(tox.get(), cMessage.data(), cMessage.size(), &error);
    if (!PARSE_ERR(error)) {
        emit failedToSetStatusMessage(message);
        return;
    }

    emit saveRequest();
    emit statusMessageSet(message);
}

void Core::setStatus(Status::Status status)
{
    QMutexLocker ml{&coreLoopLock};

    Tox_User_Status userstatus;
    switch (status) {
    case Status::Status::Online:
        userstatus = TOX_USER_STATUS_NONE;
        break;

    case Status::Status::Away:
        userstatus = TOX_USER_STATUS_AWAY;
        break;

    case Status::Status::Busy:
        userstatus = TOX_USER_STATUS_BUSY;
        break;

    default:
        return;
        break;
    }

    tox_self_set_status(tox.get(), userstatus);
    emit saveRequest();
    emit statusSet(status);
}

/**
 * @brief Returns the unencrypted tox save data
 */
QByteArray Core::getToxSaveData()
{
    QMutexLocker ml{&coreLoopLock};

    uint32_t fileSize = tox_get_savedata_size(tox.get());
    QByteArray data;
    data.resize(fileSize);
    tox_get_savedata(tox.get(), reinterpret_cast<uint8_t*>(data.data()));
    return data;
}

void Core::loadFriends()
{
    QMutexLocker ml{&coreLoopLock};

    const size_t friendCount = tox_self_get_friend_list_size(tox.get());
    if (friendCount == 0) {
        return;
    }

    std::vector<uint32_t> ids(friendCount);
    tox_self_get_friend_list(tox.get(), ids.data());
    uint8_t friendPk[TOX_PUBLIC_KEY_SIZE] = {0x00};
    for (size_t i = 0; i < friendCount; ++i) {
        Tox_Err_Friend_Get_Public_Key keyError;
        tox_friend_get_public_key(tox.get(), ids[i], friendPk, &keyError);
        if (!PARSE_ERR(keyError)) {
            continue;
        }
        emit friendAdded(ids[i], ToxPk(friendPk));
        emit friendUsernameChanged(ids[i], getFriendUsername(ids[i]));
        Tox_Err_Friend_Query queryError;
        size_t statusMessageSize = tox_friend_get_status_message_size(tox.get(), ids[i], &queryError);
        if (PARSE_ERR(queryError) && statusMessageSize) {
            std::vector<uint8_t> messageData(statusMessageSize);
            tox_friend_get_status_message(tox.get(), ids[i], messageData.data(), &queryError);
            QString friendStatusMessage = ToxString(messageData.data(), statusMessageSize).getQString();
            emit friendStatusMessageChanged(ids[i], friendStatusMessage);
        }
        checkLastOnline(ids[i]);

        // HINT: load pushtoken for friend from db, and put it in the Friend object
        emit friendLoaded(ids[i]);
        // HINT: update connection status so that the icon get drawn again, and takes pushtoken into account
        Tox_Err_Friend_Query error2;
        Tox_Connection connection_status = tox_friend_get_connection_status(tox.get(), ids[i], &error2);
        Status::Status friendStatus = Status::Status::Offline;
        switch (connection_status)
        {
            case TOX_CONNECTION_NONE:
                friendStatus = Status::Status::Offline;
                break;
            case TOX_CONNECTION_TCP:
                friendStatus = Status::Status::Online;
                break;
            case TOX_CONNECTION_UDP:
                friendStatus = Status::Status::Online;
                break;
            default:
                friendStatus = Status::Status::Offline;
                break;
        }
        // HINT: yes 3 times. we need to force a status change so the UI will update
        emit friendStatusChanged(ids[i], Status::Status::Online);
        emit friendStatusChanged(ids[i], Status::Status::Offline);
        emit friendStatusChanged(ids[i], friendStatus);
    }
}

void Core::loadGroups()
{
    QMutexLocker ml{&coreLoopLock};

    const size_t groupCount = tox_conference_get_chatlist_size(tox.get());
    if (groupCount > 0) {
        std::vector<uint32_t> groupNumbers(groupCount);
        tox_conference_get_chatlist(tox.get(), groupNumbers.data());

        for (size_t i = 0; i < groupCount; ++i) {
            Tox_Err_Conference_Title error;
            QString name;
            const auto groupNumber = groupNumbers[i];
            size_t titleSize = tox_conference_get_title_size(tox.get(), groupNumber, &error);
            const GroupId persistentId = getGroupPersistentId(groupNumber, 0);
            const QString defaultName = tr("Groupchat %1").arg(persistentId.toString().left(8));
            if (PARSE_ERR(error) || !titleSize) {
                std::vector<uint8_t> nameBuf(titleSize);
                tox_conference_get_title(tox.get(), groupNumber, nameBuf.data(), &error);
                if (PARSE_ERR(error)) {
                    name = ToxString(nameBuf.data(), titleSize).getQString();
                } else {
                    name = defaultName;
                }
            } else {
                name = defaultName;
            }
            if (getGroupAvEnabled(groupNumber)) {
                if (toxav_groupchat_enable_av(tox.get(), groupNumber, CoreAV::groupCallCallback, this)) {
                    qCritical() << "Failed to enable audio on loaded group" << groupNumber;
                }
            }
            emit emptyGroupCreated(groupNumber, persistentId, name);
        }
    }

    const uint32_t ngcCount = tox_group_get_number_groups(tox.get());
    if (ngcCount > 0) {
        std::vector<uint32_t> groupNumbers(ngcCount);
        tox_group_get_grouplist(tox.get(), groupNumbers.data());

        for (size_t i = 0; i < ngcCount; ++i) {
            Tox_Err_Group_State_Queries error;
            QString name;
            const auto groupNumber = groupNumbers[i];
            size_t titleSize = tox_group_get_name_size(tox.get(), groupNumber, &error);
            const GroupId persistentId = getGroupPersistentId(groupNumber, 1);
            const QString defaultName = persistentId.toString().left(8);
            if (PARSE_ERR(error) || !titleSize) {
                std::vector<uint8_t> nameBuf(titleSize);
                tox_group_get_name(tox.get(), groupNumber, nameBuf.data(), &error);
                if (PARSE_ERR(error)) {
                    name = ToxString(nameBuf.data(), titleSize).getQString();
                } else {
                    name = defaultName;
                }
            } else {
                name = defaultName;
            }
            emit emptyGroupCreated((Settings::NGC_GROUPNUM_OFFSET + groupNumber), persistentId, name);
        }
    }
}

void Core::checkLastOnline(uint32_t friendId)
{
    QMutexLocker ml{&coreLoopLock};

    Tox_Err_Friend_Get_Last_Online error;
    const uint64_t lastOnline = tox_friend_get_last_online(tox.get(), friendId, &error);
    if (PARSE_ERR(error)) {
        emit friendLastSeenChanged(friendId, QDateTime::fromTime_t(lastOnline));
    }
}

/**
 * @brief Returns the list of friendIds in our friendlist, an empty list on error
 */
QVector<uint32_t> Core::getFriendList() const
{
    QMutexLocker ml{&coreLoopLock};

    QVector<uint32_t> friends;
    friends.resize(tox_self_get_friend_list_size(tox.get()));
    tox_self_get_friend_list(tox.get(), friends.data());
    return friends;
}

GroupId Core::getGroupPersistentId(uint32_t groupNumber, int is_ngc) const
{
    QMutexLocker ml{&coreLoopLock};

    if (is_ngc == 1) {
        std::vector<uint8_t> idBuff(TOX_GROUP_CHAT_ID_SIZE);
        Tox_Err_Group_State_Queries error;
        if (tox_group_get_chat_id(tox.get(), groupNumber,
                                  idBuff.data(), &error)) {
            return GroupId{idBuff.data()};
        } else {
            qCritical() << "Failed to get conference ID of group" << groupNumber;
            return {};
        }
    } else {
        std::vector<uint8_t> idBuff(TOX_CONFERENCE_UID_SIZE);
        if (tox_conference_get_id(tox.get(), groupNumber,
                                  idBuff.data())) {
            return GroupId{idBuff.data()};
        } else {
            qCritical() << "Failed to get conference ID of group" << groupNumber;
            return {};
        }
    }
}

/**
 * @brief Get number of peers in the conference.
 * @return The number of peers in the conference. UINT32_MAX on failure.
 */
uint32_t Core::getGroupNumberPeers(int groupId) const
{
    QMutexLocker ml{&coreLoopLock};

    if (groupId >= static_cast<int>(Settings::NGC_GROUPNUM_OFFSET)) {
        Tox_Err_Group_Peer_Query error;
        uint32_t count = tox_group_peer_count(tox.get(), (groupId - Settings::NGC_GROUPNUM_OFFSET), &error);
        if (!PARSE_ERR(error)) {
            return std::numeric_limits<uint32_t>::max();
        }

        return count;
    } else {
        Tox_Err_Conference_Peer_Query error;
        uint32_t count = tox_conference_peer_count(tox.get(), groupId, &error);
        if (!PARSE_ERR(error)) {
            return std::numeric_limits<uint32_t>::max();
        }

        return count;
    }
}

/**
 * @brief Get the name of a peer of a group
 */
QString Core::getGroupPeerName(int groupId, int peerId) const
{
    QMutexLocker ml{&coreLoopLock};

    Tox_Err_Conference_Peer_Query error;
    size_t length = tox_conference_peer_get_name_size(tox.get(), groupId, peerId, &error);
    if (!PARSE_ERR(error) || !length) {
        qDebug() << "getGroupPeerName:error:1";
        return QString{};
    }

    std::vector<uint8_t> nameBuf(length);
    tox_conference_peer_get_name(tox.get(), groupId, peerId, nameBuf.data(), &error);
    if (!PARSE_ERR(error)) {
        qDebug() << "getGroupPeerName:error:2";
        return QString{};
    }

    return ToxString(nameBuf.data(), length).getQString();
}

/**
 * @brief Get the public key of a peer of a group
 */
ToxPk Core::getGroupPeerPk(int groupId, int peerId) const
{
    QMutexLocker ml{&coreLoopLock};

    uint8_t friendPk[TOX_PUBLIC_KEY_SIZE] = {0x00};

    if (groupId >= static_cast<int>(Settings::NGC_GROUPNUM_OFFSET)) {
        Tox_Err_Group_Peer_Query error;
        tox_group_peer_get_public_key(tox.get(), (groupId - Settings::NGC_GROUPNUM_OFFSET), peerId, friendPk, &error);
        if (!PARSE_ERR(error)) {
            qDebug() << "getGroupPeerPk:error:1";
            return ToxPk{};
        }

    } else {
        Tox_Err_Conference_Peer_Query error;
        tox_conference_peer_get_public_key(tox.get(), groupId, peerId, friendPk, &error);
        if (!PARSE_ERR(error)) {
            qDebug() << "getGroupPeerPk:error:2";
            return ToxPk{};
        }
    }

    return ToxPk(friendPk);
}

/**
 * @brief Get the names of the peers of a group
 */
QStringList Core::getGroupPeerNames(int groupId) const
{
    QMutexLocker ml{&coreLoopLock};

    assert(tox != nullptr);

    if (groupId >= static_cast<int>(Settings::NGC_GROUPNUM_OFFSET)) {
        uint32_t nPeers = getGroupNumberPeers(groupId);
        if (nPeers == std::numeric_limits<uint32_t>::max()) {
            qWarning() << "getGroupPeerNames NGC: Unable to get number of peers";
            return {};
        }

        Tox_Err_Group_Peer_Query error;
        uint32_t *peerlist = static_cast<uint32_t *>(calloc(nPeers, sizeof(uint32_t)));

        if (!peerlist) {
            qWarning() << "getGroupPeerNames NGC: calloc failed";
            return {};
        }

        tox_group_get_peerlist(tox.get(), (groupId - Settings::NGC_GROUPNUM_OFFSET), peerlist, &error);
        if (!PARSE_ERR(error)) {
            qWarning() << "getGroupPeerNames NGC: Unable to get peerlist";
            return {};
        }

        QStringList names;
        for (int i = 0; i < static_cast<int>(nPeers); ++i) {
            size_t length = tox_group_peer_get_name_size(tox.get(), (groupId - Settings::NGC_GROUPNUM_OFFSET), *(peerlist + i), &error);

            if (!PARSE_ERR(error) || !length) {
                names.append(QString());
                continue;
            }

            std::vector<uint8_t> nameBuf(length);
            tox_group_peer_get_name(tox.get(), (groupId - Settings::NGC_GROUPNUM_OFFSET), *(peerlist + i), nameBuf.data(), &error);
            if (PARSE_ERR(error)) {
                names.append(QString::number(*(peerlist + i)) + QString(":") + ToxString(nameBuf.data(), length).getQString());
            } else {
                qWarning() << "getGroupPeerNames NGC: tox_group_peer_get_name error";
                names.append(QString());
            }
        }

        free(peerlist);
        assert(names.size() == static_cast<int>(nPeers));

        return names;
    } else {
        uint32_t nPeers = getGroupNumberPeers(groupId);
        if (nPeers == std::numeric_limits<uint32_t>::max()) {
            qWarning() << "getGroupPeerNames: Unable to get number of peers";
            return {};
        }

        QStringList names;
        for (int i = 0; i < static_cast<int>(nPeers); ++i) {
            Tox_Err_Conference_Peer_Query error;
            size_t length = tox_conference_peer_get_name_size(tox.get(), groupId, i, &error);

            if (!PARSE_ERR(error) || !length) {
                names.append(QString());
                continue;
            }

            std::vector<uint8_t> nameBuf(length);
            tox_conference_peer_get_name(tox.get(), groupId, i, nameBuf.data(), &error);
            if (PARSE_ERR(error)) {
                names.append(ToxString(nameBuf.data(), length).getQString());
            } else {
                names.append(QString());
            }
        }

        assert(names.size() == static_cast<int>(nPeers));

        return names;
    }
}

/**
 * @brief Check, that group has audio or video stream
 * @param groupId Id of group to check
 * @return True for AV groups, false for text-only groups
 */
bool Core::getGroupAvEnabled(int groupId) const
{
    if (groupId >= static_cast<int>(Settings::NGC_GROUPNUM_OFFSET)) {
        return TOX_CONFERENCE_TYPE_TEXT;
    } else {
        QMutexLocker ml{&coreLoopLock};
        Tox_Err_Conference_Get_Type error;
        Tox_Conference_Type type = tox_conference_get_type(tox.get(), groupId, &error);
        PARSE_ERR(error);
        // would be nice to indicate to caller that we don't actually know..
        return type == TOX_CONFERENCE_TYPE_AV;
    }
}

/**
 * @brief Accept a groupchat invite.
 * @param inviteInfo Object which contains info about group invitation
 *
 * @return Conference number on success, UINT32_MAX on failure.
 */
uint32_t Core::joinGroupchat(const GroupInvite& inviteInfo)
{
    QMutexLocker ml{&coreLoopLock};

    const uint32_t friendId = inviteInfo.getFriendId();
    const uint8_t confType = inviteInfo.getType();
    const QByteArray invite = inviteInfo.getInvite();
    const uint8_t* const cookie = reinterpret_cast<const uint8_t*>(invite.data());
    const size_t cookieLength = invite.length();
    uint32_t groupNum{std::numeric_limits<uint32_t>::max()};
    switch (confType) {
    case TOX_CONFERENCE_TYPE_TEXT: {
        qDebug() << QString("Trying to accept invite for text group chat sent by friend %1").arg(friendId);
        Tox_Err_Conference_Join error;
        groupNum = tox_conference_join(tox.get(), friendId, cookie, cookieLength, &error);
        if (!PARSE_ERR(error)) {
            groupNum = std::numeric_limits<uint32_t>::max();
        }
        break;
    }
    case TOX_CONFERENCE_TYPE_AV: {
        qDebug() << QString("Trying to join AV groupchat invite sent by friend %1").arg(friendId);
        groupNum = toxav_join_av_groupchat(tox.get(), friendId, cookie, cookieLength,
                                           CoreAV::groupCallCallback, this);
        break;
    }
    default:
        qWarning() << "joinGroupchat: Unknown groupchat type " << confType;
    }
    if (groupNum != std::numeric_limits<uint32_t>::max()) {
        emit saveRequest();
        emit groupJoined(groupNum, getGroupPersistentId(groupNum, 0));
    }
    return groupNum;
}

void Core::groupInviteFriend(uint32_t friendId, int groupId)
{
    QMutexLocker ml{&coreLoopLock};

    if (groupId >= static_cast<int>(Settings::NGC_GROUPNUM_OFFSET)) {
        Tox_Err_Group_Invite_Friend error;
        bool result = tox_group_invite_friend(tox.get(),
            (groupId - Settings::NGC_GROUPNUM_OFFSET),
            friendId, &error);
        if (result) {
            qDebug() << "groupInviteFriend: inviting to NGC group OK, groupnum" << groupId << "error:" << error;
        } else {
            qWarning() << "groupInviteFriend: inviting to NGC group failed, groupnum" << groupId;
        }
    } else {
        Tox_Err_Conference_Invite error;
        tox_conference_invite(tox.get(), friendId, groupId, &error);
        qDebug() << "groupInviteFriend: inviting to group ... , groupnum" << groupId << "error:" << error;
        PARSE_ERR(error);
    }
}

void Core::changeOwnNgcName(uint32_t groupnumber, const QString& name)
{
    qDebug() << "changeOwnNgcName" << name << "gid" << groupnumber;
    if (groupnumber >= static_cast<int>(Settings::NGC_GROUPNUM_OFFSET)) {
        ToxString cName(name);
        bool res = tox_group_self_set_name(tox.get(), (groupnumber - Settings::NGC_GROUPNUM_OFFSET), cName.data(), cName.size(), NULL);
        if (res == false) {
            qWarning() << "changeOwnNgcName: setting new self name failed";
        } else {
            emit groupPeerlistChanged(groupnumber);
            emit saveRequest();
        }
    }
}

int Core::createGroup(uint8_t type)
{
    QMutexLocker ml{&coreLoopLock};

    if (type == TOX_CONFERENCE_TYPE_TEXT) {
        Tox_Err_Conference_New error;
        uint32_t groupId = tox_conference_new(tox.get(), &error);
        if (PARSE_ERR(error)) {
            emit saveRequest();
            emit emptyGroupCreated(groupId, getGroupPersistentId(groupId, 0));
            return groupId;
        } else {
            return std::numeric_limits<uint32_t>::max();
        }
    } else if (type == TOX_CONFERENCE_TYPE_AV) {
        // unlike tox_conference_new, toxav_add_av_groupchat does not have an error enum, so -1 group number is our
        // only indication of an error
        int groupId = toxav_add_av_groupchat(tox.get(), CoreAV::groupCallCallback, this);
        if (groupId != -1) {
            emit saveRequest();
            emit emptyGroupCreated(groupId, getGroupPersistentId(groupId, 0));
        } else {
            qCritical() << "Unknown error creating AV groupchat";
        }
        return groupId;
    } else {
        qWarning() << "createGroup: Unknown type " << type;
        return -1;
    }
}

/**
 * @brief Checks if a friend is online. Unknown friends are considered offline.
 */
bool Core::isFriendOnline(uint32_t friendId) const
{
    QMutexLocker ml{&coreLoopLock};

    Tox_Err_Friend_Query error;
    Tox_Connection connection = tox_friend_get_connection_status(tox.get(), friendId, &error);
    PARSE_ERR(error);
    return connection != TOX_CONNECTION_NONE;
}

/**
 * @brief Checks if we have a friend by public key
 */
bool Core::hasFriendWithPublicKey(const ToxPk& publicKey) const
{
    QMutexLocker ml{&coreLoopLock};

    if (publicKey.isEmpty()) {
        return false;
    }

    Tox_Err_Friend_By_Public_Key error;
    (void)tox_friend_by_public_key(tox.get(), publicKey.getData(), &error);
    return PARSE_ERR(error);
}

/**
 * @brief Get the public key part of the ToxID only
 */
ToxPk Core::getFriendPublicKey(uint32_t friendNumber) const
{
    QMutexLocker ml{&coreLoopLock};

    uint8_t rawid[TOX_PUBLIC_KEY_SIZE];
    Tox_Err_Friend_Get_Public_Key error;
    tox_friend_get_public_key(tox.get(), friendNumber, rawid, &error);
    if (!PARSE_ERR(error)) {
        qWarning() << "getFriendPublicKey: Getting public key failed";
        return ToxPk();
    }

    return ToxPk(rawid);
}

/**
 * @brief Get the username of a friend
 */
QString Core::getFriendUsername(uint32_t friendnumber) const
{
    QMutexLocker ml{&coreLoopLock};

    Tox_Err_Friend_Query error;
    size_t nameSize = tox_friend_get_name_size(tox.get(), friendnumber, &error);
    if (!PARSE_ERR(error) || !nameSize) {
        return QString();
    }

    std::vector<uint8_t> nameBuf(nameSize);
    tox_friend_get_name(tox.get(), friendnumber, nameBuf.data(), &error);
    if (!PARSE_ERR(error)) {
        return QString();
    }
    return ToxString(nameBuf.data(), nameSize).getQString();
}

uint64_t Core::getMaxMessageSize() const
{
    /*
     * TODO: Remove this hack; the reported max message length we receive from c-toxcore
     * as of 08-02-2019 is inaccurate, causing us to generate too large messages when splitting
     * them up.
     *
     * The inconsistency lies in c-toxcore group.c:2480 using MAX_GROUP_MESSAGE_DATA_LEN to verify
     * message size is within limit, but tox_max_message_length giving a different size limit to us.
     *
     * (uint32_t tox_max_message_length(void); declared in tox.h, unable to see explicit definition)
     */
    return tox_max_message_length() - 50;
}

QString Core::getPeerName(const ToxPk& id) const
{
    QMutexLocker ml{&coreLoopLock};

    Tox_Err_Friend_By_Public_Key keyError;
    uint32_t friendId = tox_friend_by_public_key(tox.get(), id.getData(), &keyError);
    if (!PARSE_ERR(keyError)) {
        qWarning() << "getPeerName: No such peer";
        return {};
    }

    Tox_Err_Friend_Query queryError;
    const size_t nameSize = tox_friend_get_name_size(tox.get(), friendId, &queryError);
    if (!PARSE_ERR(queryError) || !nameSize) {
        return {};
    }

    std::vector<uint8_t> nameBuf(nameSize);
    tox_friend_get_name(tox.get(), friendId, nameBuf.data(), &queryError);
    if (!PARSE_ERR(queryError)) {
        qWarning() << "getPeerName: Can't get name of friend " + QString().setNum(friendId);
        return {};
    }

    return ToxString(nameBuf.data(), nameSize).getQString();
}

/**
 * @brief Sets the NoSpam value to prevent friend request spam
 * @param nospam an arbitrary which becomes part of the Tox ID
 */
void Core::setNospam(uint32_t nospam)
{
    QMutexLocker ml{&coreLoopLock};

    tox_self_set_nospam(tox.get(), nospam);
    emit idSet(getSelfId());
}
